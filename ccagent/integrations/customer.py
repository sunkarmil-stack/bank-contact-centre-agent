"""Customer data service (core banking / customer master facade).

Every call enforces, in this order:
  1. Authentication context present (delegated identity from a verified token)
  2. Session binding — the customer must be the one bound to the interaction
     (prevents cross-customer access via prompt injection)
  3. Role-based authorization for the operation
  4. Customer authentication level (step-up) for the operation
  5. Purpose limitation (PIPEDA principle 4.5) — declared purpose must be
     allowed for the operation
  6. Data minimisation — only the fields needed for that purpose are returned
  7. Audit logging of every access decision (allow AND deny)

``MockCustomerService`` serves SYNTHETIC data only. ``HttpCustomerService`` is
the production adapter for the bank's customer API (behind Azure API
Management, mTLS + OAuth2 client credentials / managed identity).
"""

from __future__ import annotations

import json
import secrets
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..persistence.audit import AuditLog
from ..persistence.db import Database
from ..resilience import PermanentError, TransientError
from ..security.auth import Role


class AccessDenied(PermanentError):
    pass


class StepUpRequired(PermanentError):
    pass


class NotFound(PermanentError):
    pass


@dataclass(frozen=True)
class AccessContext:
    on_behalf_of: str
    roles: frozenset[str]
    session_customer_ref: str | None
    cust_auth_level: int
    purpose: str
    correlation_id: str
    run_id: str | None = None
    # Raw end-user credentials, forwarded so downstream systems of record can verify them
    # independently (zero trust). Never logged.
    delegation_token: str | None = field(default=None, repr=False, compare=False)
    approval_token: str | None = field(default=None, repr=False, compare=False)


OPERATION_POLICY: dict[str, dict] = {
    "get_profile": {
        "roles": {Role.AGENT, Role.CHANNEL, Role.REVIEWER},
        "min_auth": 1,
        "purposes": {"servicing", "card_servicing", "dispute", "complaint", "fraud_referral"},
    },
    "list_transactions": {
        "roles": {Role.AGENT, Role.CHANNEL, Role.REVIEWER},
        "min_auth": 1,
        "purposes": {"servicing", "dispute", "fraud_referral"},
    },
    "lock_card": {
        "roles": {Role.AGENT, Role.CHANNEL, Role.REVIEWER},
        "min_auth": 1,
        "purposes": {"card_servicing"},
    },
}

# Data minimisation: fields released per purpose.
PROFILE_FIELDS_BY_PURPOSE: dict[str, set[str]] = {
    "servicing": {"customer_ref", "display_name", "preferred_language", "accounts", "cards"},
    "card_servicing": {"customer_ref", "display_name", "cards"},
    "dispute": {"customer_ref", "display_name", "cards"},
    "complaint": {"customer_ref", "display_name", "preferred_language"},
    "fraud_referral": {"customer_ref", "display_name", "cards", "vulnerability_flags"},
}


class CustomerService(Protocol):
    async def get_profile(self, customer_ref: str, ctx: AccessContext) -> dict: ...
    async def list_transactions(self, customer_ref: str, ctx: AccessContext, limit: int = 10) -> list[dict]: ...
    async def lock_card(self, customer_ref: str, card_id: str, ctx: AccessContext, idempotency_key: str) -> dict: ...


def _authorize(op: str, customer_ref: str, ctx: AccessContext, audit: AuditLog) -> None:
    policy = OPERATION_POLICY[op]
    reason = None
    if not ctx.on_behalf_of:
        reason = "no_delegated_identity"
    elif ctx.session_customer_ref is None or customer_ref != ctx.session_customer_ref:
        reason = "customer_not_bound_to_session"
    elif not ctx.roles.intersection(policy["roles"]):
        reason = "role_not_permitted"
    elif ctx.purpose not in policy["purposes"]:
        reason = f"purpose_not_permitted:{ctx.purpose}"
    elif ctx.cust_auth_level < policy["min_auth"]:
        audit.append("data_access_denied", ctx.on_behalf_of, ctx.run_id, op=op, reason="step_up_required",
                     customer_ref=customer_ref, purpose=ctx.purpose, correlation_id=ctx.correlation_id)
        raise StepUpRequired(f"{op} requires customer authentication level {policy['min_auth']}")
    if reason:
        audit.append("data_access_denied", ctx.on_behalf_of, ctx.run_id, op=op, reason=reason,
                     customer_ref=customer_ref, purpose=ctx.purpose, correlation_id=ctx.correlation_id)
        raise AccessDenied(reason)
    audit.append("data_access_granted", ctx.on_behalf_of, ctx.run_id, op=op, customer_ref=customer_ref,
                 purpose=ctx.purpose, correlation_id=ctx.correlation_id)


class MockCustomerService:
    """SYNTHETIC data only. Card status changes and idempotency results persist
    in the service database so retries and restarts are safe.

    Used in-process (single-process demo) and as the data layer inside the
    Customer microservice (``services/customer_service``)."""

    name = "customer data (in-process)"

    def __init__(self, data_file: Path, db: Database, audit: AuditLog) -> None:
        raw = json.loads(Path(data_file).read_text())
        self._customers = {c["customer_ref"]: c for c in raw["customers"]}
        self._db = db
        self._audit = audit
        db.execute(
            "CREATE TABLE IF NOT EXISTS mock_card_status (card_id TEXT PRIMARY KEY, status TEXT NOT NULL, updated_at TEXT)"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS idempotency (key TEXT PRIMARY KEY, operation TEXT NOT NULL, result TEXT NOT NULL)"
        )

    def _customer(self, ref: str) -> dict:
        c = self._customers.get(ref)
        if not c:
            raise NotFound("customer not found")
        return c

    def _card_status(self, card: dict) -> str:
        row = self._db.query_one("SELECT status FROM mock_card_status WHERE card_id=?", (card["card_id"],))
        return row["status"] if row else card["status"]

    async def get_profile(self, customer_ref: str, ctx: AccessContext) -> dict:
        _authorize("get_profile", customer_ref, ctx, self._audit)
        c = self._customer(customer_ref)
        allowed = PROFILE_FIELDS_BY_PURPOSE.get(ctx.purpose, {"customer_ref"})
        out = {k: v for k, v in c.items() if k in allowed and k != "transactions"}
        if "cards" in out:
            out["cards"] = [{**card, "status": self._card_status(card)} for card in c["cards"]]
        return out

    async def list_transactions(self, customer_ref: str, ctx: AccessContext, limit: int = 10) -> list[dict]:
        _authorize("list_transactions", customer_ref, ctx, self._audit)
        txns = sorted(self._customer(customer_ref)["transactions"], key=lambda t: t["date"], reverse=True)
        return txns[: max(1, min(limit, 25))]

    async def lock_card(self, customer_ref: str, card_id: str, ctx: AccessContext, idempotency_key: str) -> dict:
        _authorize("lock_card", customer_ref, ctx, self._audit)
        prior = self._db.query_one("SELECT result FROM idempotency WHERE key=?", (idempotency_key,))
        if prior:
            return {**json.loads(prior["result"]), "idempotent_replay": True}
        c = self._customer(customer_ref)
        if not any(card["card_id"] == card_id for card in c["cards"]):
            raise NotFound("card not found for this customer")
        result = {"card_id": card_id, "status": "locked",
                  "confirmation": "LCK-" + "".join(secrets.choice(string.ascii_uppercase) for _ in range(8))}
        with self._db.transaction():
            self._db.execute(
                "INSERT INTO mock_card_status (card_id, status, updated_at) VALUES (?, 'locked', datetime('now'))"
                " ON CONFLICT(card_id) DO UPDATE SET status='locked', updated_at=datetime('now')",
                (card_id,),
            )
            self._db.execute(
                "INSERT INTO idempotency (key, operation, result) VALUES (?,?,?)",
                (idempotency_key, "lock_card", json.dumps(result)),
            )
        self._audit.append("card_locked", ctx.on_behalf_of, ctx.run_id, customer_ref=customer_ref, card_id=card_id,
                           confirmation=result["confirmation"], correlation_id=ctx.correlation_id)
        return {**result, "idempotent_replay": False}


class HttpCustomerService:
    """Calls the Customer microservice (``services/customer_service``) — or, in a bank
    deployment, the customer / core-banking API behind API Management.

    The system of record is authoritative for identity, customer binding, purpose
    limitation, step-up and four-eyes checks; this adapter forwards the credentials
    it needs (service token + delegation token + approval token) and maps its errors
    to the agent's resilience model (transient → retry, permanent → no retry).
    """

    name = "customer-service"

    def __init__(self, base_url: str, service_tokens, timeout_s: float = 5.0, audience: str = "customer-service") -> None:
        import httpx

        self._tokens = service_tokens
        self._audience = audience
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout_s)

    async def _headers(self, ctx: AccessContext, idempotency_key: str | None = None) -> dict:
        h = {
            "Authorization": f"Bearer {await self._tokens.token_for(self._audience)}",
            "X-Delegation-Token": ctx.delegation_token or "",
            "X-Correlation-Id": ctx.correlation_id,
            "X-Run-Id": ctx.run_id or "",
        }
        if ctx.approval_token:
            h["X-Approval-Token"] = ctx.approval_token
        if idempotency_key:
            h["Idempotency-Key"] = idempotency_key
        return h

    async def _request(self, method: str, path: str, ctx: AccessContext, **kw):
        import httpx

        headers = await self._headers(ctx, kw.pop("idempotency_key", None))
        try:
            r = await self._client.request(method, path, headers=headers, **kw)
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise TransientError(f"customer-service unreachable: {exc.__class__.__name__}") from exc
        if r.status_code in (429, 502, 503, 504):
            raise TransientError(f"customer-service {r.status_code}")
        if r.status_code >= 400:
            try:
                body = r.json()
            except ValueError:
                body = {}
            code, msg = body.get("error", ""), body.get("message", f"customer-service {r.status_code}")
            if code == "step_up_required":
                raise StepUpRequired(msg)
            if r.status_code == 404:
                raise NotFound(msg)
            if r.status_code in (401, 403, 409, 422):
                raise AccessDenied(f"{code or r.status_code}: {msg}")
            raise TransientError(f"customer-service {r.status_code}")
        return r.json()

    async def get_profile(self, customer_ref: str, ctx: AccessContext) -> dict:
        return await self._request("GET", f"/customers/{customer_ref}/profile", ctx)

    async def list_transactions(self, customer_ref: str, ctx: AccessContext, limit: int = 10) -> list[dict]:
        body = await self._request("GET", f"/customers/{customer_ref}/transactions", ctx, params={"limit": limit})
        return body["transactions"]

    async def lock_card(self, customer_ref: str, card_id: str, ctx: AccessContext, idempotency_key: str) -> dict:
        return await self._request(
            "POST", f"/customers/{customer_ref}/cards/{card_id}/lock", ctx, idempotency_key=idempotency_key, json={}
        )
