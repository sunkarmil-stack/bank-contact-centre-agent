"""Case management (CRM) integration — complaints, disputes, fraud referrals,
call wrap-up records.

``LocalCaseService`` persists cases in the service DB (sample). The production
adapter targets the bank's CRM (e.g. Dynamics 365 / Salesforce Service Cloud)
REST API behind API Management, using idempotency keys so retried calls never
create duplicate cases.
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
import string
from typing import Protocol

from ..persistence.audit import AuditLog
from ..persistence.db import Database

CASE_TYPES = {"complaint", "dispute", "fraud_referral", "card_replacement", "general_follow_up"}
PRIORITIES = {"P1", "P2", "P3"}


def _ref_code(n: int = 6) -> str:
    """Letters-only reference suffix so references are never mistaken for PII (card/phone/SIN)."""
    return "".join(secrets.choice(string.ascii_uppercase) for _ in range(n))


class CaseService(Protocol):
    async def create_case(self, *, case_type: str, priority: str, summary: str, customer_ref: str | None,
                          idempotency_key: str, actor: str, run_id: str | None, sla_hours: int,
                          details: dict | None = None, delegation_token: str | None = None,
                          approval_token: str | None = None, correlation_id: str = "-") -> dict: ...

    async def list_cases(self, case_type: str | None = None) -> list[dict]: ...


class LocalCaseService:
    """Case store. Used in-process (single-process demo) and as the data layer inside
    the Case microservice (``services/case_service``). Token arguments are verified by
    the microservice before it calls this class, so they are ignored here."""

    name = "case data (in-process)"

    def __init__(self, db: Database, audit: AuditLog) -> None:
        self._db = db
        self._audit = audit
        db.execute(
            """CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE NOT NULL, case_type TEXT NOT NULL,
                priority TEXT NOT NULL, status TEXT NOT NULL, summary TEXT NOT NULL, customer_ref TEXT,
                details TEXT, created_at TEXT NOT NULL, sla_due_at TEXT NOT NULL, created_by TEXT NOT NULL,
                run_id TEXT)"""
        )

    async def create_case(self, *, case_type: str, priority: str, summary: str, customer_ref: str | None,
                          idempotency_key: str, actor: str, run_id: str | None, sla_hours: int,
                          details: dict | None = None, delegation_token: str | None = None,
                          approval_token: str | None = None, correlation_id: str = "-") -> dict:
        if case_type not in CASE_TYPES or priority not in PRIORITIES:
            raise ValueError("invalid case_type or priority")
        existing = self._db.query_one("SELECT * FROM cases WHERE idempotency_key=?", (idempotency_key,))
        if existing:
            return {**existing, "idempotent_replay": True}
        now = dt.datetime.now(dt.UTC)
        case = {
            "case_id": f"CASE-{now:%y%m%d}-{_ref_code()}",
            "idempotency_key": idempotency_key,
            "case_type": case_type,
            "priority": priority,
            "status": "open",
            "summary": summary[:1000],
            "customer_ref": customer_ref,
            "details": json.dumps(details or {}),
            "created_at": now.isoformat(),
            "sla_due_at": (now + dt.timedelta(hours=sla_hours)).isoformat(),
            "created_by": actor,
            "run_id": run_id,
        }
        # Column names come from the literal dict above; values are bound parameters.
        cols, marks = ", ".join(case), ", ".join("?" for _ in case)
        self._db.execute(f"INSERT INTO cases ({cols}) VALUES ({marks})", tuple(case.values()))  # noqa: S608  # nosec B608
        self._audit.append("case_created", actor, run_id, case_id=case["case_id"], case_type=case_type,
                           priority=priority, sla_due_at=case["sla_due_at"])
        return {**case, "idempotent_replay": False}

    async def list_cases(self, case_type: str | None = None) -> list[dict]:
        if case_type:
            return self._db.query("SELECT * FROM cases WHERE case_type=? ORDER BY created_at DESC", (case_type,))
        return self._db.query("SELECT * FROM cases ORDER BY created_at DESC")

    async def get_case(self, case_id: str) -> dict | None:
        return self._db.query_one("SELECT * FROM cases WHERE case_id=?", (case_id,))


class CaseServiceError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class HttpCaseService:
    """Calls the Case management microservice (``services/case_service``) — in a bank
    deployment, the CRM (e.g. Dynamics 365 / Salesforce Service Cloud) behind API
    Management. Idempotency keys make retries safe: a retried POST never creates a
    second case."""

    name = "case-service"

    def __init__(self, base_url: str, service_tokens, timeout_s: float = 5.0, audience: str = "case-service") -> None:
        import httpx

        self._tokens = service_tokens
        self._audience = audience
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout_s)

    async def _call(self, method: str, path: str, headers: dict | None = None, **kw):
        import httpx

        from ..resilience import TransientError

        h = {"Authorization": f"Bearer {await self._tokens.token_for(self._audience)}", **(headers or {})}
        try:
            r = await self._client.request(method, path, headers=h, **kw)
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise TransientError(f"case-service unreachable: {exc.__class__.__name__}") from exc
        if r.status_code in (429, 502, 503, 504):
            raise TransientError(f"case-service {r.status_code}")
        if r.status_code >= 400:
            try:
                body = r.json()
            except ValueError:
                body = {}
            if r.status_code == 422:
                raise ValueError(body.get("message", "invalid case"))
            raise CaseServiceError(r.status_code, body.get("error", "error"), body.get("message", str(r.status_code)))
        return r.json()

    async def create_case(self, *, case_type: str, priority: str, summary: str, customer_ref: str | None,
                          idempotency_key: str, actor: str, run_id: str | None, sla_hours: int,
                          details: dict | None = None, delegation_token: str | None = None,
                          approval_token: str | None = None, correlation_id: str = "-") -> dict:
        headers = {"Idempotency-Key": idempotency_key, "X-Delegation-Token": delegation_token or "",
                   "X-Run-Id": run_id or "", "X-Correlation-Id": correlation_id}
        if approval_token:
            headers["X-Approval-Token"] = approval_token
        return await self._call("POST", "/cases", headers=headers, json={
            "case_type": case_type, "priority": priority, "summary": summary, "sla_hours": sla_hours,
            "details": details or {}})

    async def list_cases(self, case_type: str | None = None) -> list[dict]:
        body = await self._call("GET", "/cases", params={"case_type": case_type} if case_type else None)
        return body["items"]
