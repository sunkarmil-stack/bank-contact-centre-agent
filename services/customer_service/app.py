"""Customer microservice — system of record for client profile, transactions and
card status (stands in for core banking / customer master behind API Management).

    uvicorn services.customer_service.app:create_app --factory --port 8101

Zero-trust checks on every request, independent of what upstream services did:
  1. Workload identity: a service token for audience ``customer-service`` with the
     right application permission (``customer.read`` / ``customer.cards.lock``).
  2. End-user context: the ``X-Delegation-Token`` (who, which customer, which
     authentication level, which purpose). The customer in the URL must be the one
     bound to that token.
  3. Purpose limitation, step-up and data minimisation (``OPERATION_POLICY``).
  4. State changes: an ``X-Approval-Token`` bound to the run and the exact action,
     approved by someone other than the requester; an ``Idempotency-Key``.
  5. Every allow/deny decision is written to the shared, hash-chained audit store.

SYNTHETIC data only.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Header, Query, Request

from ccagent.config import Settings
from ccagent.container import DATA, open_audit, open_database
from ccagent.integrations.customer import AccessContext, AccessDenied, MockCustomerService, NotFound, StepUpRequired
from ccagent.secrets import build_secret_provider
from ccagent.security.service_tokens import ServiceTokenVerifier
from ccagent.security.tokens import InternalTokens

from ..common import ServiceError, error, instrument

SERVICE = "customer-service"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    secrets = build_secret_provider(settings)
    db = open_database(settings, secrets, str(Path(settings.data_dir) / "customer.db"))
    audit = open_audit(settings, secrets, SERVICE, db)
    store = MockCustomerService(DATA / "synthetic_customers.json", db, audit)
    verifier = ServiceTokenVerifier(settings.service_auth, secrets, SERVICE, settings.entra_tenant_id)
    user_tokens = InternalTokens(secrets)

    app = FastAPI(title="Customer service (synthetic system of record)", version="1.1.0",
                  docs_url=None if settings.is_prod else "/docs", redoc_url=None)
    instrument(app, SERVICE, audit)

    @app.exception_handler(StepUpRequired)
    async def _step_up(_: Request, exc: StepUpRequired):
        return error(403, "step_up_required", str(exc))

    @app.exception_handler(AccessDenied)
    async def _denied(_: Request, exc: AccessDenied):
        return error(403, "forbidden", str(exc))

    @app.exception_handler(NotFound)
    async def _nf(_: Request, exc: NotFound):
        return error(404, "not_found", str(exc))

    def context(request: Request, tool: str, permission: str) -> tuple[AccessContext, dict]:
        verifier.verify(request.headers.get("authorization"), permission)          # 1. which workload
        delegation = request.headers.get("x-delegation-token")
        if not delegation:
            raise ServiceError(401, "missing_user_context", "X-Delegation-Token is required")
        claims = user_tokens.verify_delegation(delegation, tool)                       # 2. on whose behalf
        ctx = AccessContext(
            on_behalf_of=claims["sub"], roles=frozenset(claims.get("roles", [])),
            session_customer_ref=claims.get("customer_ref"), cust_auth_level=int(claims.get("cal", 0)),
            purpose=claims["pou"], correlation_id=request.headers.get("x-correlation-id") or claims.get("cid", "-"),
            run_id=request.headers.get("x-run-id") or None,
        )
        return ctx, claims

    @app.get("/customers/{customer_ref}/profile")
    async def profile(customer_ref: str, request: Request):
        ctx, _ = context(request, "get_customer_profile", "customer.read")
        return await store.get_profile(customer_ref, ctx)                               # 3. purpose + minimisation

    @app.get("/customers/{customer_ref}/transactions")
    async def transactions(customer_ref: str, request: Request, limit: int = Query(10, ge=1, le=25)):
        ctx, _ = context(request, "list_recent_transactions", "customer.read")
        return {"transactions": await store.list_transactions(customer_ref, ctx, limit)}

    @app.post("/customers/{customer_ref}/cards/{card_id}/lock")
    async def lock(customer_ref: str, card_id: str, request: Request,
                   idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
        ctx, claims = context(request, "lock_card", "customer.cards.lock")
        if not idempotency_key or len(idempotency_key) < 8:
            raise ServiceError(422, "idempotency_key_required", "Idempotency-Key header is required")
        approval = request.headers.get("x-approval-token")                              # 4. human approval
        if not approval:
            raise ServiceError(403, "approval_required", "card lock requires a reviewer approval token")
        action = {"type": "lock_card", "customer_ref": customer_ref, "card_id": card_id}
        approved = user_tokens.verify_approval(approval, run_id=ctx.run_id or "", action=action)
        if approved["sub"] == claims["sub"]:
            raise ServiceError(403, "four_eyes_violation", "requester cannot approve own action")
        result = await store.lock_card(customer_ref, card_id, ctx, idempotency_key)
        return {**result, "approved_by": approved["sub"]}

    if settings.env in ("local", "test"):
        @app.post("/dev/reset", include_in_schema=False)
        async def reset():
            """Demo only: restore synthetic card states so a scenario can be replayed."""
            db.execute("DELETE FROM mock_card_status")
            db.execute("DELETE FROM idempotency")
            audit.append("dev_reset", "demo-recorder", None, scope="card_status")
            return {"status": "reset"}

    return app
