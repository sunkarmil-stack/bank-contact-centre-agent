"""Case management microservice — complaints, disputes, fraud referrals (stands in
for the bank's CRM behind API Management).

    uvicorn services.case_service.app:create_app --factory --port 8102

* ``POST /cases``  — workload permission ``cases.write`` + the end user's delegation
  token. The client is taken from the token, never from the request body. The
  declared purpose must match the case type. Disputes at or above the review
  threshold need an approval token bound to the run and the exact dispute, from
  someone other than the requester. ``Idempotency-Key`` is mandatory: a retried
  request returns the original case instead of creating a duplicate.
* ``GET /cases``, ``GET /cases/{id}`` — workload permission ``cases.read``
  (supervisor reporting through the agent API).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Header, Request
from pydantic import BaseModel, Field

from ccagent.config import Settings
from ccagent.container import open_audit, open_database
from ccagent.integrations.cases import CASE_TYPES, PRIORITIES, LocalCaseService
from ccagent.secrets import build_secret_provider
from ccagent.security.service_tokens import ServiceTokenVerifier
from ccagent.security.tokens import InternalTokens

from ..common import ServiceError, instrument

SERVICE = "case-service"

# Purpose of use that may create each case type.
PURPOSE_FOR_CASE = {"complaint": "complaint", "dispute": "dispute", "fraud_referral": "fraud_referral",
                    "card_replacement": "card_servicing", "general_follow_up": "servicing"}


class CaseIn(BaseModel):
    case_type: str
    priority: str
    summary: str = Field(min_length=1, max_length=1000)
    sla_hours: int = Field(48, ge=1, le=24 * 30)
    details: dict = Field(default_factory=dict)


def _public(case: dict) -> dict:
    return {k: case[k] for k in ("case_id", "case_type", "priority", "status", "summary", "customer_ref",
                                 "created_at", "sla_due_at", "created_by", "run_id") if k in case} | (
        {"idempotent_replay": case["idempotent_replay"]} if "idempotent_replay" in case else {})


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    secrets = build_secret_provider(settings)
    db = open_database(settings, secrets, str(Path(settings.data_dir) / "cases.db"))
    audit = open_audit(settings, secrets, SERVICE, db)
    store = LocalCaseService(db, audit)
    verifier = ServiceTokenVerifier(settings.service_auth, secrets, SERVICE, settings.entra_tenant_id)
    user_tokens = InternalTokens(secrets)

    app = FastAPI(title="Case management service (synthetic CRM)", version="1.1.0",
                  docs_url=None if settings.is_prod else "/docs", redoc_url=None)
    instrument(app, SERVICE, audit)

    @app.post("/cases")
    async def create(body: CaseIn, request: Request,
                     idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
        verifier.verify(request.headers.get("authorization"), "cases.write")
        delegation = request.headers.get("x-delegation-token")
        if not delegation:
            raise ServiceError(401, "missing_user_context", "X-Delegation-Token is required")
        claims = user_tokens.verify_delegation(delegation, "create_case")
        if not idempotency_key or len(idempotency_key) < 8:
            raise ServiceError(422, "idempotency_key_required", "Idempotency-Key header is required")
        if body.case_type not in CASE_TYPES or body.priority not in PRIORITIES:
            raise ServiceError(422, "invalid_case", "unknown case_type or priority")
        if claims["pou"] != PURPOSE_FOR_CASE[body.case_type]:
            raise ServiceError(403, "forbidden",
                               f"purpose '{claims['pou']}' does not permit creating a {body.case_type} case")
        run_id = request.headers.get("x-run-id") or None
        if body.case_type == "dispute" and body.details.get("requires_approval"):
            approval = request.headers.get("x-approval-token")
            if not approval:
                raise ServiceError(403, "approval_required", "dispute above threshold requires reviewer approval")
            action = {"type": "create_dispute", "customer_ref": claims.get("customer_ref"),
                      "txn_id": body.details.get("txn_id"), "amount_cad": body.details.get("amount_cad")}
            approved = user_tokens.verify_approval(approval, run_id=run_id or "", action=action)
            if approved["sub"] == claims["sub"]:
                raise ServiceError(403, "four_eyes_violation", "requester cannot approve own action")
        case = await store.create_case(
            case_type=body.case_type, priority=body.priority, summary=body.summary,
            customer_ref=claims.get("customer_ref"), idempotency_key=idempotency_key, actor=claims["sub"],
            run_id=run_id, sla_hours=body.sla_hours, details=body.details,
        )
        return _public(case)

    @app.get("/cases")
    async def list_cases(request: Request, case_type: str | None = None):
        verifier.verify(request.headers.get("authorization"), "cases.read")
        return {"items": [_public(c) for c in await store.list_cases(case_type)]}

    @app.get("/cases/{case_id}")
    async def get_case(case_id: str, request: Request):
        verifier.verify(request.headers.get("authorization"), "cases.read")
        case = await store.get_case(case_id)
        if not case:
            raise ServiceError(404, "not_found", "case not found")
        return _public(case)

    return app
