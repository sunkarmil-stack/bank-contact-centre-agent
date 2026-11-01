"""HTTP API (FastAPI).

Edge controls (in front of this service in production): Azure Front Door/WAF →
API Management (JWT validation, rate-limit-by-key, mTLS to backends) → private
Container Apps / AKS ingress. This app re-validates identity and applies its
own rate limit, request size limit and security headers (defense in depth).
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from ..config import Settings
from ..container import build_container
from ..demo_scenarios import SCENARIOS
from ..logging_setup import configure_logging, correlation_id, log_event, request_entry
from ..ops.kpis import compute_kpis
from ..ops.workforce import required_agents
from ..secrets import build_secret_provider
from ..security.auth import AuthError, Principal, Role
from ..security.service_tokens import ServiceAuthError, ServiceTokenVerifier
from ..service import ContactCentreService, ServiceError
from ..telemetry import METRICS, setup_telemetry

log = logging.getLogger("ccagent.api")
MAX_BODY_BYTES = 16 * 1024
STATIC = Path(__file__).resolve().parent.parent.parent / "static"


# ------------------------------------------------------------------ schemas
class InteractionRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    thread_id: str | None = Field(default=None, pattern=r"^thr_[a-f0-9]{32}$")


class ReviewRequest(BaseModel):
    decision: str = Field(pattern="^(approve|reject)$")
    interrupt_id: str = Field(min_length=8, max_length=128)
    action_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    comment: str = Field(default="", max_length=1000)


class StaffingRequest(BaseModel):
    contacts_per_interval: float = Field(gt=0, le=100000)
    aht_s: float = Field(gt=0, le=7200)
    interval_s: int = 1800
    target_service_level: float = Field(0.8, gt=0, lt=1)
    target_answer_s: int = Field(20, gt=0)
    shrinkage: float = Field(0.30, ge=0, lt=1)
    ai_containment_rate: float = Field(0.0, ge=0, lt=1)


class DevTokenRequest(BaseModel):
    persona: str = Field(pattern="^(ivr_authenticated|ivr_unauthenticated|agent|reviewer|reviewer2|supervisor|auditor)$")
    customer_ref: str = "SYN-C-1001"


def render_console(data: dict) -> str:
    """Wrap the console page (an HTML fragment, also publishable as a standalone page) with
    its data: live mode (scenario list only) or replay mode (a recording of real runs)."""
    fragment = (STATIC / "console.html").read_text()
    payload = json.dumps(data, default=str).replace("</", "<\\/")
    fragment = fragment.replace("__CONSOLE_DATA__", payload)
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1"></head><body>'
            + fragment + "</body></html>")


def _kb_titles() -> dict:
    kb = json.loads((STATIC.parent / "data" / "knowledge_base.json").read_text())
    return {d["doc_id"]: {"title": d["title"], "owner": d["owner"], "effective_date": d["effective_date"]}
            for d in kb["documents"]}


def create_app(settings: Settings | None = None, model=None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging()
        conn_str = None
        if settings.otel_exporter == "azure_monitor":
            from ..llm.foundry import app_insights_connection_string

            conn_str = app_insights_connection_string(settings)
        setup_telemetry(settings, conn_str)
        async with build_container(settings, model=model) as c:
            app.state.container = c
            app.state.service = ContactCentreService(c)
            log_event(log, "service started", env=settings.env, llm=settings.llm_provider,
                      persistence=settings.persistence, retriever=settings.retriever)
            yield

    ingress_verifier = ServiceTokenVerifier(settings.service_auth, build_secret_provider(settings), "agent-api",
                                            settings.entra_tenant_id)

    app = FastAPI(
        title="CIBC Contact Centre Agentic AI (reference implementation)",
        version="1.0.0",
        description="SAMPLE with synthetic data only.",
        lifespan=lifespan,
        docs_url=None if settings.is_prod else "/docs",
        redoc_url=None,
    )

    # ------------------------------------------------------------ middleware
    @app.middleware("http")
    async def edge(request: Request, call_next):
        cid = request.headers.get("x-correlation-id") or uuid.uuid4().hex
        token = correlation_id.set(cid)
        entry_token = request_entry.set("direct")
        started = time.perf_counter()
        try:
            if int(request.headers.get("content-length") or 0) > MAX_BODY_BYTES:
                return JSONResponse({"error": "payload_too_large"}, status_code=413)
            gw = request.headers.get("x-gateway-token")
            if gw:
                try:
                    ingress_verifier.verify("Bearer " + gw, "api.ingress")
                    request_entry.set("api-gateway")
                except ServiceAuthError:
                    return JSONResponse({"error": "invalid_gateway_token"}, status_code=403)
            if settings.require_gateway and request.url.path.startswith("/v1/") and request_entry.get() != "api-gateway":
                return JSONResponse({"error": "gateway_required",
                                     "message": "This API is only reachable through the API gateway"}, status_code=403)
            response = await call_next(request)
            elapsed = time.perf_counter() - started
            METRICS.inc("http_requests_total", route=request.url.path.split("/")[2] if request.url.path.count("/") > 1
                        else request.url.path, status=response.status_code)
            response.headers.update({
                "X-Correlation-Id": cid,
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            })
            if not request.url.path.startswith(("/console", "/docs", "/openapi")):
                response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
            log_event(log, "request", method=request.method, path=request.url.path, status=response.status_code,
                      duration_ms=round(elapsed * 1000, 1))
        finally:
            correlation_id.reset(token)
            request_entry.reset(entry_token)
        return response

    @app.exception_handler(ServiceError)
    async def service_error(_: Request, exc: ServiceError):
        return JSONResponse({"error": exc.code, "message": str(exc)}, status_code=exc.status)

    # ------------------------------------------------------------ auth deps
    def svc(request: Request) -> ContactCentreService:
        return request.app.state.service

    async def principal(request: Request, authorization: str | None = Header(default=None)) -> Principal:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
        c = request.app.state.container
        try:
            p = c.validator.validate(authorization.split(" ", 1)[1])
        except AuthError as e:
            c.audit.append("auth_failed", "anonymous", None, reason=str(e)[:200], path=request.url.path)
            raise HTTPException(e.status, str(e), headers={"WWW-Authenticate": "Bearer"}) from e
        if not c.limiter.allow(p.sub):
            METRICS.inc("rate_limited_total")
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": "5"})
        return p

    def require(*roles: str):
        async def dep(p: Principal = Depends(principal)) -> Principal:
            if not p.has_any(*roles):
                raise HTTPException(403, f"requires one of roles {sorted(roles)}")
            return p

        return dep

    # --------------------------------------------------------------- health
    @app.get("/healthz")
    async def healthz():
        from .. import __version__

        return {"status": "ok", "service": "agent-api", "version": __version__}

    @app.get("/readyz")
    async def readyz(request: Request):
        c = request.app.state.container
        c.db.query_one("SELECT 1 AS ok")
        return {"status": "ready", "audit_chain_valid": c.audit.verify_chain()["valid"]}

    # --------------------------------------------------------- interactions
    @app.post("/v1/interactions", status_code=200)
    async def start_interaction(
        body: InteractionRequest,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=8, max_length=128),
        p: Principal = Depends(require(Role.AGENT, Role.CHANNEL)),
        s: ContactCentreService = Depends(svc),
    ):
        return await s.start_turn(p, message=body.message, idempotency_key=idempotency_key, thread_id=body.thread_id)

    @app.get("/v1/runs/{run_id}")
    async def get_run(run_id: str, p: Principal = Depends(principal), s: ContactCentreService = Depends(svc)):
        return s.get_run(p, run_id)

    @app.get("/v1/runs/{run_id}/explain")
    async def explain_run(run_id: str, p: Principal = Depends(principal), s: ContactCentreService = Depends(svc)):
        return await s.explain(p, run_id)

    # --------------------------------------------------------- human review
    @app.get("/v1/reviews/pending")
    async def pending(p: Principal = Depends(require(Role.REVIEWER, Role.SUPERVISOR)),
                      s: ContactCentreService = Depends(svc)):
        return {"items": s.pending_reviews(p)}

    @app.post("/v1/runs/{run_id}/review")
    async def review(run_id: str, body: ReviewRequest, p: Principal = Depends(require(Role.REVIEWER)),
                     s: ContactCentreService = Depends(svc)):
        return await s.submit_review(p, run_id, decision=body.decision, interrupt_id=body.interrupt_id,
                                     action_hash_expected=body.action_hash, comment=body.comment)

    # ----------------------------------------------------- operations (WFM/QA)
    @app.get("/v1/ops/kpis")
    async def kpis(request: Request, hours: float = 24, _: Principal = Depends(require(Role.SUPERVISOR))):
        c = request.app.state.container
        return compute_kpis(c.runs, await c.cases.list_cases(), since_hours=min(max(hours, 1), 24 * 31))

    @app.get("/v1/ops/metrics")
    async def metrics(_: Principal = Depends(require(Role.SUPERVISOR, Role.AUDITOR))):
        return METRICS.snapshot()

    @app.post("/v1/ops/staffing")
    async def staffing(body: StaffingRequest, _: Principal = Depends(require(Role.SUPERVISOR))):
        return required_agents(**body.model_dump())

    @app.get("/v1/ops/cases")
    async def cases(request: Request, case_type: str | None = None,
                    _: Principal = Depends(require(Role.SUPERVISOR, Role.AUDITOR))):
        rows = await request.app.state.container.cases.list_cases(case_type)
        return {"items": [{k: r[k] for k in ("case_id", "case_type", "priority", "status", "created_at",
                                              "sla_due_at", "summary")} for r in rows]}

    # ------------------------------------------------------------- audit
    @app.get("/v1/audit/runs/{run_id}")
    async def audit_run(request: Request, run_id: str, _: Principal = Depends(require(Role.AUDITOR))):
        return {"events": request.app.state.container.audit.events(run_id)}

    @app.get("/v1/audit/verify")
    async def audit_verify(request: Request, _: Principal = Depends(require(Role.AUDITOR))):
        return request.app.state.container.audit.verify_chain()

    # --------------------------------------------------- local demo helpers
    if settings.env in ("local", "test") and settings.auth_mode == "dev":
        personas = {
            "ivr_authenticated": ("ivr-channel-svc", [Role.CHANNEL], {"channel": "ivr", "cust_auth_level": 1}),
            "ivr_unauthenticated": ("ivr-channel-svc", [Role.CHANNEL], {"channel": "ivr", "cust_auth_level": 0}),
            "agent": ("agent-001", [Role.AGENT], {"channel": "agent_desktop", "cust_auth_level": 1}),
            "reviewer": ("reviewer-007", [Role.REVIEWER], {}),
            "reviewer2": ("reviewer-008", [Role.REVIEWER], {}),
            "supervisor": ("supervisor-01", [Role.SUPERVISOR], {}),
            "auditor": ("auditor-01", [Role.AUDITOR], {}),
        }

        @app.post("/dev/token", include_in_schema=False)
        async def dev_token(request: Request, body: DevTokenRequest):
            sub, roles, extra = personas[body.persona]
            if roles[0] in (Role.CHANNEL, Role.AGENT):
                extra = {**extra, "customer_ref": body.customer_ref}
            token = request.app.state.container.validator.mint(sub, roles, ttl_s=3600, **extra)
            return {"access_token": token, "token_type": "Bearer", "sub": sub, "roles": roles}

        @app.get("/console", include_in_schema=False)
        async def console():
            return HTMLResponse(render_console({"mode": "live", "scenarios": SCENARIOS, "kb": _kb_titles()}))

    return app


# Run with:  uvicorn ccagent.api.app:create_app --factory --port 8080
