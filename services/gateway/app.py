"""API gateway (edge) — the single entry point for channels, agent desktops and the console.

    uvicorn services.gateway.app:create_app --factory --port 8000

Local stand-in for Azure Front Door + API Management. The same policies are documented
as APIM policies in docs/03-integration-design.md.

Policies, in order:
  1. Route allow-list: unknown paths get 404 (deny by default).
  2. Request size limit: 16 KB (413).
  3. Authentication at the edge: bearer token validated (Entra ID in production, dev
     tokens locally) before any traffic reaches the agent. Public routes are listed
     explicitly (console page, health, local dev sign-in).
  4. Rate limiting per signed-in principal, and per client address on public routes (429).
  5. Header hygiene: hop-by-hop headers and internal trust headers (delegation,
     approval, gateway, forwarded) are stripped from the client request so they can't
     be spoofed. Correlation ID and forwarding headers are added.
  6. Ingress proof: a short-lived workload token (``X-Gateway-Token``) tells the agent API
     the request really came through the gateway. The API refuses /v1 traffic without it
     when ``CCAGENT_REQUIRE_GATEWAY=true``.
  7. Upstream timeout (504) and connection failure (502) handling; latency and status
     metrics per route; aggregated health of every service.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from ccagent.config import Settings
from ccagent.logging_setup import configure_logging, correlation_id, log_event
from ccagent.secrets import build_secret_provider
from ccagent.security.auth import AuthError, Role, build_validator
from ccagent.security.ratelimit import TokenBucketLimiter
from ccagent.security.service_tokens import build_service_tokens

from ..common import VERSION

log = logging.getLogger("api-gateway")
MAX_BODY_BYTES = 16 * 1024
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
              "transfer-encoding", "upgrade", "host", "content-length"}
# Internal trust headers a client must never be able to set.
STRIP_PREFIXES = ("x-delegation", "x-approval", "x-gateway", "x-forwarded", "x-on-behalf", "x-purpose",
                  "x-run-id", "x-service", "x-real-ip")
_CID = re.compile(r"^[A-Za-z0-9-]{8,64}$")


@dataclass(frozen=True)
class Route:
    name: str
    prefix: str
    upstream: str
    auth: bool
    description: str


def _routes(api: str) -> list[Route]:
    return [
        Route("agent-api", "/v1/", api, True, "Interactions, reviews, explainability, supervisor and audit APIs"),
        Route("console", "/console", api, False, "Demo console page (calls /v1 through this gateway)"),
        Route("dev-signin", "/dev/token", api, False, "Local demo sign-in (disabled outside local/test)"),
        Route("api-docs", "/docs", api, False, "Agent API reference"),
        Route("api-schema", "/openapi.json", api, False, "Agent API schema"),
    ]


class GatewayMetrics:
    def __init__(self) -> None:
        self.started = time.time()
        self.by_route: dict[str, dict] = defaultdict(lambda: {"requests": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0,
                                                              "latency_ms": []})
        self.policy = defaultdict(int)

    def record(self, route: str, status: int, ms: float) -> None:
        r = self.by_route[route]
        r["requests"] += 1
        r[f"{status // 100}xx"] = r.get(f"{status // 100}xx", 0) + 1
        r["latency_ms"].append(ms)
        if len(r["latency_ms"]) > 2000:
            del r["latency_ms"][:1000]

    def snapshot(self) -> dict:
        def pct(v, p):
            s = sorted(v)
            return round(s[min(len(s) - 1, int(p / 100 * (len(s) - 1)))], 1) if s else None

        return {
            "uptime_s": round(time.time() - self.started),
            "routes": {k: {**{x: y for x, y in v.items() if x != "latency_ms"},
                           "p50_ms": pct(v["latency_ms"], 50), "p95_ms": pct(v["latency_ms"], 95)}
                       for k, v in self.by_route.items()},
            "policy_rejections": dict(self.policy),
        }


def create_app(settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    secrets = build_secret_provider(settings)
    validator = build_validator(settings, secrets)
    ingress = build_service_tokens(settings.service_auth, secrets, caller="api-gateway")
    api_url = os.getenv("GATEWAY_UPSTREAM_AGENT_API", "http://127.0.0.1:8080").rstrip("/")
    routes = _routes(api_url)
    health_targets = {
        "agent-api": api_url,
        "mcp-tool-service": os.getenv("GATEWAY_HEALTH_MCP", "http://127.0.0.1:8765"),
        "customer-service": os.getenv("GATEWAY_HEALTH_CUSTOMER", "http://127.0.0.1:8101"),
        "case-service": os.getenv("GATEWAY_HEALTH_CASE", "http://127.0.0.1:8102"),
    }
    user_limiter = TokenBucketLimiter(int(os.getenv("GATEWAY_RATE_LIMIT_PER_MINUTE", "240")))
    public_limiter = TokenBucketLimiter(int(os.getenv("GATEWAY_PUBLIC_RATE_LIMIT_PER_MINUTE", "120")))
    upstream_timeout = float(os.getenv("GATEWAY_UPSTREAM_TIMEOUT_S", "70"))
    metrics = GatewayMetrics()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging()
        async with httpx.AsyncClient(timeout=upstream_timeout, follow_redirects=False, transport=transport) as client:
            app.state.client = client
            log_event(log, "gateway started", upstream=api_url, routes=[r.prefix for r in routes])
            yield

    app = FastAPI(title="API gateway", version=VERSION, docs_url=None, redoc_url=None, lifespan=lifespan)

    def reject(status: int, code: str, message: str, cid: str, extra: dict | None = None) -> JSONResponse:
        metrics.policy[code] += 1
        return JSONResponse({"error": code, "message": message}, status_code=status,
                            headers={"X-Correlation-Id": cid, "X-Served-By": "api-gateway", **(extra or {})})

    # ----------------------------------------------------------- gateway's own endpoints
    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return {"status": "ok", "service": "api-gateway", "version": VERSION}

    @app.get("/gateway/routes")
    async def list_routes():
        return {"routes": [{"name": r.name, "prefix": r.prefix, "upstream": r.upstream, "auth_required": r.auth,
                            "description": r.description} for r in routes]}

    @app.get("/gateway/health")
    async def health(request: Request):
        client: httpx.AsyncClient = request.app.state.client

        async def probe(name: str, base: str) -> dict:
            started = time.perf_counter()
            try:
                r = await client.get(base.rstrip("/") + "/healthz", timeout=2.0)
                body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                status = "up" if r.status_code == 200 else "degraded"
            except Exception as exc:  # noqa: BLE001 — health must never raise
                body, status = {"error": exc.__class__.__name__}, "down"
            return {"name": name, "url": base, "status": status,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                    "version": body.get("version"), "detail": body.get("backends") or body.get("error")}

        results = await asyncio.gather(*(probe(n, u) for n, u in health_targets.items()))
        gw = {"name": "api-gateway", "url": str(request.base_url).rstrip("/"), "status": "up", "latency_ms": 0,
              "version": VERSION, "detail": None}
        overall = "up" if all(r["status"] == "up" for r in results) else "degraded"
        return {"status": overall, "services": [gw, *results]}

    @app.get("/gateway/metrics")
    async def gw_metrics(request: Request):
        try:
            p = validator.validate((request.headers.get("authorization") or " ").split(" ", 1)[1])
        except (AuthError, IndexError):
            return reject(401, "unauthorized", "supervisor or auditor token required", uuid.uuid4().hex)
        if not p.has_any(Role.SUPERVISOR, Role.AUDITOR):
            return reject(403, "forbidden", "supervisor or auditor role required", uuid.uuid4().hex)
        return metrics.snapshot()

    # ---------------------------------------------------------------------- proxy
    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
    async def proxy(path: str, request: Request):
        started = time.perf_counter()
        inbound = request.headers.get("x-correlation-id") or ""
        cid = inbound if _CID.match(inbound) else uuid.uuid4().hex
        token = correlation_id.set(cid)
        try:
            p = "/" + path
            route = next((r for r in routes if p == r.prefix.rstrip("/") or p.startswith(r.prefix)), None)
            if route is None:                                                               # 1. allow-list
                return reject(404, "no_route", f"no route for {p}", cid)
            if int(request.headers.get("content-length") or 0) > MAX_BODY_BYTES:          # 2. size
                return reject(413, "payload_too_large", "request body exceeds 16 KB", cid)

            principal = None
            if route.auth:                                                                 # 3. authentication
                authz = request.headers.get("authorization") or ""
                if not authz.lower().startswith("bearer "):
                    return reject(401, "unauthorized", "bearer token required", cid, {"WWW-Authenticate": "Bearer"})
                try:
                    principal = validator.validate(authz.split(" ", 1)[1])
                except AuthError as e:
                    return reject(e.status, "unauthorized" if e.status == 401 else "forbidden", str(e), cid)
                if not user_limiter.allow(principal.sub):                                  # 4. rate limit
                    return reject(429, "rate_limited", "too many requests", cid, {"Retry-After": "5"})
            else:
                client_ip = request.client.host if request.client else "unknown"
                if not public_limiter.allow(client_ip):
                    return reject(429, "rate_limited", "too many requests", cid, {"Retry-After": "5"})

            # 5. header hygiene — names normalised to lower case so a client-supplied header can
            #    never sit alongside (and be confused with) the gateway's own value.
            headers = {k.lower(): v for k, v in request.headers.items()
                       if k.lower() not in HOP_BY_HOP and k.lower() != "x-correlation-id"
                       and not k.lower().startswith(STRIP_PREFIXES)}
            headers.update({
                "x-correlation-id": cid,
                "x-forwarded-for": request.client.host if request.client else "unknown",
                "x-forwarded-proto": request.url.scheme,
                "x-gateway-route": route.name,
                "x-gateway-token": await ingress.token_for("agent-api", ttl_s=60),             # 6. ingress proof
            })
            body = await request.body()
            url = route.upstream + p + (f"?{request.url.query}" if request.url.query else "")
            client: httpx.AsyncClient = request.app.state.client
            try:
                up = await client.request(request.method, url, headers=headers, content=body)
            except httpx.TimeoutException:                                                 # 7. upstream errors
                return reject(504, "upstream_timeout", f"{route.name} did not respond in time", cid)
            except httpx.TransportError:
                return reject(502, "upstream_unavailable", f"{route.name} is unavailable", cid)

            ms = (time.perf_counter() - started) * 1000
            metrics.record(route.name, up.status_code, ms)
            out_headers = {k: v for k, v in up.headers.items()
                           if k.lower() not in HOP_BY_HOP and k.lower() != "content-encoding"}
            out_headers.update({"X-Correlation-Id": cid, "X-Served-By": "api-gateway", "X-Upstream": route.name,
                                "X-Gateway-Latency-Ms": f"{ms:.1f}"})
            log_event(log, "proxied", route=route.name, method=request.method, path=p, status=up.status_code,
                      duration_ms=round(ms, 1), principal=principal.sub if principal else None)
            return Response(content=up.content, status_code=up.status_code, headers=out_headers)
        finally:
            correlation_id.reset(token)

    return app
