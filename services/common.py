"""Cross-cutting plumbing shared by the microservices: correlation IDs, structured
request logs, security headers, uniform error bodies and request counters."""

from __future__ import annotations

import logging
import time
import uuid
from collections import Counter

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ccagent.logging_setup import configure_logging, correlation_id, log_event
from ccagent.security.service_tokens import ServiceAuthError
from ccagent.security.tokens import TokenError

VERSION = "1.1.0"


class ServiceError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": code, "message": message}, status_code=status)


def instrument(app: FastAPI, service: str, audit=None) -> Counter:
    """Attach middleware + error handlers. Returns a request counter for /metrics."""
    configure_logging()
    log = logging.getLogger(service)
    counts: Counter = Counter()

    @app.middleware("http")
    async def _mw(request: Request, call_next):
        cid = request.headers.get("x-correlation-id") or uuid.uuid4().hex
        token = correlation_id.set(cid)
        started = time.perf_counter()
        try:
            response = await call_next(request)
            counts[f"{request.method} {request.scope.get('route').path if request.scope.get('route') else request.url.path} {response.status_code}"] += 1
            response.headers.update({"X-Service": service, "X-Correlation-Id": cid, "Cache-Control": "no-store",
                                     "X-Content-Type-Options": "nosniff"})
            log_event(log, "request", method=request.method, path=request.url.path, status=response.status_code,
                      duration_ms=round((time.perf_counter() - started) * 1000, 1), service=service)
            return response
        finally:
            correlation_id.reset(token)

    def _deny(request: Request, status: int, code: str, message: str):
        if audit is not None:
            audit.append("service_access_denied", "unknown", request.headers.get("x-run-id") or None,
                         path=request.url.path, status=status, reason=code, detail=message[:200])
        return error(status, code, message)

    @app.exception_handler(ServiceAuthError)
    async def _svc_auth(request: Request, exc: ServiceAuthError):
        return _deny(request, exc.status, "unauthorized" if exc.status == 401 else "forbidden", str(exc))

    @app.exception_handler(TokenError)
    async def _tok(request: Request, exc: TokenError):
        return _deny(request, 401, "invalid_user_token", str(exc))

    @app.exception_handler(ServiceError)
    async def _svc(request: Request, exc: ServiceError):
        if exc.status in (401, 403):
            return _deny(request, exc.status, exc.code, str(exc))
        return error(exc.status, exc.code, str(exc))

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return {"status": "ok", "service": service, "version": VERSION}

    @app.get("/metrics", include_in_schema=False)
    async def metrics():
        return {"service": service, "requests": dict(counts)}

    return counts
