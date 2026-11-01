"""Structured JSON logging with correlation IDs and PII redaction."""

from __future__ import annotations

import contextvars
import json
import logging
import sys
import time

from .security.pii import redact, redact_obj

correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="-")
# How the current request entered the platform: "api-gateway" (verified ingress token) or "direct".
request_entry: contextvars.ContextVar[str] = contextvars.ContextVar("request_entry", default="direct")


class RedactingJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage())[0],
            "correlation_id": correlation_id.get(),
        }
        extra = getattr(record, "fields", None)
        if extra:
            payload.update(redact_obj(extra))
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))[0]
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(RedactingJsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for noisy in ("httpx", "httpcore", "aiosqlite"):
        logging.getLogger(noisy).setLevel("WARNING")


def log_event(logger: logging.Logger, msg: str, level: int = logging.INFO, **fields) -> None:
    logger.log(level, msg, extra={"fields": fields})
