"""Tamper-evident audit trail.

Every security-relevant event (authentication decisions, customer-data access
with purpose of use, guardrail blocks, tool calls, human approvals/rejections,
memory writes) is appended with a SHA-256 hash chain: each record's hash covers
its content plus the previous record's hash, so any edit or deletion is
detectable with ``verify_chain``.

Production: stream the same records to an immutable (WORM) store — e.g. Azure
Blob immutable storage + Microsoft Sentinel — under the bank's record
retention schedule.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid

from ..security.pii import redact_obj
from .db import Database

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id   TEXT NOT NULL UNIQUE,
    ts         REAL NOT NULL,
    event_type TEXT NOT NULL,
    actor      TEXT NOT NULL,
    run_id     TEXT,
    details    TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
)
"""

_GENESIS = "0" * 64


def _digest(
    prev_hash: str, event_id: str, ts: float, event_type: str, actor: str, run_id: str | None, details: str
) -> str:
    payload = json.dumps([prev_hash, event_id, round(ts, 6), event_type, actor, run_id, details], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLog:
    """``service`` names the writer (agent-api, mcp-tool-service, customer-service, …).
    All services may share one audit store so a run's trail is complete end to end."""

    def __init__(self, db: Database, service: str = "agent-api") -> None:
        self.db = db
        self.service = service
        db.execute(SCHEMA)

    def append(self, event_type: str, actor: str, run_id: str | None = None, **details) -> str:
        details = {**details, "service": self.service}
        details_json = json.dumps(redact_obj(details), sort_keys=True, default=str)
        with self.db.transaction():
            last = self.db.query_one("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            prev = last["hash"] if last else _GENESIS
            event_id = uuid.uuid4().hex
            ts = round(time.time(), 6)
            h = _digest(prev, event_id, ts, event_type, actor, run_id, details_json)
            self.db.execute(
                "INSERT INTO audit_log (event_id, ts, event_type, actor, run_id, details, prev_hash, hash)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (event_id, ts, event_type, actor, run_id, details_json, prev, h),
            )
        return event_id

    def events(self, run_id: str | None = None, limit: int = 500) -> list[dict]:
        if run_id:
            rows = self.db.query("SELECT * FROM audit_log WHERE run_id=? ORDER BY seq LIMIT ?", (run_id, limit))
        else:
            rows = self.db.query("SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?", (limit,))
        for r in rows:
            r["details"] = json.loads(r["details"])
        return rows

    def verify_chain(self) -> dict:
        prev = _GENESIS
        count = 0
        for r in self.db.query("SELECT * FROM audit_log ORDER BY seq"):
            expected = _digest(prev, r["event_id"], r["ts"], r["event_type"], r["actor"], r["run_id"], r["details"])
            if r["prev_hash"] != prev or r["hash"] != expected:
                return {"valid": False, "broken_at_seq": r["seq"], "checked": count}
            prev = r["hash"]
            count += 1
        return {"valid": True, "checked": count}
