"""Durable run registry (replaces the in-memory ``runs`` dict).

A *run* is one turn of an interaction processed by the agent graph. It records
who started it, which LangGraph thread it belongs to, its status, and — when
paused for human review — which interrupt is pending and the hash of the exact
action awaiting approval. Updates use optimistic concurrency (``version``) so
two reviewers cannot both resume the same run.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass

from .db import Database

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id            TEXT PRIMARY KEY,
    thread_id         TEXT NOT NULL,
    requested_by      TEXT NOT NULL,
    channel           TEXT NOT NULL,
    customer_ref      TEXT,
    idempotency_key   TEXT NOT NULL,
    status            TEXT NOT NULL,
    intent            TEXT,
    queue             TEXT,
    pending_interrupt TEXT,
    pending_action    TEXT,
    action_hash       TEXT,
    reviewer          TEXT,
    result            TEXT,
    metrics           TEXT,
    version           INTEGER NOT NULL DEFAULT 1,
    created_at        REAL NOT NULL,
    updated_at        REAL NOT NULL,
    UNIQUE (requested_by, idempotency_key)
);
CREATE INDEX IF NOT EXISTS ix_runs_status ON runs(status);
CREATE INDEX IF NOT EXISTS ix_runs_thread ON runs(thread_id);
"""


class RunStatus:
    RUNNING = "running"
    AWAITING_REVIEW = "awaiting_review"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"


class ConcurrencyError(Exception):
    pass


@dataclass
class Run:
    run_id: str
    thread_id: str
    requested_by: str
    channel: str
    customer_ref: str | None
    idempotency_key: str
    status: str
    intent: str | None
    queue: str | None
    pending_interrupt: str | None
    pending_action: dict | None
    action_hash: str | None
    reviewer: str | None
    result: dict | None
    metrics: dict | None
    version: int
    created_at: float
    updated_at: float

    @classmethod
    def from_row(cls, row: dict) -> "Run":
        row = dict(row)
        for k in ("pending_action", "result", "metrics"):
            row[k] = json.loads(row[k]) if row.get(k) else None
        return cls(**row)


class RunRepository:
    def __init__(self, db: Database) -> None:
        self.db = db
        for stmt in SCHEMA.strip().split(";"):
            if stmt.strip():
                db.execute(stmt)

    def create_or_get(
        self, *, requested_by: str, idempotency_key: str, thread_id: str | None, channel: str, customer_ref: str | None
    ) -> tuple[Run, bool]:
        """Idempotent create. Returns (run, created)."""
        existing = self.db.query_one(
            "SELECT * FROM runs WHERE requested_by=? AND idempotency_key=?", (requested_by, idempotency_key)
        )
        if existing:
            return Run.from_row(existing), False
        now = time.time()
        run_id = f"run_{uuid.uuid4().hex}"
        thread_id = thread_id or f"thr_{uuid.uuid4().hex}"
        try:
            self.db.execute(
                "INSERT INTO runs (run_id, thread_id, requested_by, channel, customer_ref, idempotency_key, status,"
                " version, created_at, updated_at) VALUES (?,?,?,?,?,?,?,1,?,?)",
                (run_id, thread_id, requested_by, channel, customer_ref, idempotency_key, RunStatus.RUNNING, now, now),
            )
        except Exception:
            # lost a race with a concurrent identical request
            row = self.db.query_one(
                "SELECT * FROM runs WHERE requested_by=? AND idempotency_key=?", (requested_by, idempotency_key)
            )
            if row:
                return Run.from_row(row), False
            raise
        return self.get(run_id), True  # type: ignore[return-value]

    def get(self, run_id: str) -> Run | None:
        row = self.db.query_one("SELECT * FROM runs WHERE run_id=?", (run_id,))
        return Run.from_row(row) if row else None

    def latest_for_thread(self, thread_id: str) -> Run | None:
        row = self.db.query_one("SELECT * FROM runs WHERE thread_id=? ORDER BY created_at DESC LIMIT 1", (thread_id,))
        return Run.from_row(row) if row else None

    def update(self, run_id: str, expected_version: int, **fields) -> Run:
        for k in ("pending_action", "result", "metrics"):
            if k in fields and fields[k] is not None and not isinstance(fields[k], str):
                fields[k] = json.dumps(fields[k], default=str)
        fields["updated_at"] = time.time()
        cols = ", ".join(f"{k}=?" for k in fields)
        n = self.db.execute(
            f"UPDATE runs SET {cols}, version=version+1 WHERE run_id=? AND version=?",
            (*fields.values(), run_id, expected_version),
        )
        if n != 1:
            raise ConcurrencyError(f"run {run_id} was modified concurrently")
        return self.get(run_id)  # type: ignore[return-value]

    def list_by_status(self, status: str, limit: int = 100) -> list[Run]:
        rows = self.db.query("SELECT * FROM runs WHERE status=? ORDER BY created_at LIMIT ?", (status, limit))
        return [Run.from_row(r) for r in rows]

    def all_runs(self, since: float = 0.0) -> list[Run]:
        return [Run.from_row(r) for r in self.db.query("SELECT * FROM runs WHERE created_at>=?", (since,))]
