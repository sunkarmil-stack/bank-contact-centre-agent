"""Minimal DB-API helper so repositories run on SQLite (local) and
PostgreSQL (prod) with the same SQL.

SQLite runs in WAL mode so several worker processes on one host share state.
PostgreSQL (Azure Database for PostgreSQL Flexible Server, encryption at rest
with customer-managed keys, private endpoint) is the production target.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path


class Database:
    def __init__(self, dsn_or_path: str, kind: str = "sqlite") -> None:
        self.kind = kind
        self._lock = threading.RLock()
        if kind == "sqlite":
            if dsn_or_path != ":memory:":
                Path(dsn_or_path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(dsn_or_path, check_same_thread=False, isolation_level=None, timeout=30)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.execute("PRAGMA foreign_keys=ON")
        elif kind == "postgres":
            import psycopg  # optional dependency
            from psycopg.rows import dict_row

            self._conn = psycopg.connect(dsn_or_path, autocommit=True, row_factory=dict_row)
        else:
            raise ValueError(kind)

    _PG_REWRITES = (
        ("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY"),
        (" REAL ", " DOUBLE PRECISION "),
        (" REAL,", " DOUBLE PRECISION,"),
        (" REAL\n", " DOUBLE PRECISION\n"),
        ("datetime('now')", "now()::text"),
        ("BEGIN IMMEDIATE", "BEGIN"),
    )

    def _sql(self, sql: str) -> str:
        if self.kind == "sqlite":
            return sql
        for a, b in self._PG_REWRITES:
            sql = sql.replace(a, b)
        return sql.replace("?", "%s")

    def execute(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            cur = self._conn.execute(self._sql(sql), params)
            return cur.rowcount

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(self._sql(sql), params)
            return [dict(r) for r in cur.fetchall()]

    def query_one(self, sql: str, params: tuple = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    @contextmanager
    def transaction(self):
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE" if self.kind == "sqlite" else "BEGIN")
            try:
                yield self
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def close(self) -> None:
        self._conn.close()
