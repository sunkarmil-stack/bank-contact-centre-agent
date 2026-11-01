"""Durable, encrypted LangGraph checkpointer (short-term memory) and store
(long-term memory).

Replaces ``MemorySaver``: state survives restarts and is shared by all workers.

* local/dev : ``AsyncSqliteSaver`` + ``AsyncSqliteStore`` (WAL file on disk)
* prod      : ``AsyncPostgresSaver`` + ``AsyncPostgresStore`` (Azure Database for
              PostgreSQL, private endpoint, CMK encryption at rest)

Application-level encryption: every checkpoint blob is AES-256-GCM encrypted
with a key from the secret provider (Key Vault in prod), on top of storage
encryption — so DB operators / backups never see conversation content in clear.
The cipher name carries a key version to support key rotation.

Retention: the long-term store uses LangGraph's native TTL with a background
sweeper; checkpoints are pruned by ``scripts/purge_expired.py`` per the
approved retention schedule.
"""

from __future__ import annotations

import base64
import os
from contextlib import asynccontextmanager

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from langgraph.checkpoint.serde.encrypted import EncryptedSerializer
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from ..config import Settings
from ..secrets import CHECKPOINT_ENCRYPTION_KEY, SecretProvider


class AESGCMCipher:
    """Implements LangGraph's ``CipherProtocol`` with AES-256-GCM."""

    def __init__(self, keys: dict[str, bytes], active_version: str) -> None:
        for v, k in keys.items():
            if len(k) != 32:
                raise ValueError(f"key {v} must be 32 bytes (AES-256)")
        self._keys = keys
        self._active = active_version

    def encrypt(self, plaintext: bytes) -> tuple[str, bytes]:
        nonce = os.urandom(12)
        ct = AESGCM(self._keys[self._active]).encrypt(nonce, plaintext, None)
        return f"aesgcm-{self._active}", nonce + ct

    def decrypt(self, ciphername: str, ciphertext: bytes) -> bytes:
        if not ciphername.startswith("aesgcm-"):
            raise ValueError(f"unsupported cipher {ciphername}")
        version = ciphername.removeprefix("aesgcm-")
        key = self._keys[version]
        return AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], None)


def build_serializer(secrets: SecretProvider) -> EncryptedSerializer:
    raw = base64.urlsafe_b64decode(secrets.get(CHECKPOINT_ENCRYPTION_KEY))[:32]
    cipher = AESGCMCipher({"v1": raw}, active_version="v1")
    return EncryptedSerializer(cipher, JsonPlusSerializer())


@asynccontextmanager
async def open_memory(settings: Settings, secrets: SecretProvider):
    """Yield (checkpointer, store) for the configured backend."""
    serde = build_serializer(secrets)
    ttl = {"default_ttl": settings.memory_ttl_minutes, "refresh_on_read": False, "sweep_interval_minutes": 60}

    if settings.persistence == "postgres":
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver  # optional dependency
        from langgraph.store.postgres.aio import AsyncPostgresStore

        dsn = secrets.get("postgres-dsn")
        async with AsyncPostgresSaver.from_conn_string(dsn, serde=serde) as saver, AsyncPostgresStore.from_conn_string(
            dsn, ttl=ttl
        ) as store:
            await saver.setup()
            await store.setup()
            await store.start_ttl_sweeper()
            try:
                yield saver, store
            finally:
                await store.stop_ttl_sweeper()
        return

    import aiosqlite
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
    from langgraph.store.sqlite.aio import AsyncSqliteStore

    path = settings.sqlite_path
    if path != ":memory:":
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    cp_conn = await aiosqlite.connect(path.replace(".db", ".checkpoints.db") if path != ":memory:" else path)
    st_conn = await aiosqlite.connect(
        path.replace(".db", ".memory.db") if path != ":memory:" else path, isolation_level=None
    )
    await cp_conn.execute("PRAGMA journal_mode=WAL")
    await st_conn.execute("PRAGMA journal_mode=WAL")
    saver = AsyncSqliteSaver(cp_conn, serde=serde)
    store = AsyncSqliteStore(st_conn, ttl=ttl)
    await saver.setup()
    await store.setup()
    try:
        yield saver, store
    finally:
        await cp_conn.close()
        await st_conn.close()
