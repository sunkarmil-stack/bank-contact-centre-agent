"""Secret management.

Local/dev: secrets come from environment variables (or are generated per
process for throw-away dev use).
Prod: Azure Key Vault via managed identity (``DefaultAzureCredential``). No
secret is ever logged, put in a URL, or persisted to the checkpoint store.
"""

from __future__ import annotations

import base64
import json
import os
import secrets as _stdlib_secrets
import threading
import time
from pathlib import Path
from typing import Protocol

from .config import Settings


class SecretProvider(Protocol):
    def get(self, name: str) -> str: ...


class EnvSecretProvider:
    """Reads ``CCAGENT_SECRET_<NAME>``.

    Non-prod only: a missing secret is generated once and kept in a local
    owner-only file (``<data_dir>/.dev-secrets.json``) so that encrypted
    checkpoints stay readable across restarts. Never used in prod.
    """

    def __init__(self, allow_generate: bool, dev_file: Path | None = None) -> None:
        self._allow_generate = allow_generate
        self._dev_file = dev_file
        self._generated: dict[str, str] = {}
        self._lock = threading.Lock()
        if allow_generate and dev_file and dev_file.exists():
            self._generated = json.loads(dev_file.read_text())

    def get(self, name: str) -> str:
        env_name = f"CCAGENT_SECRET_{name.upper().replace('-', '_')}"
        value = os.getenv(env_name)
        if value:
            return value
        if not self._allow_generate:
            raise KeyError(f"Secret {name!r} not configured ({env_name})")
        with self._lock:
            if name not in self._generated and self._dev_file and self._dev_file.exists():
                self._generated = json.loads(self._dev_file.read_text())  # another local process may have created it
            if name not in self._generated:
                self._generated[name] = base64.urlsafe_b64encode(_stdlib_secrets.token_bytes(32)).decode()
                if self._dev_file:
                    self._dev_file.parent.mkdir(parents=True, exist_ok=True)
                    self._dev_file.write_text(json.dumps(self._generated))
                    os.chmod(self._dev_file, 0o600)
            return self._generated[name]


class KeyVaultSecretProvider:
    """Azure Key Vault with a short in-memory cache (supports rotation)."""

    def __init__(self, vault_url: str, cache_ttl_s: int = 300) -> None:
        from azure.identity import DefaultAzureCredential  # lazy: optional dependency
        from azure.keyvault.secrets import SecretClient

        self._client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
        self._ttl = cache_ttl_s
        self._cache: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()

    def get(self, name: str) -> str:
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(name)
            if hit and now - hit[0] < self._ttl:
                return hit[1]
        value = self._client.get_secret(name).value
        if value is None:
            raise KeyError(name)
        with self._lock:
            self._cache[name] = (now, value)
        return value


def build_secret_provider(settings: Settings) -> SecretProvider:
    vault_url = os.getenv("AZURE_KEY_VAULT_URL")
    if vault_url:
        return KeyVaultSecretProvider(vault_url)
    return EnvSecretProvider(
        allow_generate=not settings.is_prod, dev_file=Path(settings.data_dir) / ".dev-secrets.json"
    )


# Names of secrets used by the service (documented in docs/04-security-governance.md)
JWT_SIGNING_KEY = "jwt-signing-key"            # dev-mode HS256 only
DELEGATION_SIGNING_KEY = "delegation-signing-key"  # orchestrator -> MCP tool server
APPROVAL_SIGNING_KEY = "approval-signing-key"      # reviewer approval tokens
CHECKPOINT_ENCRYPTION_KEY = "checkpoint-encryption-key"  # AES-256-GCM, base64 32 bytes
