"""Service-to-service authentication (workload identity).

Every internal hop carries TWO credentials (zero trust):

1. A **service token** in ``Authorization: Bearer …`` — *which workload is calling*
   (e.g. the MCP tool service), for which audience (e.g. ``customer-service``),
   with which application permissions (e.g. ``customer.read``).
2. The end user's **delegation token** in ``X-Delegation-Token`` — *on whose behalf*,
   for which customer, with which customer authentication level and purpose.
   (Plus an ``X-Approval-Token`` for state-changing actions.)

Modes
* ``local`` (dev/test): short-lived HS256 tokens signed with a key from the secret
  provider (shared via Key Vault in a real environment).
* ``azure`` (prod): the caller gets an Entra ID token for the target API with its
  **managed identity** (``DefaultAzureCredential``); the receiving service validates
  it against the tenant JWKS and checks the app role. No shared secrets.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

import jwt

from ..secrets import SecretProvider

SERVICE_SIGNING_KEY = "service-signing-key"
_ISS = "ccagent-workload-identity"

# Application permissions granted to each workload (Entra app roles in production).
WORKLOAD_PERMISSIONS: dict[str, dict[str, list[str]]] = {
    "mcp-tool-service": {
        "customer-service": ["customer.read", "customer.cards.lock"],
        "case-service": ["cases.write", "cases.read"],
    },
    "agent-api": {
        "case-service": ["cases.read"],  # supervisor KPIs / case listing
    },
    "api-gateway": {
        "agent-api": ["api.ingress"],  # proves a request came through the gateway
    },
}


class ServiceAuthError(Exception):
    def __init__(self, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class CallerWorkload:
    name: str
    permissions: frozenset[str]


class LocalServiceTokens:
    def __init__(self, secrets: SecretProvider, caller: str) -> None:
        self._secrets = secrets
        self.caller = caller

    async def token_for(self, audience: str, ttl_s: int = 120) -> str:
        now = int(time.time())
        perms = WORKLOAD_PERMISSIONS.get(self.caller, {}).get(audience, [])
        return jwt.encode(
            {"iss": _ISS, "sub": self.caller, "aud": audience, "roles": perms, "iat": now, "exp": now + ttl_s,
             "jti": uuid.uuid4().hex},
            self._secrets.get(SERVICE_SIGNING_KEY), algorithm="HS256",
        )


class AzureServiceTokens:
    """Managed identity → Entra token for ``api://<audience>/.default``."""

    def __init__(self, caller: str) -> None:
        from azure.identity.aio import DefaultAzureCredential

        self.caller = caller
        self._cred = DefaultAzureCredential()

    async def token_for(self, audience: str, ttl_s: int = 0) -> str:
        return (await self._cred.get_token(f"api://{audience}/.default")).token


def build_service_tokens(mode: str, secrets: SecretProvider, caller: str):
    return AzureServiceTokens(caller) if mode == "azure" else LocalServiceTokens(secrets, caller)


class ServiceTokenVerifier:
    """Used by a receiving service to authenticate the calling workload."""

    def __init__(self, mode: str, secrets: SecretProvider, audience: str, tenant_id: str | None = None) -> None:
        self.mode = mode
        self.audience = audience
        self._secrets = secrets
        if mode == "azure":
            if not tenant_id:
                raise ServiceAuthError("ENTRA_TENANT_ID required for azure service auth", 500)
            self._issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
            self._jwks = jwt.PyJWKClient(f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys")

    def verify(self, authorization: str | None, required_permission: str) -> CallerWorkload:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise ServiceAuthError("missing service token")
        token = authorization.split(" ", 1)[1]
        try:
            if self.mode == "azure":
                key = self._jwks.get_signing_key_from_jwt(token).key
                claims = jwt.decode(token, key, algorithms=["RS256"], audience=f"api://{self.audience}",
                                    issuer=self._issuer)
                name = claims.get("azp") or claims.get("appid") or claims["sub"]
            else:
                claims = jwt.decode(token, self._secrets.get(SERVICE_SIGNING_KEY), algorithms=["HS256"],
                                    audience=self.audience, issuer=_ISS, options={"require": ["exp", "sub", "aud"]})
                name = claims["sub"]
        except jwt.PyJWTError as exc:
            raise ServiceAuthError(f"invalid service token: {exc.__class__.__name__}") from exc
        perms = frozenset(claims.get("roles") or [])
        if required_permission not in perms:
            raise ServiceAuthError(f"workload {name} lacks permission {required_permission}", 403)
        return CallerWorkload(name=name, permissions=perms)
