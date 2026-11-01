"""Identity & authorization.

* ``entra`` mode (prod): validates Microsoft Entra ID access tokens (RS256) via
  the tenant JWKS — issuer, audience, expiry and signature are enforced. App
  roles come from the ``roles`` claim (assigned through Entra app roles / PIM).
* ``dev`` mode (local/test only): HS256 tokens minted by ``scripts/issue_dev_token.py``.

Customer authentication level (``cust_auth_level``) is asserted by the channel
(IVR / CCaaS) after it authenticates the caller, and is carried in the token
issued to the session — the LLM never decides it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum

import jwt

from ..config import Settings
from ..secrets import JWT_SIGNING_KEY, SecretProvider


class Role:
    AGENT = "contact_centre_agent"      # human agent using agent-assist
    CHANNEL = "channel_service"         # IVR / chat channel service principal
    REVIEWER = "reviewer"               # servicing/fraud approver (HITL)
    SUPERVISOR = "supervisor"           # team lead: KPIs, queues, QA
    AUDITOR = "auditor"                 # 2nd/3rd line: audit trail read-only

    ALL = {AGENT, CHANNEL, REVIEWER, SUPERVISOR, AUDITOR}


class CustomerAuthLevel(IntEnum):
    NONE = 0         # anonymous caller
    KBA = 1          # knowledge-based / telephone PIN
    STRONG = 2       # OTP / app push / voice biometrics


@dataclass(frozen=True)
class Principal:
    sub: str
    roles: frozenset[str]
    name: str = ""
    tenant: str = ""
    channel: str = "agent_desktop"
    customer_ref: str | None = None
    cust_auth_level: int = 0
    claims: dict = field(default_factory=dict, compare=False, repr=False)

    def has_any(self, *roles: str) -> bool:
        return bool(self.roles.intersection(roles))


class AuthError(Exception):
    def __init__(self, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.status = status


def _principal_from_claims(claims: dict) -> Principal:
    roles = claims.get("roles") or []
    if isinstance(roles, str):
        roles = [roles]
    unknown = set(roles) - Role.ALL
    roles = [r for r in roles if r in Role.ALL]
    if not roles:
        raise AuthError("token has no recognised application role", status=403)
    return Principal(
        sub=str(claims.get("oid") or claims["sub"]),
        roles=frozenset(roles),
        name=claims.get("name", ""),
        tenant=claims.get("tid", ""),
        channel=claims.get("channel", "agent_desktop"),
        customer_ref=claims.get("customer_ref"),
        cust_auth_level=int(claims.get("cust_auth_level", 0)),
        claims={k: v for k, v in claims.items() if k not in {"customer_ref"}} | {"ignored_roles": sorted(unknown)},
    )


class DevTokenValidator:
    algorithm = "HS256"

    def __init__(self, settings: Settings, secrets: SecretProvider) -> None:
        if settings.is_prod:
            raise AuthError("dev token validator is disabled in prod", status=500)
        self._settings = settings
        self._secrets = secrets

    def mint(self, sub: str, roles: list[str], ttl_s: int = 3600, **extra) -> str:
        now = int(time.time())
        claims = {
            "sub": sub,
            "roles": roles,
            "iss": self._settings.dev_issuer,
            "aud": self._settings.dev_audience,
            "iat": now,
            "nbf": now,
            "exp": now + ttl_s,
            **extra,
        }
        return jwt.encode(claims, self._secrets.get(JWT_SIGNING_KEY), algorithm=self.algorithm)

    def validate(self, token: str) -> Principal:
        try:
            claims = jwt.decode(
                token,
                self._secrets.get(JWT_SIGNING_KEY),
                algorithms=[self.algorithm],
                audience=self._settings.dev_audience,
                issuer=self._settings.dev_issuer,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
                leeway=30,
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid token: {exc.__class__.__name__}") from exc
        return _principal_from_claims(claims)


class EntraTokenValidator:
    """Validates Entra ID v2 access tokens using the tenant's signing keys."""

    def __init__(self, settings: Settings) -> None:
        if not (settings.entra_tenant_id and settings.entra_audience):
            raise AuthError("ENTRA_TENANT_ID and ENTRA_AUDIENCE are required", status=500)
        tid = settings.entra_tenant_id
        self._issuer = f"https://login.microsoftonline.com/{tid}/v2.0"
        self._audience = settings.entra_audience
        self._jwks = jwt.PyJWKClient(
            f"https://login.microsoftonline.com/{tid}/discovery/v2.0/keys", cache_keys=True, lifespan=3600
        )

    def validate(self, token: str) -> Principal:
        try:
            key = self._jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "aud", "iss"]},
                leeway=60,
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid token: {exc.__class__.__name__}") from exc
        return _principal_from_claims(claims)


def build_validator(settings: Settings, secrets: SecretProvider):
    if settings.auth_mode == "entra":
        return EntraTokenValidator(settings)
    return DevTokenValidator(settings, secrets)
