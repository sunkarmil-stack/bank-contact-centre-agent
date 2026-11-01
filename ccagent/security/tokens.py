"""Short-lived, purpose-bound internal tokens.

* Delegation token: minted by the orchestrator for each tool call. Carries the
  end-user identity (on-behalf-of), the customer the session is bound to, the
  customer auth level, the declared purpose of use and the correlation id. The
  MCP tool server verifies it — so a prompt-injected LLM cannot widen scope or
  switch customers by changing tool arguments.

* Approval token: minted only by the review endpoint after an authorised,
  four-eyes-compliant reviewer approves a specific action. It is bound to the
  run id and the SHA-256 hash of the exact action payload.

Production: replace HS256 with keys held in Key Vault / Managed HSM (or use
Entra OBO tokens + APIM validate-jwt for the delegation hop).
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid

import jwt

from ..secrets import APPROVAL_SIGNING_KEY, DELEGATION_SIGNING_KEY, SecretProvider

_ISS = "ccagent-orchestrator"


class TokenError(Exception):
    pass


def action_hash(action: dict) -> str:
    canonical = json.dumps(action, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class InternalTokens:
    def __init__(self, secrets: SecretProvider) -> None:
        self._secrets = secrets

    # -- delegation -------------------------------------------------------
    def mint_delegation(
        self,
        *,
        on_behalf_of: str,
        roles: list[str],
        customer_ref: str | None,
        cust_auth_level: int,
        purpose: str,
        correlation_id: str,
        tool: str,
        ttl_s: int = 60,
    ) -> str:
        now = int(time.time())
        return jwt.encode(
            {
                "iss": _ISS,
                "aud": "ccagent-mcp-tools",
                "sub": on_behalf_of,
                "roles": roles,
                "customer_ref": customer_ref,
                "cal": cust_auth_level,
                "pou": purpose,
                "cid": correlation_id,
                "tool": tool,
                "iat": now,
                "exp": now + ttl_s,
                "jti": uuid.uuid4().hex,
            },
            self._secrets.get(DELEGATION_SIGNING_KEY),
            algorithm="HS256",
        )

    def verify_delegation(self, token: str, tool: str) -> dict:
        try:
            claims = jwt.decode(
                token,
                self._secrets.get(DELEGATION_SIGNING_KEY),
                algorithms=["HS256"],
                audience="ccagent-mcp-tools",
                issuer=_ISS,
                options={"require": ["exp", "sub", "tool", "pou"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenError(f"delegation token rejected: {exc.__class__.__name__}") from exc
        if claims["tool"] != tool:
            raise TokenError("delegation token not issued for this tool")
        return claims

    # -- approval ---------------------------------------------------------
    def mint_approval(self, *, run_id: str, action: dict, reviewer: str, ttl_s: int = 300) -> str:
        now = int(time.time())
        return jwt.encode(
            {
                "iss": "ccagent-review",
                "aud": "ccagent-mcp-tools",
                "sub": reviewer,
                "run_id": run_id,
                "ah": action_hash(action),
                "iat": now,
                "exp": now + ttl_s,
            },
            self._secrets.get(APPROVAL_SIGNING_KEY),
            algorithm="HS256",
        )

    def verify_approval(self, token: str, *, run_id: str, action: dict) -> dict:
        try:
            claims = jwt.decode(
                token,
                self._secrets.get(APPROVAL_SIGNING_KEY),
                algorithms=["HS256"],
                audience="ccagent-mcp-tools",
                issuer="ccagent-review",
            )
        except jwt.PyJWTError as exc:
            raise TokenError(f"approval token rejected: {exc.__class__.__name__}") from exc
        if claims["run_id"] != run_id or claims["ah"] != action_hash(action):
            raise TokenError("approval token does not match this run/action")
        return claims
