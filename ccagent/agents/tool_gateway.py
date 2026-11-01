"""Agent-side MCP client ("tool gateway").

Responsibilities:
  * mint a per-call delegation token from the *verified* session identity
    (the LLM cannot influence identity, customer binding or purpose);
  * enforce a per-agent tool allow-list (least privilege per agent);
  * apply timeouts, bounded retries (only for idempotent/keyed calls) and a
    circuit breaker per tool;
  * emit OpenInference TOOL spans and audit records.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

from ..persistence.audit import AuditLog
from ..resilience import CircuitBreaker, TransientError, call_with_resilience
from ..security.tokens import InternalTokens
from ..telemetry import METRICS, SpanKind, span

try:  # MCP SDK v2
    from mcp.client.client import Client as _MCPClient

    _MCP_V2 = True
except ImportError:  # pragma: no cover
    _MCP_V2 = False


# Least-privilege tool allow-list per agent.
AGENT_TOOL_ALLOWLIST: dict[str, set[str]] = {
    "knowledge_agent": {"search_knowledge"},
    "account_agent": {"get_customer_profile", "list_recent_transactions", "search_knowledge"},
    "card_agent": {"get_customer_profile", "lock_card", "search_knowledge"},
    "dispute_agent": {"list_recent_transactions", "create_case", "search_knowledge"},
    "complaint_agent": {"create_case", "search_knowledge"},
    "escalation_agent": {"create_case", "get_customer_profile"},
}

SAFE_TO_RETRY = {"search_knowledge", "get_customer_profile", "list_recent_transactions"}
KEYED_TOOLS = {"create_case", "lock_card"}  # retry-safe because idempotency keys are mandatory


@dataclass(frozen=True)
class ToolSession:
    on_behalf_of: str
    roles: tuple[str, ...]
    customer_ref: str | None
    cust_auth_level: int
    correlation_id: str
    run_id: str


class ToolNotPermitted(Exception):
    pass


def parse_tool_result(result) -> dict:
    """Normalise an MCP ``CallToolResult`` (SDK v1 or v2) to a dict."""
    is_error = getattr(result, "is_error", None)
    if is_error is None:
        is_error = getattr(result, "isError", False)
    if is_error:
        text = " ".join(getattr(c, "text", "") for c in result.content)
        if "timeout" in text.lower() or "unavailable" in text.lower():
            raise TransientError(text)
        return {"ok": False, "error": "tool_error", "message": text[:300]}
    structured = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        out = structured["result"] if set(structured) == {"result"} else structured
        if out.get("error") == "unavailable":
            raise TransientError(f"backend unavailable: {out.get('served_by')}")
        return out
    for c in result.content:
        if getattr(c, "text", None):
            try:
                return json.loads(c.text)
            except json.JSONDecodeError:
                return {"ok": True, "text": c.text}
    return {"ok": False, "error": "empty_result"}


class MCPToolGateway:
    def __init__(self, server_or_url, tokens: InternalTokens, audit: AuditLog, timeout_s: float, max_retries: int):
        self._target = server_or_url  # MCPServer instance (in-process) or Streamable HTTP URL
        self.transport = "mcp-http" if isinstance(server_or_url, str) else "mcp-in-process"
        self._tokens = tokens
        self._audit = audit
        self._timeout_s = timeout_s
        self._max_retries = max_retries
        self._breakers: dict[str, CircuitBreaker] = {}

    async def _raw_call(self, tool: str, arguments: dict) -> dict:
        if _MCP_V2:
            async with _MCPClient(self._target, read_timeout_seconds=self._timeout_s) as client:
                result = await client.call_tool(tool, arguments)
        else:  # pragma: no cover
            from mcp.shared.memory import create_connected_server_and_client_session

            async with create_connected_server_and_client_session(self._target._mcp_server) as client:
                result = await client.call_tool(tool, arguments)
        return parse_tool_result(result)

    async def call(self, agent: str, tool: str, session: ToolSession, purpose: str, **arguments) -> dict:
        if tool not in AGENT_TOOL_ALLOWLIST.get(agent, set()):
            self._audit.append("tool_denied", session.on_behalf_of, session.run_id, agent=agent, tool=tool)
            raise ToolNotPermitted(f"{agent} is not permitted to call {tool}")
        if tool in KEYED_TOOLS and not arguments.get("idempotency_key"):
            raise ValueError(f"{tool} requires an idempotency_key")

        token = self._tokens.mint_delegation(
            on_behalf_of=session.on_behalf_of,
            roles=list(session.roles),
            customer_ref=session.customer_ref,
            cust_auth_level=session.cust_auth_level,
            purpose=purpose,
            correlation_id=session.correlation_id,
            tool=tool,
        )
        args = {**arguments, "delegation_token": token}
        if tool not in ("search_knowledge",):
            args.setdefault("run_id", session.run_id)
        breaker = self._breakers.setdefault(tool, CircuitBreaker(tool))
        retries = self._max_retries if (tool in SAFE_TO_RETRY or tool in KEYED_TOOLS) else 0
        started = time.perf_counter()
        with span(f"tool.{tool}", SpanKind.TOOL, **{"tool.name": tool, "agent.name": agent, "purpose": purpose,
                                                     "run_id": session.run_id}) as s:
            result = await call_with_resilience(
                lambda: self._raw_call(tool, args), timeout_s=self._timeout_s, max_retries=retries, breaker=breaker
            )
            s.set_attribute("tool.ok", bool(result.get("ok")))
        METRICS.inc("tool_calls_total", tool=tool, ok=bool(result.get("ok")))
        METRICS.observe(f"tool_latency_s.{tool}", time.perf_counter() - started)
        self._audit.append(
            "tool_call", session.on_behalf_of, session.run_id, agent=agent, tool=tool, purpose=purpose,
            ok=bool(result.get("ok")), error=result.get("error"), backend=result.get("served_by"),
            transport=self.transport,
        )
        return result
