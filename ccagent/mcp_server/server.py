"""MCP tool server — the governed boundary between agents and enterprise systems.

Agents never call core banking / CRM / search directly. They call MCP tools,
and every tool:
  * requires a signed, short-lived **delegation token** (identity, roles,
    bound customer, customer auth level, purpose of use, correlation id);
  * takes the customer from the token — NEVER from LLM-supplied arguments;
  * for state-changing actions, requires an **approval token** bound to the
    run id and the exact action hash (human-in-the-loop, four-eyes);
  * is idempotent (caller-supplied idempotency key);
  * returns structured JSON and writes an audit record.

Runs in-process (tests / local) or as a separate service over Streamable HTTP
(``python -m ccagent.mcp_server``) behind API Management with mTLS.

Compatible with the MCP Python SDK v2 (``MCPServer``) and v1 (``FastMCP``).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..integrations.cases import CaseService, CaseServiceError
from ..integrations.customer import AccessContext, CustomerService, NotFound, PermanentError, StepUpRequired
from ..integrations.knowledge import docs_to_chunks
from ..persistence.audit import AuditLog
from ..resilience import TransientError
from ..security.guardrails import filter_retrieved
from ..security.tokens import InternalTokens, TokenError

try:  # MCP Python SDK v2
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # pragma: no cover - MCP SDK v1
    from mcp.server.fastmcp import FastMCP as _Server


@dataclass
class ToolServices:
    customers: CustomerService
    cases: CaseService
    retriever: object  # langchain BaseRetriever
    tokens: InternalTokens
    audit: AuditLog


def _ctx(claims: dict, run_id: str | None = None, delegation_token: str | None = None,
         approval_token: str | None = None) -> AccessContext:
    return AccessContext(
        on_behalf_of=claims["sub"],
        roles=frozenset(claims.get("roles", [])),
        session_customer_ref=claims.get("customer_ref"),
        cust_auth_level=int(claims.get("cal", 0)),
        purpose=claims["pou"],
        correlation_id=claims.get("cid", "-"),
        run_id=run_id,
        delegation_token=delegation_token,
        approval_token=approval_token,
    )


UNAVAILABLE = {"ok": False, "error": "unavailable", "retryable": True}


def _error(code: str, message: str) -> dict:
    return {"ok": False, "error": code, "message": message}


def build_mcp_server(svc: ToolServices) -> _Server:
    mcp = _Server(
        name="ccagent-enterprise-tools",
        instructions="Governed contact-centre tools. All calls require a delegation token issued by the orchestrator.",
    )

    def verify(token: str, tool: str) -> dict:
        claims = svc.tokens.verify_delegation(token, tool)
        return claims

    cust_backend = getattr(svc.customers, "name", "customer data")
    case_backend = getattr(svc.cases, "name", "case data")
    kb_backend = getattr(svc.retriever, "backend_name", "knowledge index")

    @mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(request):  # noqa: ARG001
        from starlette.responses import JSONResponse

        from .. import __version__

        return JSONResponse({"status": "ok", "service": "mcp-tool-service", "version": __version__,
                             "backends": {"customers": cust_backend, "cases": case_backend, "knowledge": kb_backend}})

    @mcp.tool(name="search_knowledge", description="Search the approved contact-centre knowledge base.")
    async def search_knowledge(query: str, delegation_token: str, top_k: int = 4) -> dict:
        try:
            claims = verify(delegation_token, "search_knowledge")
        except TokenError as e:
            return _error("unauthorized", str(e))
        docs = await svc.retriever.ainvoke(query[:500])
        chunks, dropped = filter_retrieved(docs_to_chunks(docs)[: max(1, min(top_k, 8))])
        if dropped:
            svc.audit.append("retrieval_injection_filtered", claims["sub"], None, dropped=dropped)
        return {"ok": True, "chunks": chunks, "filtered": dropped, "served_by": kb_backend}

    @mcp.tool(name="get_customer_profile",
              description="Get the minimised profile of the customer bound to this session.")
    async def get_customer_profile(delegation_token: str, run_id: str | None = None) -> dict:
        try:
            claims = verify(delegation_token, "get_customer_profile")
            profile = await svc.customers.get_profile(claims.get("customer_ref") or "",
                                                      _ctx(claims, run_id, delegation_token))
            return {"ok": True, "profile": profile, "served_by": cust_backend}
        except TransientError:
            return UNAVAILABLE | {"served_by": cust_backend}
        except TokenError as e:
            return _error("unauthorized", str(e))
        except StepUpRequired as e:
            return _error("step_up_required", str(e))
        except NotFound as e:
            return _error("not_found", str(e))
        except PermanentError as e:
            return _error("forbidden", str(e))

    @mcp.tool(name="list_recent_transactions", description="List recent transactions for the bound customer.")
    async def list_recent_transactions(delegation_token: str, limit: int = 10, run_id: str | None = None) -> dict:
        try:
            claims = verify(delegation_token, "list_recent_transactions")
            txns = await svc.customers.list_transactions(claims.get("customer_ref") or "",
                                                         _ctx(claims, run_id, delegation_token), limit)
            return {"ok": True, "transactions": txns, "served_by": cust_backend}
        except TransientError:
            return UNAVAILABLE | {"served_by": cust_backend}
        except TokenError as e:
            return _error("unauthorized", str(e))
        except StepUpRequired as e:
            return _error("step_up_required", str(e))
        except PermanentError as e:
            return _error("forbidden", str(e))

    @mcp.tool(name="create_case", description="Create a CRM case (complaint, dispute, fraud referral, follow-up).")
    async def create_case(
        delegation_token: str,
        case_type: str,
        priority: str,
        summary: str,
        idempotency_key: str,
        sla_hours: int = 48,
        run_id: str | None = None,
        details: dict | None = None,
        approval_token: str | None = None,
    ) -> dict:
        try:
            claims = verify(delegation_token, "create_case")
            if case_type == "dispute" and (details or {}).get("requires_approval"):
                action = {"type": "create_dispute", "customer_ref": claims.get("customer_ref"),
                          "txn_id": (details or {}).get("txn_id"), "amount_cad": (details or {}).get("amount_cad")}
                if not approval_token:
                    return _error("approval_required", "dispute above threshold requires reviewer approval")
                svc.tokens.verify_approval(approval_token, run_id=run_id or "", action=action)
            case = await svc.cases.create_case(
                case_type=case_type, priority=priority, summary=summary, customer_ref=claims.get("customer_ref"),
                idempotency_key=idempotency_key, actor=claims["sub"], run_id=run_id, sla_hours=sla_hours,
                details=details, delegation_token=delegation_token, approval_token=approval_token,
                correlation_id=claims.get("cid", "-"),
            )
            return {"ok": True, "served_by": case_backend,
                    "case": {k: case[k] for k in ("case_id", "case_type", "priority", "status",
                                                  "sla_due_at", "idempotent_replay")}}
        except TransientError:
            return UNAVAILABLE | {"served_by": case_backend}
        except TokenError as e:
            return _error("unauthorized", str(e))
        except CaseServiceError as e:
            code = e.code if e.code in ("approval_required", "forbidden", "unauthorized") else "forbidden"
            return _error(code, str(e))
        except ValueError as e:
            return _error("invalid_request", str(e))

    @mcp.tool(name="lock_card", description="Temporarily lock a card. Requires a reviewer approval token.")
    async def lock_card(
        delegation_token: str, card_id: str, idempotency_key: str, run_id: str, approval_token: str | None = None
    ) -> dict:
        try:
            claims = verify(delegation_token, "lock_card")
            action = {"type": "lock_card", "customer_ref": claims.get("customer_ref"), "card_id": card_id}
            if not approval_token:
                return _error("approval_required", "card lock requires reviewer approval")
            approval = svc.tokens.verify_approval(approval_token, run_id=run_id, action=action)
            if approval["sub"] == claims["sub"]:
                return _error("forbidden", "four-eyes violation: requester cannot approve own action")
            result = await svc.customers.lock_card(
                claims.get("customer_ref") or "", card_id,
                _ctx(claims, run_id, delegation_token, approval_token), idempotency_key
            )
            return {"ok": True, "result": result, "approved_by": approval["sub"], "served_by": cust_backend}
        except TransientError:
            return UNAVAILABLE | {"served_by": cust_backend}
        except TokenError as e:
            return _error("unauthorized", str(e))
        except StepUpRequired as e:
            return _error("step_up_required", str(e))
        except NotFound as e:
            return _error("not_found", str(e))
        except PermanentError as e:
            return _error("forbidden", str(e))

    return mcp
