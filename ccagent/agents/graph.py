"""Agent orchestrator — a LangGraph supervisor with specialist agents.

    START
      │
  input_guard ──(blocked)──────────────────────────────┐
      │                                                 │
  load_memory (long-term store)                         │
      │                                                 │
  orchestrator (intent, sentiment, vulnerability, routing)
      │
      ├─ knowledge_agent ─────────────────────────┐
      ├─ account_agent* ──────────────────────────┤
      ├─ card_agent* ── human_review ─ execute_action ┤      * requires customer
      ├─ dispute_agent* ─(≥ threshold)─ human_review ┤        authentication; otherwise
      ├─ complaint_agent ─────────────────────────┤        → step_up
      ├─ escalation_agent (fraud / vulnerable / human / low confidence)
      └─ step_up ─────────────────────────────────┤
                                                   ▼
                                     responder (grounded draft + output guard / fallback)
                                                   │
                                     finalize (wrap-up summary, disposition, QA,
                                               long-term memory, audit) → END

Every specialist reaches enterprise systems only through the MCP tool gateway
with its own least-privilege tool allow-list.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, trim_messages
from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime
from langgraph.types import interrupt

from ..config import Settings
from ..llm.prompts import CLASSIFY_SYSTEM, DRAFT_SYSTEM, PROMPT_VERSION, SUMMARY_SYSTEM
from ..llm.structured import CallSummary, DraftAnswer, IntentResult, OutputValidationError, invoke_structured
from ..ops.qa import score_interaction
from ..ops.routing import route_for
from ..persistence.audit import AuditLog
from ..resilience import CircuitOpenError
from ..security.guardrails import screen_input, spotlight, validate_output
from ..security.pii import redact
from ..security.tokens import action_hash
from ..telemetry import METRICS, SpanKind, span
from .state import CallState
from .tool_gateway import MCPToolGateway, ToolSession

AUTH_REQUIRED_INTENTS = {"account_inquiry", "card_lost_stolen", "transaction_dispute"}
ESCALATE_INTENTS = {"fraud_report", "human_agent_request", "vulnerable_support"}

SAFE_FALLBACK = (
    "I'm sorry — I want to make sure you get the right help, so I'm connecting you with a colleague now. "
    "Please stay on the line."
)
BLOCKED_RESPONSE = (
    "I'm sorry, I can't help with that request. I can help with card, account, dispute or complaint questions, "
    "or connect you with a colleague."
)


@dataclass
class GraphDeps:
    settings: Settings
    model: object
    gateway: MCPToolGateway
    audit: AuditLog


def _session(state: CallState) -> ToolSession:
    p = state["principal"]
    return ToolSession(
        on_behalf_of=p["sub"],
        roles=tuple(p["roles"]),
        customer_ref=state.get("customer_ref"),
        cust_auth_level=int(state.get("cust_auth_level", 0)),
        correlation_id=state.get("correlation_id", "-"),
        run_id=state["run_id"],
    )


def _idem(state: CallState, action: dict) -> str:
    return hashlib.sha256(f"{state['thread_id']}|{action_hash(action)}".encode()).hexdigest()[:40]


def build_graph(deps: GraphDeps):
    s = deps.settings
    gw = deps.gateway

    # ------------------------------------------------------------------ guard
    async def input_guard(state: CallState) -> dict:
        with span("guard.input", SpanKind.GUARDRAIL) as sp:
            text, kinds = redact(state["utterance"])
            kinds = sorted(set(kinds) | set(state.get("pii_found") or []))
            decision = screen_input(text, s.max_message_chars)
            sp.set_attribute("guard.allowed", decision.allowed)
        update: dict = {
            "utterance": text,
            "pii_found": kinds,
            "guard": {"allowed": decision.allowed, "reasons": decision.reasons, "risk": decision.risk_score},
            "messages": [HumanMessage(content=text)],
            "prompt_version": PROMPT_VERSION,
            "trace": ["input_guard"],
        }
        if kinds:
            deps.audit.append("pii_redacted_inbound", state["principal"]["sub"], state["run_id"], kinds=kinds)
        if not decision.allowed:
            METRICS.inc("guardrail_blocks_total", stage="input")
            deps.audit.append("guardrail_block", state["principal"]["sub"], state["run_id"],
                              stage="input", reasons=decision.reasons, risk=decision.risk_score)
            update |= {"final_response": BLOCKED_RESPONSE, "intent": "blocked", "resolved": False}
        return update

    def after_guard(state: CallState) -> str:
        return "load_memory" if state["guard"].get("allowed") else "finalize"

    # ----------------------------------------------------------- long-term memory
    async def load_memory(state: CallState, runtime: Runtime) -> dict:
        ctx: list[str] = []
        ref = state.get("customer_ref")
        if ref and runtime.store is not None and state.get("cust_auth_level", 0) >= 1:
            items = await runtime.store.asearch(("customers", ref, "interactions"), limit=3)
            ctx = [f"{i.value.get('date')}: {i.value.get('summary')}" for i in items]
            prefs = await runtime.store.aget(("customers", ref, "preferences"), "profile")
            if prefs:
                ctx.append(f"preferences: {prefs.value}")
        return {"memory_context": ctx, "trace": ["load_memory"]}

    # ------------------------------------------------------------ orchestrator
    async def orchestrator(state: CallState) -> dict:
        history = trim_messages(
            state.get("messages", []), max_tokens=s.short_term_max_messages, token_counter=len,
            strategy="last", start_on="human", include_system=False,
        )
        prior = "\n".join(f"{m.type}: {m.content}" for m in history[:-1])[-1500:]
        memory = "\n".join(state.get("memory_context", []))
        user = f"PRIOR_TURNS:\n{prior or 'none'}\nCLIENT_HISTORY:\n{memory or 'none'}\nUTTERANCE: {state['utterance']}"
        try:
            with span("agent.orchestrator", SpanKind.AGENT, **{"agent.name": "orchestrator"}):
                res = await invoke_structured(
                    deps.model, [SystemMessage(content=CLASSIFY_SYSTEM), HumanMessage(content=user)],
                    IntentResult, name="classify_intent", timeout_s=s.llm_timeout_s,
                )
            intent, conf = res.intent, res.confidence
            sentiment, vuln, entities = res.sentiment, res.vulnerability, res.entities
        except (OutputValidationError, TimeoutError, CircuitOpenError):
            intent, conf, sentiment, vuln, entities = "general", 0.0, "neutral", False, {}
        route = route_for(intent, sentiment=sentiment, vulnerability=vuln)
        METRICS.inc("intents_total", intent=intent)
        return {
            "intent": intent, "confidence": conf, "sentiment": sentiment, "vulnerability": vuln,
            "entities": entities, "route": route.__dict__, "trace": ["orchestrator"],
        }

    def route_after_orchestrator(state: CallState) -> str:
        intent = state["intent"]
        if intent in ESCALATE_INTENTS or state.get("vulnerability"):
            return "escalation_agent"
        if state["confidence"] < s.intent_confidence_floor:
            return "escalation_agent"
        if intent in AUTH_REQUIRED_INTENTS and int(state.get("cust_auth_level", 0)) < 1:
            return "step_up"
        return {
            "account_inquiry": "account_agent",
            "card_lost_stolen": "card_agent",
            "transaction_dispute": "dispute_agent",
            "complaint": "complaint_agent",
        }.get(intent, "knowledge_agent")

    # --------------------------------------------------------- specialist agents
    async def _kb(agent: str, state: CallState, query: str) -> list[dict]:
        res = await gw.call(agent, "search_knowledge", _session(state), purpose="servicing",
                            query=query, top_k=s.retrieval_top_k)
        return res.get("chunks", []) if res.get("ok") else []

    async def knowledge_agent(state: CallState) -> dict:
        with span("agent.knowledge", SpanKind.AGENT, **{"agent.name": "knowledge_agent"}):
            chunks = await _kb("knowledge_agent", state, state["utterance"])
        if not chunks:
            return {"escalation": {"reason": "no_grounding", **state["route"]}, "trace": ["knowledge_agent"]}
        return {"retrieved": chunks, "resolved": True, "trace": ["knowledge_agent"]}

    async def step_up(state: CallState) -> dict:
        deps.audit.append("step_up_requested", state["principal"]["sub"], state["run_id"], intent=state["intent"])
        return {
            "step_up_required": True,
            "final_response": "For your security, I need to verify your identity before I can help with that. "
                              "I'll take you through a quick verification step now.",
            "trace": ["step_up"],
        }

    async def account_agent(state: CallState) -> dict:
        sess = _session(state)
        with span("agent.account", SpanKind.AGENT, **{"agent.name": "account_agent"}):
            prof = await gw.call("account_agent", "get_customer_profile", sess, purpose="servicing")
            txns = await gw.call("account_agent", "list_recent_transactions", sess, purpose="servicing", limit=3)
        if not (prof.get("ok") and txns.get("ok")):
            if "step_up_required" in (prof.get("error"), txns.get("error")):
                return {"step_up_required": True, "trace": ["account_agent"]}
            return {"escalation": {"reason": "data_unavailable", **state["route"]}, "trace": ["account_agent"]}
        facts = [f"Your {a['nickname']} balance is ${a['balance_cad']:,.2f}" for a in prof["profile"].get("accounts", [])]
        facts += [f"Recent: {t['date']} {t['merchant']} ${abs(t['amount_cad']):,.2f}" for t in txns["transactions"]]
        return {"facts": facts, "account_data_disclosed": True, "resolved": True, "trace": ["account_agent"]}

    async def card_agent(state: CallState) -> dict:
        sess = _session(state)
        with span("agent.card", SpanKind.AGENT, **{"agent.name": "card_agent"}):
            prof = await gw.call("card_agent", "get_customer_profile", sess, purpose="card_servicing")
            chunks = await _kb("card_agent", state, "lost stolen credit card lock replacement")
        if not prof.get("ok"):
            return {"escalation": {"reason": prof.get("error", "data_unavailable"), **state["route"]},
                    "retrieved": chunks, "trace": ["card_agent"]}
        cards = [c for c in prof["profile"].get("cards", []) if c["status"] == "active"]
        last4 = state.get("entities", {}).get("card_last4")
        if last4:
            cards = [c for c in cards if c["last4"] == last4]
        if not cards:
            return {"facts": ["I couldn't find an active card matching that description on your profile"],
                    "escalation": {"reason": "card_not_found", **state["route"]}, "retrieved": chunks,
                    "trace": ["card_agent"]}
        if len(cards) > 1:
            options = ", ".join(f"the {c['product']} ending in {c['last4']}" for c in cards)
            return {"final_response": f"I can help lock your card. Which card is it: {options}?",
                    "trace": ["card_agent"]}
        card = cards[0]
        action = {"type": "lock_card", "customer_ref": state["customer_ref"], "card_id": card["card_id"]}
        return {
            "proposed_action": action | {"display": f"Lock {card['product']} ending in {card['last4']}",
                                         "risk_reason": "card state change requested via assistant"},
            "retrieved": chunks,
            "trace": ["card_agent"],
        }

    async def dispute_agent(state: CallState) -> dict:
        sess = _session(state)
        with span("agent.dispute", SpanKind.AGENT, **{"agent.name": "dispute_agent"}):
            txns = await gw.call("dispute_agent", "list_recent_transactions", sess, purpose="dispute", limit=10)
            chunks = await _kb("dispute_agent", state, "dispute credit card transaction")
        if not txns.get("ok"):
            return {"escalation": {"reason": txns.get("error", "data_unavailable"), **state["route"]},
                    "retrieved": chunks, "trace": ["dispute_agent"]}
        ents = state.get("entities", {})
        items = [t for t in txns["transactions"] if t["amount_cad"] < 0]
        match = None
        if ents.get("txn_id"):
            match = next((t for t in items if t["txn_id"] == ents["txn_id"]), None)
        elif ents.get("amount_cad"):
            match = next((t for t in items if abs(abs(t["amount_cad"]) - ents["amount_cad"]) < 0.01), None)
        if not match:
            listing = "; ".join(f"{t['date']} {t['merchant']} ${abs(t['amount_cad']):,.2f}" for t in items[:3])
            return {"final_response": f"I can help with a dispute. Which transaction is it? Recent charges: {listing}.",
                    "account_data_disclosed": True, "retrieved": chunks, "trace": ["dispute_agent"]}
        amount = abs(match["amount_cad"])
        action = {"type": "create_dispute", "customer_ref": state["customer_ref"],
                  "txn_id": match["txn_id"], "amount_cad": amount}
        needs_review = amount >= s.dispute_review_threshold_cad
        return {
            "proposed_action": action | {"display": f"Dispute {match['merchant']} ${amount:,.2f}",
                                         "requires_review": needs_review,
                                         "risk_reason": f"dispute amount ${amount:,.2f} vs threshold "
                                                        f"${s.dispute_review_threshold_cad:,.2f}"},
            "retrieved": chunks,
            "account_data_disclosed": True,
            "trace": ["dispute_agent"],
        }

    def route_after_action_agent(state: CallState) -> str:
        if state.get("final_response") or state.get("escalation") or state.get("step_up_required"):
            return "responder"
        action = state.get("proposed_action")
        if not action:
            return "responder"
        if action["type"] == "lock_card" or action.get("requires_review"):
            return "human_review"
        return "execute_action"

    async def complaint_agent(state: CallState) -> dict:
        sess = _session(state)
        with span("agent.complaint", SpanKind.AGENT, **{"agent.name": "complaint_agent"}):
            chunks = await _kb("complaint_agent", state, "complaint handling procedure escalation")
            idem = hashlib.sha256(f"{state['thread_id']}|complaint|{state['utterance']}".encode()).hexdigest()[:40]
            res = await gw.call("complaint_agent", "create_case", sess, purpose="complaint",
                                case_type="complaint", priority=state["route"]["priority"],
                                summary=f"Client complaint (redacted): {state['utterance'][:400]}",
                                idempotency_key=idem, sla_hours=s.complaint_ack_sla_hours)
        if not res.get("ok"):
            return {"escalation": {"reason": "case_creation_failed", **state["route"]}, "retrieved": chunks,
                    "trace": ["complaint_agent"]}
        case = res["case"]
        return {
            "case_id": case["case_id"],
            "facts": [f"I'm sorry for your experience. I've recorded your complaint under reference {case['case_id']}",
                      f"Our Client Care team will follow up within {s.complaint_ack_sla_hours} hours"],
            "retrieved": chunks,
            "resolved": True,
            "trace": ["complaint_agent"],
        }

    async def escalation_agent(state: CallState) -> dict:
        sess = _session(state)
        route = state["route"]
        reason = ("low_confidence" if state["confidence"] < s.intent_confidence_floor
                  and state["intent"] not in ESCALATE_INTENTS else state["intent"])
        facts: list[str] = []
        case_id = None
        with span("agent.escalation", SpanKind.AGENT, **{"agent.name": "escalation_agent", "reason": reason}):
            if state["intent"] == "fraud_report":
                idem = hashlib.sha256(f"{state['thread_id']}|fraud".encode()).hexdigest()[:40]
                res = await gw.call("escalation_agent", "create_case", sess, purpose="fraud_referral",
                                    case_type="fraud_referral", priority="P1",
                                    summary=f"Suspected fraud reported (redacted): {state['utterance'][:400]}",
                                    idempotency_key=idem, sla_hours=route["case_sla_hours"])
                if res.get("ok"):
                    case_id = res["case"]["case_id"]
                facts.append("I'm transferring you to our fraud team right away as a priority")
                facts.append("We will never ask for your password, one-time passcode or full card number")
            elif state["intent"] == "vulnerable_support" or state.get("vulnerability"):
                facts.append("I'm so sorry to hear that. I'm connecting you with a specialist colleague who can "
                             "take the time to help")
            else:
                facts.append("I'm connecting you with a colleague who can help")
        packet = {
            "queue": route["queue"], "skill": route["skill"], "priority": route["priority"],
            "answer_sla_s": route["answer_sla_s"], "reason": reason, "intent": state["intent"],
            "sentiment": state.get("sentiment"), "vulnerability": state.get("vulnerability"),
            "case_id": case_id, "context": state["utterance"][:300],
        }
        METRICS.inc("escalations_total", queue=route["queue"], reason=reason)
        return {"escalation": packet, "facts": facts, "case_id": case_id, "trace": ["escalation_agent"]}

    # ------------------------------------------------------ human in the loop
    async def human_review(state: CallState) -> dict:
        action = {k: v for k, v in state["proposed_action"].items()
                  if k not in ("display", "risk_reason", "requires_review")}
        decision = interrupt({
            "kind": "approval_required",
            "run_id": state["run_id"],
            "action": action,
            "action_hash": action_hash(action),
            "display": state["proposed_action"].get("display"),
            "risk_reason": state["proposed_action"].get("risk_reason"),
            "requested_by": state["principal"]["sub"],
            "intent": state["intent"],
        })
        # --- resumed: the API has already authenticated/authorised the reviewer;
        # re-check four-eyes and binding defensively inside the graph.
        reviewer = decision.get("reviewer")
        if reviewer == state["principal"]["sub"]:
            raise PermissionError("four-eyes violation")
        if decision.get("action_hash") != action_hash(action):
            raise PermissionError("review does not match pending action")
        deps.audit.append(f"review_{decision['decision']}", reviewer, state["run_id"],
                          action=action, comment=decision.get("comment", "")[:500])
        if decision["decision"] != "approve":
            return {
                "review": {"decision": "reject", "reviewer": reviewer},
                "facts": ["I wasn't able to complete that request here, so I'm connecting you with a colleague"],
                "escalation": {"reason": "review_rejected", **state["route"]},
                "trace": ["human_review"],
            }
        return {"review": {"decision": "approve", "reviewer": reviewer,
                           "approval_token": decision["approval_token"]}, "trace": ["human_review"]}

    def route_after_review(state: CallState) -> str:
        return "execute_action" if state["review"]["decision"] == "approve" else "responder"

    async def execute_action(state: CallState) -> dict:
        sess = _session(state)
        pa = state["proposed_action"]
        action = {k: v for k, v in pa.items() if k not in ("display", "risk_reason", "requires_review")}
        approval = (state.get("review") or {}).get("approval_token")
        idem = _idem(state, action)
        with span("agent.execute_action", SpanKind.AGENT, **{"action.type": action["type"]}):
            if action["type"] == "lock_card":
                res = await gw.call("card_agent", "lock_card", sess, purpose="card_servicing",
                                    card_id=action["card_id"], idempotency_key=idem, approval_token=approval)
                if res.get("ok"):
                    facts = [f"{pa['display'].replace('Lock', 'Your')} is now locked, so no new purchases can be made",
                             f"Your confirmation number is {res['result']['confirmation']}",
                             "A replacement card is normally mailed within 5 to 7 business days"]
                    return {"action_result": res["result"], "facts": facts, "resolved": True,
                            "trace": ["execute_action"]}
            else:  # create_dispute
                res = await gw.call("dispute_agent", "create_case", sess, purpose="dispute",
                                    case_type="dispute", priority=state["route"]["priority"],
                                    summary=f"Dispute {action['txn_id']} amount ${action['amount_cad']:,.2f}",
                                    idempotency_key=idem, sla_hours=state["route"]["case_sla_hours"],
                                    details={"txn_id": action["txn_id"], "amount_cad": action["amount_cad"],
                                             "requires_approval": bool(pa.get("requires_review"))},
                                    approval_token=approval)
                if res.get("ok"):
                    case = res["case"]
                    facts = [f"I've opened a dispute for {pa['display'].removeprefix('Dispute ')} under "
                             f"reference {case['case_id']}",
                             "Disputes are usually reviewed within 30 to 90 days and the outcome is not "
                             "certain until the review is complete"]
                    return {"action_result": case, "case_id": case["case_id"], "facts": facts, "resolved": True,
                            "trace": ["execute_action"]}
        return {"facts": ["I wasn't able to complete that request, so I'm connecting you with a colleague"],
                "escalation": {"reason": f"action_failed:{res.get('error')}", **state["route"]},
                "action_result": res, "trace": ["execute_action"]}

    # ------------------------------------------------------------- responder
    async def responder(state: CallState) -> dict:
        if state.get("final_response"):
            text = state["final_response"]
            return {"messages": [AIMessage(content=text)], "trace": ["responder"]}
        if state.get("step_up_required"):
            text = ("For your security, I need to verify your identity before I can help with that. "
                    "I'll take you through a quick verification step now.")
            return {"final_response": text, "messages": [AIMessage(content=text)], "trace": ["responder"]}

        chunks = state.get("retrieved", [])
        facts = state.get("facts", [])
        user = (f"QUESTION: {state['utterance']}\nFACTS:\n" + ("\n".join(f"- {f}" for f in facts) or "none")
                + "\nDOCUMENTS:\n" + (spotlight(chunks) if chunks else "none"))
        fallback = False
        violations: list[str] = []
        citations: list[str] = []
        nba: list[str] = []
        try:
            with span("agent.responder", SpanKind.AGENT, **{"agent.name": "responder"}):
                draft = await invoke_structured(
                    deps.model, [SystemMessage(content=DRAFT_SYSTEM), HumanMessage(content=user)],
                    DraftAnswer, name="draft_answer", timeout_s=s.llm_timeout_s,
                )
            text, citations, nba = draft.answer, draft.citations, draft.next_best_actions
            requires_citation = state["intent"] == "product_question" and not facts
            with span("guard.output", SpanKind.GUARDRAIL):
                check = validate_output(text, citations, {c["doc_id"] for c in chunks}, requires_citation)
            if not check.ok:
                violations = check.violations
                METRICS.inc("guardrail_blocks_total", stage="output")
                deps.audit.append("guardrail_block", state["principal"]["sub"], state["run_id"],
                                  stage="output", reasons=violations)
                text, fallback = SAFE_FALLBACK, True
        except (OutputValidationError, TimeoutError, CircuitOpenError) as exc:
            deps.audit.append("llm_fallback", state["principal"]["sub"], state["run_id"], error=type(exc).__name__)
            text, fallback = SAFE_FALLBACK, True

        if not fallback and (state.get("sentiment") == "negative" or state.get("vulnerability")):
            if not any(w in text.lower() for w in ("sorry", "understand", "apologi")):
                text = "I'm sorry for the trouble, and I understand how frustrating this is. " + text
        update = {
            "final_response": text, "citations": citations, "next_best_actions": nba,
            "output_violations": violations, "fallback": fallback,
            "messages": [AIMessage(content=text)], "trace": ["responder"],
        }
        if fallback and not state.get("escalation"):
            update["escalation"] = {"reason": "fallback", **state.get("route", route_for("general").__dict__)}
            METRICS.inc("fallbacks_total")
        return update

    # -------------------------------------------------------------- finalize
    async def finalize(state: CallState, runtime: Runtime) -> dict:
        outcome = ("escalated to " + state["escalation"]["queue"] if state.get("escalation") and
                   state["escalation"].get("queue") else
                   "blocked by guardrail" if state.get("intent") == "blocked" else
                   "identity verification required" if state.get("step_up_required") else
                   "resolved" if state.get("resolved") else "information provided")
        try:
            res = await invoke_structured(
                deps.model,
                [SystemMessage(content=SUMMARY_SYSTEM),
                 HumanMessage(content=f"INTENT: {state.get('intent')}\nOUTCOME: {outcome}\n"
                                      f"CASE: {state.get('case_id') or 'none'}")],
                CallSummary, name="summarize", timeout_s=s.llm_timeout_s,
            )
            summary, disposition = redact(res.summary)[0], res.disposition_code
        except Exception:
            summary, disposition = f"Interaction about {state.get('intent')}: {outcome}.", "GENERAL"

        final = {**state, "summary": summary}
        qa = score_interaction(final)
        ref = state.get("customer_ref")
        if ref and runtime.store is not None and state.get("cust_auth_level", 0) >= 1 and state.get("intent") != "blocked":
            await runtime.store.aput(
                ("customers", ref, "interactions"), state["run_id"],
                {"date": time.strftime("%Y-%m-%d"), "summary": summary, "intent": state.get("intent"),
                 "disposition": disposition, "case_id": state.get("case_id")},
            )
            deps.audit.append("memory_written", state["principal"]["sub"], state["run_id"],
                              namespace="interactions", customer_ref=ref)
        deps.audit.append("interaction_completed", state["principal"]["sub"], state["run_id"],
                          intent=state.get("intent"), disposition=disposition, qa_score=qa["score"],
                          escalated=bool(state.get("escalation")), prompt_version=PROMPT_VERSION)
        return {"summary": summary, "disposition": disposition, "qa": qa, "trace": ["finalize"]}

    # ---------------------------------------------------------------- wiring
    g = StateGraph(CallState)
    for name, fn in [
        ("input_guard", input_guard), ("load_memory", load_memory), ("orchestrator", orchestrator),
        ("knowledge_agent", knowledge_agent), ("account_agent", account_agent), ("card_agent", card_agent),
        ("dispute_agent", dispute_agent), ("complaint_agent", complaint_agent),
        ("escalation_agent", escalation_agent), ("step_up", step_up), ("human_review", human_review),
        ("execute_action", execute_action), ("responder", responder), ("finalize", finalize),
    ]:
        g.add_node(name, fn)

    g.add_edge(START, "input_guard")
    g.add_conditional_edges("input_guard", after_guard, ["load_memory", "finalize"])
    g.add_edge("load_memory", "orchestrator")
    g.add_conditional_edges(
        "orchestrator", route_after_orchestrator,
        ["knowledge_agent", "account_agent", "card_agent", "dispute_agent", "complaint_agent",
         "escalation_agent", "step_up"],
    )
    for n in ("knowledge_agent", "account_agent", "complaint_agent", "escalation_agent", "step_up"):
        g.add_edge(n, "responder")
    for n in ("card_agent", "dispute_agent"):
        g.add_conditional_edges(n, route_after_action_agent, ["human_review", "execute_action", "responder"])
    g.add_conditional_edges("human_review", route_after_review, ["execute_action", "responder"])
    g.add_edge("execute_action", "responder")
    g.add_edge("responder", "finalize")
    g.add_edge("finalize", END)
    return g
