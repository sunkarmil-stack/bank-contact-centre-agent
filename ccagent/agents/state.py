"""Graph state (short-term memory). Persisted — encrypted — by the checkpointer
after every node, so a run can pause for human review and resume on any
worker, even after a restart. Only PII-redacted text is ever placed in state.
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages


def _trace_reducer(current: list[str] | None, new: list[str] | None) -> list[str]:
    """Append node names; ``None`` resets the per-turn trace."""
    if new is None:
        return []
    return (current or []) + new


class CallState(TypedDict, total=False):
    # conversation (short-term memory, trimmed before each model call)
    messages: Annotated[list[AnyMessage], add_messages]

    # identity & session (bound by the API from verified tokens, never by the LLM)
    run_id: str
    thread_id: str
    correlation_id: str
    principal: dict           # {"sub", "roles", "channel"}
    customer_ref: str | None
    cust_auth_level: int

    # per-turn working state
    utterance: str
    pii_found: list[str]
    guard: dict
    memory_context: list[str]
    intent: str
    confidence: float
    sentiment: str
    vulnerability: bool
    entities: dict
    route: dict
    retrieved: list[dict]
    facts: list[str]
    proposed_action: dict | None
    review: dict | None
    action_result: dict | None
    case_id: str | None
    escalation: dict | None
    step_up_required: bool
    citations: list[str]
    next_best_actions: list[str]
    final_response: str | None
    output_violations: list[str]
    fallback: bool
    resolved: bool
    account_data_disclosed: bool
    summary: str | None
    disposition: str | None
    qa: dict | None
    prompt_version: str
    trace: Annotated[list[str], _trace_reducer]


# Values reset at the start of every turn (fields not listed persist across turns).
TURN_DEFAULTS: dict[str, Any] = {
    "pii_found": [],
    "guard": {},
    "memory_context": [],
    "intent": "general",
    "confidence": 0.0,
    "sentiment": "neutral",
    "vulnerability": False,
    "entities": {},
    "route": {},
    "retrieved": [],
    "facts": [],
    "proposed_action": None,
    "review": None,
    "action_result": None,
    "case_id": None,
    "escalation": None,
    "step_up_required": False,
    "citations": [],
    "next_best_actions": [],
    "final_response": None,
    "output_violations": [],
    "fallback": False,
    "resolved": False,
    "account_data_disclosed": False,
    "summary": None,
    "disposition": None,
    "qa": None,
    "trace": None,
}
