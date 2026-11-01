"""Automated quality-assurance scorecard for every interaction.

Mirrors a typical contact-centre QA form; supervisors calibrate weights.
Scores feed coaching, the QA sampling queue (low scores are prioritised for
human QA review) and model-risk monitoring.
"""

from __future__ import annotations

SCORECARD = [
    # (criterion, weight)
    ("identity_verified_before_disclosure", 25),
    ("correct_routing_or_resolution", 20),
    ("no_sensitive_data_exposed", 20),
    ("grounded_in_approved_knowledge", 15),
    ("empathy_on_negative_or_vulnerable", 10),
    ("complaint_logged_when_expressed", 10),
]

_EMPATHY = ("sorry", "understand", "i can help", "here to help", "apologi", "thank you for")


def score_interaction(state: dict) -> dict:
    intent = state.get("intent")
    answer = (state.get("final_response") or "").lower()
    results: dict[str, bool | None] = {}

    disclosed = bool(state.get("account_data_disclosed"))
    results["identity_verified_before_disclosure"] = (not disclosed) or state.get("cust_auth_level", 0) >= 1
    results["correct_routing_or_resolution"] = bool(
        state.get("resolved") or state.get("escalation") or state.get("step_up_required") or intent == "blocked"
    )
    results["no_sensitive_data_exposed"] = not state.get("output_violations")
    if intent in ("product_question", "card_lost_stolen", "transaction_dispute") and not state.get("step_up_required"):
        results["grounded_in_approved_knowledge"] = bool(state.get("citations")) or bool(state.get("escalation"))
    else:
        results["grounded_in_approved_knowledge"] = None  # not applicable
    if state.get("sentiment") == "negative" or state.get("vulnerability"):
        results["empathy_on_negative_or_vulnerable"] = any(p in answer for p in _EMPATHY)
    else:
        results["empathy_on_negative_or_vulnerable"] = None
    if intent == "complaint":
        results["complaint_logged_when_expressed"] = bool(state.get("case_id"))
    else:
        results["complaint_logged_when_expressed"] = None

    applicable = [(c, w) for c, w in SCORECARD if results[c] is not None]
    total_w = sum(w for _, w in applicable) or 1
    earned = sum(w for c, w in applicable if results[c])
    score = round(100 * earned / total_w)
    return {"score": score, "criteria": results, "needs_human_qa": score < 80}
