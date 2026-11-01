"""Contact-centre KPIs computed from the durable run registry."""

from __future__ import annotations

import datetime as dt
import time
from collections import Counter

from ..persistence.runs import RunRepository, RunStatus


def compute_kpis(runs: RunRepository, cases: list[dict], since_hours: float = 24) -> dict:
    since = time.time() - since_hours * 3600
    items = runs.all_runs(since)
    total = len(items)
    intents = Counter(r.intent or "unknown" for r in items)
    queues = Counter(r.queue for r in items if r.queue)
    contained = sum(1 for r in items if (r.metrics or {}).get("contained"))
    escalated = sum(1 for r in items if (r.metrics or {}).get("escalated"))
    blocked = sum(1 for r in items if (r.metrics or {}).get("guardrail_blocked"))
    fallbacks = sum(1 for r in items if (r.metrics or {}).get("fallback"))
    reviewed = [r for r in items if r.reviewer]
    approved = sum(1 for r in reviewed if (r.metrics or {}).get("review_decision") == "approve")
    qa_scores = [(r.metrics or {}).get("qa_score") for r in items if (r.metrics or {}).get("qa_score") is not None]
    handle = [(r.metrics or {}).get("handle_time_s") for r in items if (r.metrics or {}).get("handle_time_s")]
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    open_complaints = [c for c in cases if c["case_type"] == "complaint" and c["status"] == "open"]
    breached = [c for c in open_complaints if c["sla_due_at"] < now]

    def rate(x: int) -> float:
        return round(x / total, 4) if total else 0.0

    return {
        "window_hours": since_hours,
        "interactions": total,
        "containment_rate": rate(contained),
        "escalation_rate": rate(escalated),
        "guardrail_block_rate": rate(blocked),
        "fallback_rate": rate(fallbacks),
        "awaiting_review": sum(1 for r in items if r.status == RunStatus.AWAITING_REVIEW),
        "hitl_reviews": len(reviewed),
        "hitl_approval_rate": round(approved / len(reviewed), 4) if reviewed else None,
        "avg_qa_score": round(sum(qa_scores) / len(qa_scores), 1) if qa_scores else None,
        "avg_ai_handle_time_s": round(sum(handle) / len(handle), 3) if handle else None,
        "intent_mix": dict(intents),
        "queue_mix": dict(queues),
        "open_complaints": len(open_complaints),
        "complaint_sla_breaches": len(breached),
    }
