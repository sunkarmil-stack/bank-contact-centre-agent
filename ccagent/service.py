"""Application service: runs turns through the graph, manages the durable run
lifecycle, and implements the protected human-review / resume flow."""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid

from langgraph.types import Command

from .agents.state import TURN_DEFAULTS
from .container import Container
from .logging_setup import correlation_id, log_event, request_entry
from .persistence.runs import ConcurrencyError, Run, RunStatus
from .security.auth import Principal, Role
from .security.pii import redact
from .security.tokens import action_hash
from .telemetry import METRICS, SpanKind, span

log = logging.getLogger("ccagent.service")



def _langsmith_callbacks() -> list:
    """LangSmith tracing of the whole graph run, through a PII-anonymising client.

    Deliberately NOT using @traceable on service methods: their raw inputs
    (unredacted caller text) would bypass the anonymiser."""
    if os.getenv("LANGSMITH_TRACING", "false").lower() != "true":
        return []
    from langchain_core.tracers.langchain import LangChainTracer

    from .telemetry import langsmith_client

    return [LangChainTracer(client=langsmith_client(), project_name=os.getenv("LANGSMITH_PROJECT", "ccagent"))]


class ServiceError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def _view(run: Run) -> dict:
    out = {
        "run_id": run.run_id,
        "thread_id": run.thread_id,
        "status": run.status,
        "intent": run.intent,
        "queue": run.queue,
        "version": run.version,
    }
    if run.status == RunStatus.AWAITING_REVIEW:
        pa = run.pending_action or {}
        out["pending_review"] = {
            "interrupt_id": run.pending_interrupt,
            "action_hash": run.action_hash,
            "action_type": pa.get("type"),
            "display": pa.get("display"),
            "risk_reason": pa.get("risk_reason"),
            "requested_by": pa.get("requested_by"),
        }
        out["response"] = "One moment please — a colleague is reviewing your request."
    if run.result:
        out.update(run.result)
    return out


class ContactCentreService:
    def __init__(self, c: Container) -> None:
        self.c = c
        self._callbacks = _langsmith_callbacks()

    # ---------------------------------------------------------------- helpers
    def _config(self, thread_id: str, run_id: str, principal_sub: str) -> dict:
        return {
            "configurable": {"thread_id": thread_id},
            "run_name": "contact_centre_turn",
            "tags": ["contact-centre", self.c.settings.env],
            "metadata": {"run_id": run_id, "principal": principal_sub},
            "callbacks": self._callbacks,
        }

    async def _invoke(self, payload, run: Run) -> dict:
        cfg = self._config(run.thread_id, run.run_id, run.requested_by)
        return await asyncio.wait_for(self.c.graph.ainvoke(payload, cfg), timeout=self.c.settings.graph_timeout_s)

    def _record_outcome(self, run: Run, result: dict, started: float, extra_metrics: dict | None = None) -> Run:
        interrupts = result.get("__interrupt__") or []
        if interrupts:
            intr = interrupts[0]
            value = intr.value
            METRICS.inc("hitl_requested_total", action=value["action"]["type"])
            self.c.audit.append("review_requested", run.requested_by, run.run_id,
                                action=value["action"], interrupt_id=intr.id)
            return self.c.runs.update(
                run.run_id, run.version, status=RunStatus.AWAITING_REVIEW, intent=result.get("intent"),
                queue=(result.get("route") or {}).get("queue"), pending_interrupt=intr.id,
                pending_action={"display": value.get("display"), "risk_reason": value.get("risk_reason"),
                                "type": value["action"]["type"], "requested_by": value["requested_by"],
                                "action": value["action"]},
                action_hash=value["action_hash"],
            )
        escalation = result.get("escalation")
        public = {
            "response": result.get("final_response"),
            "citations": result.get("citations", []),
            "next_best_actions": result.get("next_best_actions", []),
            "escalation": escalation,
            "step_up_required": bool(result.get("step_up_required")),
            "case_id": result.get("case_id"),
            "wrap_up": {"summary": result.get("summary"), "disposition": result.get("disposition")},
            "qa": result.get("qa"),
            "trace": result.get("trace", []),
        }
        metrics = {
            "contained": bool(result.get("resolved")) and not escalation,
            "escalated": bool(escalation),
            "guardrail_blocked": result.get("intent") == "blocked",
            "fallback": bool(result.get("fallback")),
            "qa_score": (result.get("qa") or {}).get("score"),
            "handle_time_s": round(time.perf_counter() - started, 3),
            **(extra_metrics or {}),
        }
        METRICS.observe("turn_latency_s", metrics["handle_time_s"])
        return self.c.runs.update(
            run.run_id, run.version, status=RunStatus.COMPLETED, intent=result.get("intent"),
            queue=(escalation or {}).get("queue") or (result.get("route") or {}).get("queue"),
            pending_interrupt=None, result=public, metrics=metrics,
        )

    def _fail(self, run: Run, exc: Exception) -> Run:
        log_event(log, "turn failed", logging.ERROR, run_id=run.run_id, error=type(exc).__name__)
        self.c.audit.append("run_failed", run.requested_by, run.run_id, error=type(exc).__name__)
        METRICS.inc("runs_failed_total", error=type(exc).__name__)
        current = self.c.runs.get(run.run_id) or run
        return self.c.runs.update(
            run.run_id, current.version, status=RunStatus.FAILED,
            result={"response": "I'm sorry — something went wrong on our side. I'm connecting you with a colleague.",
                    "escalation": {"reason": "system_error", "queue": "GENERAL_BANKING", "priority": "P2"}},
            metrics={"escalated": True, "fallback": True},
        )

    # ------------------------------------------------------------ start / turn
    async def start_turn(self, principal: Principal, *, message: str, idempotency_key: str,
                         thread_id: str | None = None) -> dict:
        if not principal.has_any(Role.AGENT, Role.CHANNEL):
            raise ServiceError(403, "forbidden", "only agents or channel services can start interactions")
        if not message or not message.strip():
            raise ServiceError(422, "invalid_request", "message is required")
        if thread_id:
            last = self.c.runs.latest_for_thread(thread_id)
            # Bind the thread to both the calling principal AND the customer: one IVR service
            # identity serves many customers, so the principal check alone would let another
            # customer's session load this conversation's short-term memory.
            if not last or last.requested_by != principal.sub or last.customer_ref != principal.customer_ref:
                self.c.audit.append("thread_access_denied", principal.sub, last.run_id if last else None,
                                    reason="thread_not_bound_to_caller")
                raise ServiceError(403, "forbidden", "thread does not belong to caller")
            if last.status == RunStatus.AWAITING_REVIEW:
                raise ServiceError(409, "review_pending", "a review is pending on this thread")

        run, created = self.c.runs.create_or_get(
            requested_by=principal.sub, idempotency_key=idempotency_key, thread_id=thread_id,
            channel=principal.channel, customer_ref=principal.customer_ref,
        )
        if not created:
            METRICS.inc("idempotent_replays_total")
            return _view(run) | {"idempotent_replay": True}

        redacted, pii_kinds = redact(message)
        self.c.audit.append("turn_started", principal.sub, run.run_id, channel=principal.channel,
                            customer_ref=principal.customer_ref, cust_auth_level=principal.cust_auth_level,
                            entry=request_entry.get())
        payload = {
            **TURN_DEFAULTS,
            "utterance": redacted,
            "pii_found": pii_kinds,  # what the API boundary redacted, so it is audited and explainable
            "run_id": run.run_id,
            "thread_id": run.thread_id,
            "correlation_id": correlation_id.get() if correlation_id.get() != "-" else uuid.uuid4().hex,
            "principal": {"sub": principal.sub, "roles": sorted(principal.roles), "channel": principal.channel},
            "customer_ref": principal.customer_ref,
            "cust_auth_level": principal.cust_auth_level,
        }
        started = time.perf_counter()
        with span("turn", SpanKind.CHAIN, run_id=run.run_id, channel=principal.channel):
            try:
                result = await self._invoke(payload, run)
            except Exception as exc:  # noqa: BLE001 - every failure must degrade to a human hand-off
                return _view(self._fail(run, exc))
        METRICS.inc("turns_total")
        return _view(self._record_outcome(run, result, started))

    # ------------------------------------------------------------------ review
    async def submit_review(self, reviewer: Principal, run_id: str, *, decision: str, interrupt_id: str,
                            action_hash_expected: str, comment: str = "") -> dict:
        if not reviewer.has_any(Role.REVIEWER):
            raise ServiceError(403, "forbidden", "reviewer role required")
        if decision not in ("approve", "reject"):
            raise ServiceError(422, "invalid_request", "decision must be approve or reject")
        run = self.c.runs.get(run_id)
        if not run:
            raise ServiceError(404, "not_found", "run not found")
        if run.status != RunStatus.AWAITING_REVIEW:
            raise ServiceError(409, "not_awaiting_review", f"run status is {run.status}")
        if reviewer.sub == run.requested_by:
            self.c.audit.append("review_denied", reviewer.sub, run_id, reason="four_eyes")
            raise ServiceError(403, "four_eyes_violation", "requester cannot review their own action")
        if interrupt_id != run.pending_interrupt or action_hash_expected != run.action_hash:
            self.c.audit.append("review_denied", reviewer.sub, run_id, reason="stale_or_mismatched_review")
            raise ServiceError(409, "review_mismatch", "review does not match the pending action (stale?)")
        action = (run.pending_action or {}).get("action") or {}
        if action_hash(action) != run.action_hash:
            raise ServiceError(409, "review_mismatch", "pending action integrity check failed")

        try:  # claim the run (optimistic concurrency — exactly one reviewer wins)
            run = self.c.runs.update(run_id, run.version, status=RunStatus.RUNNING, reviewer=reviewer.sub)
        except ConcurrencyError as exc:
            raise ServiceError(409, "conflict", "run was claimed by another reviewer") from exc

        self.c.audit.append("review_submitted", reviewer.sub, run_id, decision=decision, comment=comment[:500])
        resume = {
            "decision": decision,
            "reviewer": reviewer.sub,
            "comment": redact(comment)[0][:500],
            "action_hash": run.action_hash,
            "approval_token": self.c.tokens.mint_approval(run_id=run_id, action=action, reviewer=reviewer.sub)
            if decision == "approve" else None,
        }
        METRICS.inc("hitl_decisions_total", decision=decision)
        started = time.perf_counter()
        try:
            result = await self._invoke(Command(resume=resume), run)
        except Exception as exc:  # noqa: BLE001
            return _view(self._fail(run, exc))
        return _view(self._record_outcome(run, result, started, {"review_decision": decision}))

    # ------------------------------------------------------------------- reads
    def get_run(self, principal: Principal, run_id: str) -> dict:
        run = self.c.runs.get(run_id)
        if not run:
            raise ServiceError(404, "not_found", "run not found")
        if run.requested_by != principal.sub and not principal.has_any(Role.SUPERVISOR, Role.REVIEWER, Role.AUDITOR):
            raise ServiceError(403, "forbidden", "not permitted to view this run")
        return _view(run)

    async def explain(self, principal: Principal, run_id: str) -> dict:
        """Explainability view of a run for agent-assist, supervisors, reviewers and auditors:
        what the AI decided, which controls fired, which systems it touched, and the audit trail.
        Contains only redacted content; never tokens or raw account facts."""
        run = self.c.runs.get(run_id)
        if not run:
            raise ServiceError(404, "not_found", "run not found")
        if run.requested_by != principal.sub and not principal.has_any(Role.SUPERVISOR, Role.REVIEWER, Role.AUDITOR):
            raise ServiceError(403, "forbidden", "not permitted to view this run")
        snap = await self.c.graph.aget_state({"configurable": {"thread_id": run.thread_id}})
        v = snap.values or {}
        review = v.get("review") or {}
        pa = v.get("proposed_action") or {}
        return {
            "run": _view(run),
            "decision": {
                "utterance_seen_by_ai": v.get("utterance"),
                "intent": v.get("intent"), "confidence": v.get("confidence"), "sentiment": v.get("sentiment"),
                "vulnerability": v.get("vulnerability"), "route": v.get("route"),
                "customer_ref": v.get("customer_ref"), "cust_auth_level": v.get("cust_auth_level"),
                "pii_redacted": v.get("pii_found", []), "input_guard": v.get("guard"),
                "retrieved": [{"doc_id": c["doc_id"], "title": c.get("title"), "score": c.get("score")}
                              for c in v.get("retrieved", [])],
                "citations": v.get("citations", []),
                "proposed_action": {k: pa.get(k) for k in ("type", "display", "risk_reason")} if pa else None,
                "review": {k: review.get(k) for k in ("decision", "reviewer")} if review else None,
                "escalation": v.get("escalation"), "step_up_required": v.get("step_up_required"),
                "output_violations": v.get("output_violations", []), "fallback": v.get("fallback"),
                "summary": v.get("summary"), "disposition": v.get("disposition"), "qa": v.get("qa"),
                "trace": v.get("trace", []), "prompt_version": v.get("prompt_version"),
            },
            "audit": [{"ts": e["ts"], "event": e["event_type"], "actor": e["actor"], "details": e["details"]}
                      for e in self.c.audit.events(run_id)],
        }

    def pending_reviews(self, principal: Principal) -> list[dict]:
        if not principal.has_any(Role.REVIEWER, Role.SUPERVISOR):
            raise ServiceError(403, "forbidden", "reviewer or supervisor role required")
        return [
            {"run_id": r.run_id, "interrupt_id": r.pending_interrupt, "action_hash": r.action_hash,
             "display": (r.pending_action or {}).get("display"), "risk_reason": (r.pending_action or {}).get("risk_reason"),
             "requested_by": r.requested_by, "intent": r.intent, "waiting_s": round(time.time() - r.updated_at),
             "can_review": r.requested_by != principal.sub}
            for r in self.c.runs.list_by_status(RunStatus.AWAITING_REVIEW)
        ]
