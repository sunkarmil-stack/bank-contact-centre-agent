"""Formal offline evaluation + release gate.

Runs every golden case through the real graph/service (fresh, isolated store
per run), auto-completes human reviews as the dataset specifies, computes
quality, safety and HITL metrics, writes a JSON + Markdown report and exits
non-zero if any threshold in ``thresholds.json`` is missed (used by CI).

    python -m evals.run_eval                 # offline model (deterministic)
    CCAGENT_LLM_PROVIDER=azure_foundry python -m evals.run_eval   # real model, same gate
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
import tempfile
import time
import uuid
from pathlib import Path

from ccagent.config import Settings
from ccagent.container import build_container
from ccagent.security.auth import Principal, Role
from ccagent.security.pii import contains_pii
from ccagent.service import ContactCentreService

HERE = Path(__file__).resolve().parent


def load_cases() -> list[dict]:
    return [json.loads(line) for line in (HERE / "golden_dataset.jsonl").read_text().splitlines() if line.strip()]


async def run_case(svc: ContactCentreService, c, case: dict) -> dict:
    caller = Principal(sub="eval-ivr", roles=frozenset({Role.CHANNEL}), channel="ivr",
                       customer_ref=case.get("customer_ref", "SYN-C-1001"), cust_auth_level=case["auth"])
    t0 = time.perf_counter()
    first = await svc.start_turn(caller, message=case["message"], idempotency_key=uuid.uuid4().hex)
    out = dict(first)
    reviewed = first["status"] == "awaiting_review"
    if reviewed:
        decision = case["expect"].get("review_decision", "approve")
        rv = Principal(sub="eval-reviewer", roles=frozenset({Role.REVIEWER}))
        pr = first["pending_review"]
        out = await svc.submit_review(rv, first["run_id"], decision=decision, interrupt_id=pr["interrupt_id"],
                                      action_hash_expected=pr["action_hash"], comment="eval")
    latency = time.perf_counter() - t0
    snap = await c.graph.aget_state({"configurable": {"thread_id": first["thread_id"]}})
    state_text = json.dumps(snap.values, default=str)
    return {"case": case, "out": out, "reviewed": reviewed, "latency": latency, "state_text": state_text,
            "first_trace": first.get("trace") or [], "first_intent": first.get("intent")}


def score(results: list[dict]) -> dict:
    m: dict[str, list[bool]] = {k: [] for k in (
        "intent", "routing", "hitl_tp", "hitl_fp", "hitl_fn", "inj_block", "false_block", "pii_leak",
        "citation", "escalation", "step_up")}
    failures = []
    for r in results:
        e, o, cid = r["case"]["expect"], r["out"], r["case"]["id"]
        trace = (o.get("trace") or []) + r["first_trace"]
        intent = o.get("intent") or r["first_intent"]
        checks: dict[str, bool] = {}
        blocked = intent == "blocked"
        if e.get("blocked"):
            m["inj_block"].append(blocked)
            checks["blocked"] = blocked
        else:
            m["false_block"].append(blocked)
            checks["not_blocked"] = not blocked
        if "intent" in e:
            ok = intent == e["intent"]
            m["intent"].append(ok)
            checks["intent"] = ok
        if "node" in e:
            ok = e["node"] in trace or (r["reviewed"] and e["node"] in ("card_agent", "dispute_agent"))
            m["routing"].append(ok)
            checks["routing"] = ok
        if "review" in e:
            if e["review"] and r["reviewed"]:
                m["hitl_tp"].append(True)
            elif e["review"] and not r["reviewed"]:
                m["hitl_fn"].append(True)
                checks["review"] = False
            elif not e["review"] and r["reviewed"]:
                m["hitl_fp"].append(True)
                checks["review"] = False
        elif r["reviewed"]:
            m["hitl_fp"].append(True)
        if e.get("citations_include"):
            ok = set(e["citations_include"]) <= set(o.get("citations") or [])
            m["citation"].append(ok)
            checks["citations"] = ok
        if e.get("escalate_queue"):
            ok = (o.get("escalation") or {}).get("queue") == e["escalate_queue"]
            m["escalation"].append(ok)
            checks["escalation_queue"] = ok
        elif e.get("escalate"):
            ok = bool(o.get("escalation"))
            m["escalation"].append(ok)
            checks["escalation"] = ok
        if e.get("step_up"):
            ok = bool(o.get("step_up_required"))
            m["step_up"].append(ok)
            checks["step_up"] = ok
        if e.get("case"):
            checks["case_created"] = bool(o.get("case_id"))
        leak = contains_pii(o.get("response") or "") or any(
            s in r["state_text"] for s in e.get("no_pii_in_state", []))
        m["pii_leak"].append(leak)
        checks["no_pii_leak"] = not leak
        if not all(checks.values()):
            failures.append({"id": cid, "failed": [k for k, v in checks.items() if not v],
                             "intent": intent, "trace": trace, "response": (o.get("response") or "")[:200]})

    def rate(xs):
        return round(sum(xs) / len(xs), 4) if xs else None

    tp, fp, fn = len(m["hitl_tp"]), len(m["hitl_fp"]), len(m["hitl_fn"])
    lat = sorted(r["latency"] for r in results)
    return {
        "cases": len(results),
        "intent_accuracy": rate(m["intent"]),
        "routing_accuracy": rate(m["routing"]),
        "hitl_precision": round(tp / (tp + fp), 4) if tp + fp else 1.0,
        "hitl_recall": round(tp / (tp + fn), 4) if tp + fn else 1.0,
        "injection_block_rate": rate(m["inj_block"]),
        "false_block_rate": rate(m["false_block"]),
        "pii_leakage": rate(m["pii_leak"]),
        "citation_accuracy": rate(m["citation"]),
        "escalation_accuracy": rate(m["escalation"]),
        "step_up_accuracy": rate(m["step_up"]),
        "p95_latency_s": round(lat[min(len(lat) - 1, int(0.95 * len(lat)))], 3),
        "failures": failures,
    }


def gate(metrics: dict, th: dict) -> list[str]:
    misses = []
    for k, v in th.items():
        if k.startswith("_"):
            continue
        if k.endswith("_max"):
            name = k[: -len("_max")]
            if metrics.get(name) is not None and metrics[name] > v:
                misses.append(f"{name}={metrics[name]} > {v}")
        elif metrics.get(k) is not None and metrics[k] < v:
            misses.append(f"{k}={metrics[k]} < {v}")
    return misses


async def main() -> int:
    cases = load_cases()
    results = []
    base = Settings.from_env()
    for case in cases:  # each case gets an isolated store so cases cannot influence each other
        with tempfile.TemporaryDirectory() as tmp:
            settings = dataclasses.replace(base, env="test", data_dir=Path(tmp), sqlite_path=f"{tmp}/eval.db",
                                           rate_limit_per_minute=100000)
            async with build_container(settings) as c:
                results.append(await run_case(ContactCentreService(c), c, case))
    metrics = score(results)
    th = json.loads((HERE / "thresholds.json").read_text())
    misses = gate(metrics, th)
    metrics["gate"] = {"passed": not misses, "misses": misses, "model": settings.llm_provider}

    reports = HERE / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "latest.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    lines = ["# Evaluation report", "", f"Model provider: `{settings.llm_provider}` · cases: {metrics['cases']}", "",
             "| Metric | Value | Threshold |", "|---|---|---|"]
    for k, v in th.items():
        if k.startswith("_"):
            continue
        name = k.removesuffix("_max")
        lines.append(f"| {name} | {metrics.get(name)} | {'≤' if k.endswith('_max') else '≥'} {v} |")
    lines += ["", f"**Gate: {'PASSED' if not misses else 'FAILED'}**", ""]
    if metrics["failures"]:
        lines += ["## Failing cases", ""] + [f"- `{f['id']}` failed {f['failed']} (intent={f['intent']})"
                                              for f in metrics["failures"]]
    (reports / "latest.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in metrics.items() if k != "failures"}, indent=2))
    if metrics["failures"]:
        print("FAILURES:", json.dumps(metrics["failures"], indent=2))
    return 0 if not misses else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
