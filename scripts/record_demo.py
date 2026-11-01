"""Record the stakeholder demo from the REAL platform — all five services.

Starts the gateway, agent API, MCP tool service, customer-service and case-service
as separate processes (``scripts.run_all``), then drives every demo scenario through
the API gateway exactly as the console does: sign-in, call, explainability view,
the requester's refused self-approval, the reviewer's approve / reject. It also runs a
60-call sample shift on a second, fresh stack and records the supervisor KPIs, the
audit-chain check, gateway health and gateway metrics.

Output: ``static/demo_recording.json`` (offline model, synthetic data).

    python -m scripts.record_demo
    python -m scripts.build_demo_page      # shareable replay page
"""

from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from ccagent.container import DATA
from ccagent.demo_scenarios import SCENARIOS, SHIFT_MIX
from ccagent.llm.prompts import PROMPT_VERSION

from .run_all import Stack, start_stack

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "static" / "demo_recording.json"
PORT_OFFSET = 2000  # keep clear of a stack you may already be running on the default ports


class Client:
    def __init__(self, stack: Stack) -> None:
        self.stack = stack
        self._tokens: dict[str, str] = {}

    def call(self, method: str, path: str, body=None, token: str | None = None, headers=None, base=None):
        h = {"content-type": "application/json", **(headers or {})}
        if token:
            h["Authorization"] = "Bearer " + token
        req = urllib.request.Request((base or self.stack.gateway) + path, method=method, headers=h,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=90) as r:  # noqa: S310 - local stack
                return r.status, json.load(r), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e), dict(e.headers)

    def token(self, persona: str, customer: str = "SYN-C-1001") -> str:
        k = f"{persona}|{customer}"
        if k not in self._tokens:
            self._tokens[k] = self.call("POST", "/dev/token", {"persona": persona, "customer_ref": customer})[1][
                "access_token"]
        return self._tokens[k]

    def reset_cards(self) -> None:
        self.call("POST", "/dev/reset", base=self.stack.url("customer-service"))

    def turn(self, sc: dict) -> tuple[dict, dict]:
        persona = "ivr_authenticated" if sc["auth"] >= 1 else "ivr_unauthenticated"
        status, body, headers = self.call("POST", "/v1/interactions", {"message": sc["message"]},
                                          self.token(persona, sc["customer"]), {"Idempotency-Key": uuid.uuid4().hex})
        if status != 200:
            raise RuntimeError(f"{sc['id']}: {status} {body}")
        return body, _gw(headers)

    def explain(self, run_id: str) -> dict:
        return self.call("GET", f"/v1/runs/{run_id}/explain", token=self.token("supervisor"))[1]

    def review(self, run: dict, decision: str, persona: str = "reviewer", customer: str = "SYN-C-1001"):
        pr = run["pending_review"]
        return self.call("POST", f"/v1/runs/{run['run_id']}/review",
                         {"decision": decision, "interrupt_id": pr["interrupt_id"], "action_hash": pr["action_hash"],
                          "comment": "Caller verified in IVR" if decision == "approve" else "Details did not match"},
                         self.token(persona, customer))


def _gw(headers: dict) -> dict:
    low = {k.lower(): v for k, v in headers.items()}
    return {"route": low.get("x-upstream"), "latency_ms": float(low.get("x-gateway-latency-ms") or 0),
            "correlation_id": low.get("x-correlation-id")}


def record_scenario(c: Client, sc: dict) -> dict:
    out: dict = {}
    c.reset_cards()
    first, gw = c.turn(sc)
    out["initial"] = {"response": first, "explain": c.explain(first["run_id"]), "gateway": gw}
    if first["status"] != "awaiting_review":
        return out
    persona = "ivr_authenticated" if sc["auth"] >= 1 else "ivr_unauthenticated"
    status, body, _ = c.review(first, "approve", persona=persona, customer=sc["customer"])
    out["requester_attempt"] = {"status": status, "error": body.get("error"),
                                "message": body.get("message") or body.get("detail") or ""}
    status, final, _ = c.review(first, "approve")
    out["approve"] = {"response": final, "explain": c.explain(first["run_id"])}
    c.reset_cards()
    second, _ = c.turn(sc)
    status, final, _ = c.review(second, "reject")
    out["reject"] = {"response": final, "explain": c.explain(second["run_id"])}
    return out


def record_shift(c: Client) -> dict:
    by_id = {s["id"]: s for s in SCENARIOS}
    calls = [sid for sid, n in SHIFT_MIX.items() for _ in range(n)]
    for i, sid in enumerate(calls):
        sc = by_id[sid]
        c.reset_cards()  # each shift call stands for a different caller with an active card
        r, _ = c.turn(sc)
        if r["status"] == "awaiting_review":
            c.review(r, "reject" if i % 7 == 3 else "approve")
    sup, aud = c.token("supervisor"), c.token("auditor")
    return {"calls": len(calls), "kpis": c.call("GET", "/v1/ops/kpis", token=sup)[1],
            "audit_chain": c.call("GET", "/v1/audit/verify", token=aud)[1]}


def main() -> None:
    # The recorder sends hundreds of calls a minute as a few principals; raise the per-principal
    # limits for these private recording stacks only (normal runs keep the defaults).
    os.environ["CCAGENT_RATE_LIMIT_PER_MINUTE"] = "100000"
    os.environ["GATEWAY_RATE_LIMIT_PER_MINUTE"] = "100000"
    os.environ["GATEWAY_PUBLIC_RATE_LIMIT_PER_MINUTE"] = "100000"
    kb = json.loads((DATA / "knowledge_base.json").read_text())
    with tempfile.TemporaryDirectory() as tmp:
        print("Starting the five services for the scenario recording…")
        stack = start_stack(Path(tmp) / "scenarios", port_offset=PORT_OFFSET, fresh=True)
        try:
            c = Client(stack)
            runs = {}
            for sc in SCENARIOS:
                runs[sc["id"]] = record_scenario(c, sc)
                print(f"  recorded {sc['id']}")
            # Show the edge refusing traffic: no sign-in, a forged token, and an unknown route.
            c.call("POST", "/v1/interactions", {"message": "hello"})
            c.call("POST", "/v1/interactions", {"message": "hello"}, token="forged.token.value")
            c.call("GET", "/admin/export-all-customers")
            health = json.dumps(c.call("GET", "/gateway/health")[1])
            for name, port in stack.ports.items():  # show the standard ports a local run uses
                health = health.replace(f":{port}", f":{port - PORT_OFFSET}")
            architecture = {
                "health": json.loads(health),
                "metrics": c.call("GET", "/gateway/metrics", token=c.token("supervisor"))[1],
                "routes": c.call("GET", "/gateway/routes")[1]["routes"],
            }
        finally:
            stack.stop()
        print("Starting a fresh stack for the 60-call sample shift…")
        stack = start_stack(Path(tmp) / "shift", port_offset=PORT_OFFSET + 50, fresh=True)
        try:
            shift = record_shift(Client(stack))
        finally:
            stack.stop()
    recording = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "model": "offline deterministic model",
        "prompt_version": PROMPT_VERSION,
        "topology": "five services: api-gateway, agent-api, mcp-tool-service, customer-service, case-service",
        "scenarios": SCENARIOS,
        "runs": runs,
        "architecture": architecture,
        "shift": shift,
        "kb": {d["doc_id"]: {"title": d["title"], "owner": d["owner"], "effective_date": d["effective_date"]}
               for d in kb["documents"]},
    }
    OUT.write_text(json.dumps(recording, indent=1, default=str))
    print(f"recorded {len(SCENARIOS)} scenarios and a {shift['calls']}-call shift through the gateway -> {OUT}")


if __name__ == "__main__":
    main()
