"""End-to-end: all five services as real processes, driven through the API gateway.

Covers the architecture claims: edge authentication, gateway-only ingress, agents
reaching systems of record only via MCP + workload identity, four-eyes enforced again
at the system of record, a shared verifiable audit trail, and graceful degradation
when a microservice is down.
"""

import json
import os
import urllib.error
import urllib.request
import uuid

import pytest

from scripts.run_all import start_stack


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    offset = 1000 + (os.getpid() % 500) * 3
    s = start_stack(tmp_path_factory.mktemp("stack"), port_offset=offset, fresh=True)
    yield s
    s.stop()


def call(stack, method, path, body=None, token=None, headers=None, base=None):
    h = {"content-type": "application/json", **(headers or {})}
    if token:
        h["Authorization"] = "Bearer " + token
    req = urllib.request.Request((base or stack.gateway) + path, method=method, headers=h,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def tok(stack, persona):
    return call(stack, "POST", "/dev/token", {"persona": persona})[1]["access_token"]


def turn(stack, token, message):
    return call(stack, "POST", "/v1/interactions", {"message": message}, token, {"Idempotency-Key": uuid.uuid4().hex})


def test_all_services_healthy_through_gateway(stack):
    _, h = call(stack, "GET", "/gateway/health")
    assert h["status"] == "up"
    assert {s["name"] for s in h["services"]} == {"api-gateway", "agent-api", "mcp-tool-service",
                                                  "customer-service", "case-service"}


def test_edge_and_ingress_controls(stack):
    assert call(stack, "POST", "/v1/interactions", {"message": "hi"})[0] == 401
    ivr = tok(stack, "ivr_authenticated")
    status, body = call(stack, "POST", "/v1/interactions", {"message": "hi"}, ivr,
                        {"Idempotency-Key": uuid.uuid4().hex}, base=stack.url("agent-api"))
    assert status == 403 and body["error"] == "gateway_required"


def test_card_lock_end_to_end_across_services(stack):
    ivr, rev, sup, aud = (tok(stack, p) for p in ("ivr_authenticated", "reviewer", "supervisor", "auditor"))
    call(stack, "POST", "/dev/reset", base=stack.url("customer-service"))
    _, r1 = turn(stack, ivr, "I lost my credit card")
    assert r1["status"] == "awaiting_review"
    pr = r1["pending_review"]
    _, r2 = call(stack, "POST", f"/v1/runs/{r1['run_id']}/review",
                 {"decision": "approve", "interrupt_id": pr["interrupt_id"], "action_hash": pr["action_hash"]}, rev)
    assert "locked" in r2["response"]
    _, x = call(stack, "GET", f"/v1/runs/{r1['run_id']}/explain", token=sup)
    services = {e["details"].get("service") for e in x["audit"]}
    assert {"agent-api", "customer-service"} <= services
    started = next(e for e in x["audit"] if e["event"] == "turn_started")
    assert started["details"]["entry"] == "api-gateway"
    tools = [e["details"] for e in x["audit"] if e["event"] == "tool_call"]
    assert all(t["transport"] == "mcp-http" for t in tools)
    assert any(t["tool"] == "lock_card" and t["backend"] == "customer-service" for t in tools)
    assert any(e["event"] == "card_locked" and e["details"]["service"] == "customer-service" for e in x["audit"])
    assert call(stack, "GET", "/v1/audit/verify", token=aud)[1]["valid"] is True


def test_complaint_case_lives_in_case_service(stack):
    ivr, sup = tok(stack, "ivr_authenticated"), tok(stack, "supervisor")
    _, r = turn(stack, ivr, "This is unacceptable, I want to file a complaint")
    assert r["case_id"].startswith("CASE-")
    _, cases = call(stack, "GET", "/v1/ops/cases?case_type=complaint", token=sup)
    assert any(c["case_id"] == r["case_id"] for c in cases["items"])


def test_customer_service_outage_degrades_to_a_person(stack):
    """Kill customer-service: the balance request must hand off safely, not crash or leak."""
    ivr = tok(stack, "ivr_authenticated")
    proc = stack.procs["customer-service"]
    proc.terminate()
    proc.wait(timeout=10)
    _, h = call(stack, "GET", "/gateway/health")
    assert h["status"] == "degraded"
    assert next(s for s in h["services"] if s["name"] == "customer-service")["status"] == "down"
    status, r = turn(stack, ivr, "What's my balance?")
    assert status == 200
    assert r["escalation"] and "colleague" in r["response"]
    assert "$" not in r["response"]
    # the knowledge path does not depend on customer-service and keeps working
    _, k = turn(stack, ivr, "How do e-Transfer limits work?")
    assert "KB-ETRF-007" in k["citations"]
