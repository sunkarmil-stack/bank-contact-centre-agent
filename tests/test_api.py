"""HTTP API: authentication, authorization, idempotency, protected review/resume,
rate limiting, ops and audit endpoints."""

import dataclasses
import uuid

import pytest
from fastapi.testclient import TestClient

from ccagent.api.app import create_app


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as c:
        yield c


def tok(client, persona, customer_ref="SYN-C-1001"):
    r = client.post("/dev/token", json={"persona": persona, "customer_ref": customer_ref})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def start(client, msg, persona="ivr_authenticated", idem=None, thread_id=None):
    body = {"message": msg} | ({"thread_id": thread_id} if thread_id else {})
    return client.post("/v1/interactions", json=body,
                       headers=tok(client, persona) | {"Idempotency-Key": idem or uuid.uuid4().hex})


def test_requires_authentication(client):
    r = client.post("/v1/interactions", json={"message": "hi"}, headers={"Idempotency-Key": "x" * 10})
    assert r.status_code == 401
    r = client.post("/v1/interactions", json={"message": "hi"},
                    headers={"Idempotency-Key": "x" * 10, "Authorization": "Bearer garbage"})
    assert r.status_code == 401


def test_role_enforced(client):
    r = client.post("/v1/interactions", json={"message": "hi"},
                    headers=tok(client, "reviewer") | {"Idempotency-Key": "x" * 10})
    assert r.status_code == 403


def test_idempotency_key_required_and_replayed(client):
    r = client.post("/v1/interactions", json={"message": "fees?"}, headers=tok(client, "ivr_authenticated"))
    assert r.status_code == 422
    a = start(client, "What are the monthly fees?", idem="same-key-123")
    b = start(client, "What are the monthly fees?", idem="same-key-123")
    assert a.json()["run_id"] == b.json()["run_id"] and b.json()["idempotent_replay"] is True


def test_security_headers_and_correlation_id(client):
    r = client.get("/healthz", headers={"X-Correlation-Id": "abc123"})
    assert r.headers["X-Correlation-Id"] == "abc123"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Cache-Control"] == "no-store"


def test_review_endpoint_is_protected(client):
    r1 = start(client, "I lost my credit card").json()
    run_id, pr = r1["run_id"], r1["pending_review"]
    body = {"decision": "approve", "interrupt_id": pr["interrupt_id"], "action_hash": pr["action_hash"]}

    # caller / agent / supervisor cannot approve
    for persona in ("ivr_authenticated", "agent", "supervisor"):
        assert client.post(f"/v1/runs/{run_id}/review", json=body, headers=tok(client, persona)).status_code == 403
    # stale / mismatched review payload
    bad = body | {"action_hash": "0" * 64}
    assert client.post(f"/v1/runs/{run_id}/review", json=bad, headers=tok(client, "reviewer")).status_code == 409
    # wrong run id
    assert client.post("/v1/runs/run_nope/review", json=body, headers=tok(client, "reviewer")).status_code == 404
    # reviewer sees it in the queue
    q = client.get("/v1/reviews/pending", headers=tok(client, "reviewer")).json()["items"]
    assert any(i["run_id"] == run_id for i in q)
    # authorised reviewer approves
    ok = client.post(f"/v1/runs/{run_id}/review", json=body, headers=tok(client, "reviewer"))
    assert ok.status_code == 200 and "locked" in ok.json()["response"]
    # cannot be approved twice
    again = client.post(f"/v1/runs/{run_id}/review", json=body, headers=tok(client, "reviewer2"))
    assert again.status_code == 409


def test_run_visibility(client):
    r = start(client, "What are the monthly fees?").json()
    assert client.get(f"/v1/runs/{r['run_id']}", headers=tok(client, "ivr_authenticated")).status_code == 200
    assert client.get(f"/v1/runs/{r['run_id']}", headers=tok(client, "agent")).status_code == 403
    assert client.get(f"/v1/runs/{r['run_id']}", headers=tok(client, "supervisor")).status_code == 200


def test_ops_kpis_staffing_and_audit(client):
    start(client, "What are the monthly fees?")
    start(client, "This is unacceptable, I want to make a complaint")
    start(client, "I think I was scammed")
    k = client.get("/v1/ops/kpis", headers=tok(client, "supervisor")).json()
    assert k["interactions"] == 3 and k["open_complaints"] == 1 and k["escalation_rate"] > 0
    s = client.post("/v1/ops/staffing", headers=tok(client, "supervisor"),
                    json={"contacts_per_interval": 200, "aht_s": 300, "ai_containment_rate": 0.25}).json()
    assert s["agents_required"] > 0 and s["service_level"] >= 0.8
    assert client.get("/v1/ops/kpis", headers=tok(client, "agent")).status_code == 403
    v = client.get("/v1/audit/verify", headers=tok(client, "auditor")).json()
    assert v["valid"] is True
    assert client.get("/v1/audit/verify", headers=tok(client, "supervisor")).status_code == 403


def test_rate_limit(settings):
    limited = dataclasses.replace(settings, rate_limit_per_minute=4)
    with TestClient(create_app(limited)) as c:
        h = tok(c, "supervisor")
        codes = [c.get("/v1/ops/metrics", headers=h).status_code for _ in range(6)]
    assert 429 in codes


def test_payload_size_limit(client):
    r = client.post("/v1/interactions", content=b"x" * 20000,
                    headers=tok(client, "ivr_authenticated") | {"Idempotency-Key": "x" * 10,
                                                                "content-type": "application/json"})
    assert r.status_code == 413
