"""Customer and Case microservices: zero-trust checks on every request."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from ccagent.secrets import build_secret_provider
from ccagent.security.service_tokens import LocalServiceTokens
from ccagent.security.tokens import InternalTokens


@pytest.fixture
def kit(settings):
    secrets = build_secret_provider(settings)
    tokens = InternalTokens(secrets)

    def svc_token(caller, audience):
        return asyncio.run(LocalServiceTokens(secrets, caller).token_for(audience))

    def delegation(tool, purpose, customer="SYN-C-1001", level=1, sub="ivr-svc"):
        return tokens.mint_delegation(on_behalf_of=sub, roles=["channel_service"], customer_ref=customer,
                                      cust_auth_level=level, purpose=purpose, correlation_id="cid-test", tool=tool)

    return settings, tokens, svc_token, delegation


@pytest.fixture
def customer(kit):
    from services.customer_service.app import create_app

    settings = kit[0]
    with TestClient(create_app(settings)) as c:
        yield c


@pytest.fixture
def cases(kit):
    from services.case_service.app import create_app

    with TestClient(create_app(kit[0])) as c:
        yield c


def h(svc, user=None, **extra):
    out = {"Authorization": f"Bearer {svc}"}
    if user:
        out["X-Delegation-Token"] = user
    out.update(extra)
    return out


# ---------------------------------------------------------------- customer-service

def test_customer_requires_workload_identity(customer, kit):
    _, _, svc_token, delegation = kit
    user = delegation("get_customer_profile", "servicing")
    assert customer.get("/customers/SYN-C-1001/profile", headers={"X-Delegation-Token": user}).status_code == 401
    wrong_aud = svc_token("mcp-tool-service", "case-service")
    assert customer.get("/customers/SYN-C-1001/profile", headers=h(wrong_aud, user)).status_code == 401
    no_perm = svc_token("agent-api", "customer-service")  # agent-api has no customer permissions
    assert customer.get("/customers/SYN-C-1001/profile", headers=h(no_perm, user)).status_code == 403


def test_customer_requires_user_context_and_binding(customer, kit):
    _, _, svc_token, delegation = kit
    svc = svc_token("mcp-tool-service", "customer-service")
    assert customer.get("/customers/SYN-C-1001/profile", headers=h(svc)).json()["error"] == "missing_user_context"
    user_1002 = delegation("get_customer_profile", "servicing", customer="SYN-C-1002")
    r = customer.get("/customers/SYN-C-1001/profile", headers=h(svc, user_1002))
    assert r.status_code == 403 and "customer_not_bound_to_session" in r.json()["message"]
    wrong_tool = delegation("lock_card", "servicing")
    assert customer.get("/customers/SYN-C-1001/profile", headers=h(svc, wrong_tool)).status_code == 401


def test_customer_purpose_minimisation_and_step_up(customer, kit):
    _, _, svc_token, delegation = kit
    svc = svc_token("mcp-tool-service", "customer-service")
    full = customer.get("/customers/SYN-C-1001/profile", headers=h(svc, delegation("get_customer_profile", "servicing")))
    assert full.status_code == 200 and "accounts" in full.json()
    minimal = customer.get("/customers/SYN-C-1001/profile",
                           headers=h(svc, delegation("get_customer_profile", "complaint"))).json()
    assert "accounts" not in minimal and "cards" not in minimal
    r = customer.get("/customers/SYN-C-1001/profile",
                     headers=h(svc, delegation("get_customer_profile", "servicing", level=0)))
    assert r.status_code == 403 and r.json()["error"] == "step_up_required"
    r = customer.get("/customers/SYN-C-1001/transactions",
                     headers=h(svc, delegation("list_recent_transactions", "complaint")))
    assert r.status_code == 403  # purpose not permitted for transactions


def test_card_lock_needs_approval_four_eyes_and_is_idempotent(customer, kit):
    _, tokens, svc_token, delegation = kit
    svc = svc_token("mcp-tool-service", "customer-service")
    user = delegation("lock_card", "card_servicing")
    url = "/customers/SYN-C-1001/cards/SYN-K-1001-01/lock"
    base = h(svc, user, **{"Idempotency-Key": "lock-key-0001", "X-Run-Id": "run_x"})
    assert customer.post(url, headers=base).json()["error"] == "approval_required"
    action = {"type": "lock_card", "customer_ref": "SYN-C-1001", "card_id": "SYN-K-1001-01"}
    other_run = tokens.mint_approval(run_id="run_other", action=action, reviewer="reviewer-007")
    assert customer.post(url, headers=base | {"X-Approval-Token": other_run}).status_code == 401
    self_ok = tokens.mint_approval(run_id="run_x", action=action, reviewer="ivr-svc")
    assert customer.post(url, headers=base | {"X-Approval-Token": self_ok}).json()["error"] == "four_eyes_violation"
    good = tokens.mint_approval(run_id="run_x", action=action, reviewer="reviewer-007")
    r1 = customer.post(url, headers=base | {"X-Approval-Token": good}).json()
    r2 = customer.post(url, headers=base | {"X-Approval-Token": good}).json()
    assert r1["status"] == "locked" and r1["idempotent_replay"] is False
    assert r2["confirmation"] == r1["confirmation"] and r2["idempotent_replay"] is True
    no_key = {k: v for k, v in base.items() if k != "Idempotency-Key"} | {"X-Approval-Token": good}
    assert customer.post(url, headers=no_key).status_code == 422


# -------------------------------------------------------------------- case-service

def test_case_create_binding_purpose_and_idempotency(cases, kit):
    _, _, svc_token, delegation = kit
    svc = svc_token("mcp-tool-service", "case-service")
    user = delegation("create_case", "complaint")
    body = {"case_type": "complaint", "priority": "P2", "summary": "Long wait times", "sla_hours": 48,
            "customer_ref": "SYN-C-9999"}  # extra field ignored: client comes from the token
    hdr = h(svc, user, **{"Idempotency-Key": "case-key-0001", "X-Run-Id": "run_c"})
    a = cases.post("/cases", headers=hdr, json=body).json()
    b = cases.post("/cases", headers=hdr, json=body).json()
    assert a["customer_ref"] == "SYN-C-1001" and a["case_id"] == b["case_id"] and b["idempotent_replay"] is True
    wrong_purpose = delegation("create_case", "servicing")
    r = cases.post("/cases", headers=h(svc, wrong_purpose, **{"Idempotency-Key": "case-key-0002"}), json=body)
    assert r.status_code == 403


def test_large_dispute_requires_approval(cases, kit):
    _, tokens, svc_token, delegation = kit
    svc = svc_token("mcp-tool-service", "case-service")
    user = delegation("create_case", "dispute")
    details = {"txn_id": "SYN-T-9003", "amount_cad": 749.0, "requires_approval": True}
    body = {"case_type": "dispute", "priority": "P2", "summary": "Dispute", "details": details}
    hdr = h(svc, user, **{"Idempotency-Key": "disp-key-0001", "X-Run-Id": "run_d"})
    assert cases.post("/cases", headers=hdr, json=body).json()["error"] == "approval_required"
    action = {"type": "create_dispute", "customer_ref": "SYN-C-1001", "txn_id": "SYN-T-9003", "amount_cad": 749.0}
    ok = tokens.mint_approval(run_id="run_d", action=action, reviewer="reviewer-007")
    r = cases.post("/cases", headers=hdr | {"X-Approval-Token": ok}, json=body)
    assert r.status_code == 200 and r.json()["case_type"] == "dispute"


def test_case_listing_needs_read_permission(cases, kit):
    _, _, svc_token, _ = kit
    assert cases.get("/cases", headers=h(svc_token("agent-api", "case-service"))).status_code == 200
    assert cases.get("/cases", headers=h(svc_token("api-gateway", "case-service"))).status_code == 403
    assert cases.get("/cases").status_code == 401


def test_denials_are_audited(customer, kit, settings):
    from ccagent.persistence.audit import AuditLog
    from ccagent.persistence.db import Database

    customer.get("/customers/SYN-C-1001/profile")
    log = AuditLog(Database(str(settings.data_dir / "customer.db")), service="test")
    events = [e for e in log.events() if e["event_type"] == "service_access_denied"]
    assert events and events[0]["details"]["service"] == "customer-service"
