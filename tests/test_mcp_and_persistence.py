"""MCP tool-server controls, encryption at rest, durability across restarts,
and audit-chain integrity."""

import asyncio
import json
import sqlite3
from pathlib import Path

from ccagent.agents.tool_gateway import ToolNotPermitted, ToolSession, parse_tool_result
from ccagent.container import build_container
from ccagent.persistence.runs import RunStatus
from ccagent.service import ContactCentreService

from .conftest import ivr, key, reviewer, run_with_service


def _session(customer_ref="SYN-C-1001", level=1, sub="ivr-svc"):
    return ToolSession(on_behalf_of=sub, roles=("channel_service",), customer_ref=customer_ref,
                       cust_auth_level=level, correlation_id="test", run_id="run_test")


def test_mcp_tools_reject_missing_or_forged_delegation(settings):
    async def sc(svc, c):
        from mcp.client.client import Client

        async with Client(c.mcp_server) as client:
            r1 = await client.call_tool("get_customer_profile", {"delegation_token": "forged"})
        return parse_tool_result(r1)

    out = run_with_service(settings, sc)
    assert out["ok"] is False and out["error"] == "unauthorized"


def test_customer_comes_from_token_not_arguments(settings):
    async def sc(svc, c):
        prof = await c.gateway.call("account_agent", "get_customer_profile", _session("SYN-C-1002"),
                                    purpose="servicing")
        return prof

    prof = run_with_service(settings, sc)
    assert prof["profile"]["customer_ref"] == "SYN-C-1002"


def test_purpose_limitation_and_data_minimisation(settings):
    async def sc(svc, c):
        complaint = await c.gateway.call("escalation_agent", "get_customer_profile", _session(), purpose="complaint")
        bogus = await c.gateway.call("escalation_agent", "get_customer_profile", _session(), purpose="marketing")
        return complaint, bogus

    complaint, bogus = run_with_service(settings, sc)
    assert "accounts" not in complaint["profile"] and "cards" not in complaint["profile"]
    assert bogus["ok"] is False and bogus["error"] == "forbidden"


def test_agent_tool_allowlist_enforced(settings):
    async def sc(svc, c):
        try:
            await c.gateway.call("knowledge_agent", "lock_card", _session(), purpose="card_servicing",
                                 card_id="SYN-K-1001-01", idempotency_key="k" * 20)
        except ToolNotPermitted:
            return True
        return False

    assert run_with_service(settings, sc)


def test_lock_card_requires_matching_approval_and_four_eyes(settings):
    async def sc(svc, c):
        s = _session()
        no_approval = await c.gateway.call("card_agent", "lock_card", s, purpose="card_servicing",
                                           card_id="SYN-K-1001-01", idempotency_key="k" * 20)
        wrong = c.tokens.mint_approval(run_id="run_test", reviewer="reviewer-007",
                                       action={"type": "lock_card", "customer_ref": "SYN-C-1001", "card_id": "OTHER"})
        mismatched = await c.gateway.call("card_agent", "lock_card", s, purpose="card_servicing",
                                          card_id="SYN-K-1001-01", idempotency_key="k" * 20, approval_token=wrong)
        self_approved = c.tokens.mint_approval(run_id="run_test", reviewer="ivr-svc",
                                               action={"type": "lock_card", "customer_ref": "SYN-C-1001",
                                                       "card_id": "SYN-K-1001-01"})
        four_eyes = await c.gateway.call("card_agent", "lock_card", s, purpose="card_servicing",
                                         card_id="SYN-K-1001-01", idempotency_key="k" * 20,
                                         approval_token=self_approved)
        return no_approval, mismatched, four_eyes

    a, b, f = run_with_service(settings, sc)
    assert a["error"] == "approval_required"
    assert b["error"] == "unauthorized"
    assert f["error"] == "forbidden"


def test_checkpoints_are_encrypted_at_rest(settings):
    secret_phrase = "zebra quartz lantern"

    async def sc(svc, c):
        return await svc.start_turn(ivr(), message=f"What are the fees {secret_phrase}?", idempotency_key=key())

    run_with_service(settings, sc)
    cp_db = Path(settings.sqlite_path.replace(".db", ".checkpoints.db"))
    raw = cp_db.read_bytes() + (cp_db.with_suffix(".db-wal").read_bytes() if cp_db.with_suffix(".db-wal").exists() else b"")
    assert secret_phrase.encode() not in raw
    con = sqlite3.connect(cp_db)
    types = {r[0] for r in con.execute("SELECT type FROM checkpoints")}
    assert all("+aesgcm-v1" in t for t in types if t)


def test_paused_run_survives_restart_and_resumes_on_new_instance(settings):
    async def phase1():
        async with build_container(settings) as c:
            return await ContactCentreService(c).start_turn(ivr(), message="I lost my credit card",
                                                            idempotency_key=key())

    async def phase2(r1):
        async with build_container(settings) as c:  # brand-new process-equivalent: new connections, new graph
            pr = r1["pending_review"]
            return await ContactCentreService(c).submit_review(
                reviewer(), r1["run_id"], decision="approve", interrupt_id=pr["interrupt_id"],
                action_hash_expected=pr["action_hash"])

    r1 = asyncio.run(phase1())
    assert r1["status"] == RunStatus.AWAITING_REVIEW
    r2 = asyncio.run(phase2(r1))
    assert r2["status"] == "completed" and "locked" in r2["response"]


def test_audit_chain_detects_tampering(settings):
    async def sc(svc, c):
        await svc.start_turn(ivr(), message="What are the monthly fees?", idempotency_key=key())
        ok = c.audit.verify_chain()
        c.db.execute("UPDATE audit_log SET details=? WHERE seq=2", (json.dumps({"tampered": True}),))
        return ok, c.audit.verify_chain()

    ok, broken = run_with_service(settings, sc)
    assert ok["valid"] and ok["checked"] > 3
    assert broken == {"valid": False, "broken_at_seq": 2, "checked": 1}


def test_audit_details_are_redacted(settings):
    async def sc(svc, c):
        c.audit.append("test_event", "tester", None, note="email alex@example.com card 4111111111111111")
        return c.audit.events(limit=1)[0]["details"]["note"]

    note = run_with_service(settings, sc)
    assert "alex@example.com" not in note and "4111111111111111" not in note
