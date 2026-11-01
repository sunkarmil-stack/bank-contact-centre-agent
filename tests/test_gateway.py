"""API gateway policies (upstream replaced by a recording stub) and the agent API's
ingress check."""

import asyncio
import dataclasses

import httpx
import pytest
from fastapi.testclient import TestClient

from ccagent.secrets import build_secret_provider
from ccagent.security.auth import DevTokenValidator, Role
from ccagent.security.service_tokens import LocalServiceTokens


class Upstream:
    """Records what the gateway forwards; can simulate outages."""

    def __init__(self):
        self.seen: list[httpx.Request] = []
        self.mode = "ok"

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.mode == "down":
            raise httpx.ConnectError("refused", request=request)
        if self.mode == "slow":
            raise httpx.ReadTimeout("timeout", request=request)
        self.seen.append(request)
        return httpx.Response(200, json={"ok": True, "path": request.url.path}, headers={"Connection": "close"})


@pytest.fixture
def gw(settings, monkeypatch):
    monkeypatch.setenv("GATEWAY_RATE_LIMIT_PER_MINUTE", "1000")
    from services.gateway.app import create_app

    up = Upstream()
    secrets = build_secret_provider(settings)
    dev = DevTokenValidator(settings, secrets)
    with TestClient(create_app(settings, transport=httpx.MockTransport(up))) as c:
        yield c, up, dev


def bearer(dev, roles=(Role.CHANNEL,), sub="ivr-svc"):
    return {"Authorization": "Bearer " + dev.mint(sub, list(roles), customer_ref="SYN-C-1001", cust_auth_level=1)}


def test_edge_authentication(gw):
    c, up, dev = gw
    assert c.post("/v1/interactions", json={"message": "hi"}).status_code == 401
    assert c.post("/v1/interactions", json={}, headers={"Authorization": "Bearer junk"}).status_code == 401
    assert up.seen == []  # nothing reached the agent
    r = c.post("/v1/interactions", json={"message": "hi"}, headers=bearer(dev))
    assert r.status_code == 200 and r.headers["X-Upstream"] == "agent-api" and "X-Gateway-Latency-Ms" in r.headers


def test_public_routes_and_deny_by_default(gw):
    c, up, _ = gw
    assert c.get("/console").status_code == 200
    assert c.get("/admin/secret").status_code == 404
    assert c.get("/gateway/routes").json()["routes"][0]["auth_required"] is True


def test_header_hygiene_and_ingress_token(gw, settings):
    c, up, dev = gw
    spoofed = {"X-Delegation-Token": "forged", "X-Approval-Token": "forged", "X-Gateway-Token": "forged",
               "X-Forwarded-For": "6.6.6.6", "X-Correlation-Id": "abc12345-cid"}
    c.post("/v1/interactions", json={"message": "hi"}, headers=bearer(dev) | spoofed)
    h = up.seen[-1].headers
    assert "x-delegation-token" not in h and "x-approval-token" not in h
    assert h["x-forwarded-for"] != "6.6.6.6"
    assert h["x-correlation-id"] == "abc12345-cid" and h["x-gateway-route"] == "agent-api"
    from ccagent.security.service_tokens import ServiceTokenVerifier

    caller = ServiceTokenVerifier("local", build_secret_provider(settings), "agent-api").verify(
        "Bearer " + h["x-gateway-token"], "api.ingress")
    assert caller.name == "api-gateway"


def test_size_limit_and_upstream_failures(gw):
    c, up, dev = gw
    big = c.post("/v1/interactions", content=b"x" * 20000,
                 headers=bearer(dev) | {"content-type": "application/json"})
    assert big.status_code == 413
    up.mode = "down"
    assert c.get("/v1/runs/x", headers=bearer(dev)).json()["error"] == "upstream_unavailable"
    up.mode = "slow"
    assert c.get("/v1/runs/x", headers=bearer(dev)).status_code == 504


def test_rate_limit_per_principal(settings, monkeypatch):
    monkeypatch.setenv("GATEWAY_RATE_LIMIT_PER_MINUTE", "4")
    from services.gateway.app import create_app

    dev = DevTokenValidator(settings, build_secret_provider(settings))
    with TestClient(create_app(settings, transport=httpx.MockTransport(Upstream()))) as c:
        codes = [c.get("/v1/ops/kpis", headers=bearer(dev, sub="busy")).status_code for _ in range(6)]
        other = c.get("/v1/ops/kpis", headers=bearer(dev, sub="someone-else")).status_code
    assert 429 in codes and other == 200


def test_gateway_metrics_require_supervisor(gw):
    c, _, dev = gw
    c.get("/v1/ops/kpis", headers=bearer(dev))
    assert c.get("/gateway/metrics", headers=bearer(dev)).status_code == 403
    m = c.get("/gateway/metrics", headers=bearer(dev, roles=(Role.SUPERVISOR,), sub="sup")).json()
    assert m["routes"]["agent-api"]["requests"] >= 1


def test_agent_api_refuses_traffic_that_bypassed_the_gateway(settings):
    from ccagent.api.app import create_app

    s = dataclasses.replace(settings, require_gateway=True)
    secrets = build_secret_provider(s)
    dev = DevTokenValidator(s, secrets)
    sup = {"Authorization": "Bearer " + dev.mint("sup", [Role.SUPERVISOR])}
    ingress = asyncio.run(LocalServiceTokens(secrets, "api-gateway").token_for("agent-api"))
    forged = asyncio.run(LocalServiceTokens(secrets, "agent-api").token_for("agent-api"))  # no api.ingress right
    with TestClient(create_app(s)) as c:
        assert c.get("/v1/ops/kpis", headers=sup).json()["error"] == "gateway_required"
        assert c.get("/v1/ops/kpis", headers=sup | {"X-Gateway-Token": forged}).status_code == 403
        assert c.get("/v1/ops/kpis", headers=sup | {"X-Gateway-Token": ingress}).status_code == 200
        assert c.get("/healthz").status_code == 200  # health stays reachable for the platform
