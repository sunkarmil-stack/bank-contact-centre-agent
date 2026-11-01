import asyncio
import dataclasses
import uuid

import pytest

from ccagent.config import Settings
from ccagent.container import build_container
from ccagent.security.auth import Principal, Role
from ccagent.service import ContactCentreService


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.delenv("CCAGENT_OFFLINE_FAULT", raising=False)
    monkeypatch.setenv("LANGSMITH_TRACING", "false")
    base = Settings.from_env()
    return dataclasses.replace(
        base,
        env="test",
        data_dir=tmp_path,
        sqlite_path=str(tmp_path / "ccagent.db"),
        llm_provider="offline",
        auth_mode="dev",
        persistence="sqlite",
        rate_limit_per_minute=10_000,
        otel_exporter="none",
    )


def ivr(customer_ref="SYN-C-1001", level=1, sub="ivr-svc"):
    return Principal(sub=sub, roles=frozenset({Role.CHANNEL}), channel="ivr", customer_ref=customer_ref,
                     cust_auth_level=level)


def reviewer(sub="reviewer-007"):
    return Principal(sub=sub, roles=frozenset({Role.REVIEWER}))


def key():
    return uuid.uuid4().hex


def run_with_service(settings, scenario, model=None):
    async def _go():
        async with build_container(settings, model=model) as c:
            return await scenario(ContactCentreService(c), c)

    return asyncio.run(_go())
