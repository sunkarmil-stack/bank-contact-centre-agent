"""Composition root: wires adapters according to configuration."""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from .agents.graph import GraphDeps, build_graph
from .agents.tool_gateway import MCPToolGateway
from .config import Settings
from .integrations.cases import HttpCaseService, LocalCaseService
from .integrations.customer import HttpCustomerService, MockCustomerService
from .integrations.knowledge import AzureAISearchRetriever, LocalBM25Retriever
from .llm.factory import build_chat_model
from .mcp_server.server import ToolServices, build_mcp_server
from .persistence.audit import AuditLog
from .persistence.checkpoint import open_memory
from .persistence.db import Database
from .persistence.runs import RunRepository
from .secrets import build_secret_provider
from .security.auth import build_validator
from .security.ratelimit import TokenBucketLimiter
from .security.service_tokens import build_service_tokens
from .security.tokens import InternalTokens

DATA = Path(__file__).resolve().parent.parent / "data"


@dataclass
class Container:
    settings: Settings
    secrets: object
    db: Database
    audit: AuditLog
    runs: RunRepository
    cases: LocalCaseService
    customers: object
    retriever: object
    tokens: InternalTokens
    mcp_server: object
    gateway: MCPToolGateway
    model: object
    graph: object
    store: object
    checkpointer: object
    validator: object
    limiter: TokenBucketLimiter


def open_database(settings: Settings, secrets, path: str | None = None) -> Database:
    if settings.persistence == "postgres":
        return Database(secrets.get("postgres-dsn"), kind="postgres")
    return Database(path or settings.sqlite_path)


def open_audit(settings: Settings, secrets, service: str, default_db: Database) -> AuditLog:
    """One shared, hash-chained audit store for every service (the same PostgreSQL in prod,
    a shared WAL-mode SQLite file locally) so a run's trail is complete end to end."""
    if (settings.persistence == "postgres" or not settings.audit_db_path
            or settings.audit_db_path == settings.sqlite_path):
        return AuditLog(default_db, service=service)
    return AuditLog(Database(settings.audit_db_path), service=service)


def build_tool_backends(settings: Settings, secrets, db: Database, audit: AuditLog):
    """Systems of record behind the MCP tools: in-process (single-process demo) or the
    Customer / Case microservices over HTTP with workload identity."""
    svc_tokens = build_service_tokens(settings.service_auth, secrets, caller="mcp-tool-service")
    if settings.customer_service == "http":
        customers = HttpCustomerService(settings.customer_api_base_url or "", svc_tokens,
                                        timeout_s=settings.tool_timeout_s)
    else:
        customers = MockCustomerService(DATA / "synthetic_customers.json", db, audit)
    if settings.case_service == "http":
        cases = HttpCaseService(settings.case_api_base_url or "", svc_tokens, timeout_s=settings.tool_timeout_s)
    else:
        cases = LocalCaseService(db, audit)
    if settings.retriever == "azure_ai_search":
        retriever = AzureAISearchRetriever(endpoint=settings.azure_search_endpoint or "",
                                           index=settings.azure_search_index, k=settings.retrieval_top_k,
                                           semantic_config=settings.azure_search_semantic_config)
    else:
        retriever = LocalBM25Retriever(kb_path=DATA / "knowledge_base.json", k=settings.retrieval_top_k)
    return customers, cases, retriever


@asynccontextmanager
async def build_container(settings: Settings | None = None, model=None):
    settings = settings or Settings.from_env()
    settings.validate_for_environment()
    secrets = build_secret_provider(settings)

    db = open_database(settings, secrets)
    audit = open_audit(settings, secrets, "agent-api", db)
    runs = RunRepository(db)
    tokens = InternalTokens(secrets)

    if settings.mcp_mode == "http":
        # Tools run in the separate MCP tool service; this process only needs case listing for KPIs.
        mcp_server, customers, retriever = None, None, None
        cases = (HttpCaseService(settings.case_api_base_url or "",
                                 build_service_tokens(settings.service_auth, secrets, caller="agent-api"),
                                 timeout_s=settings.tool_timeout_s)
                 if settings.case_service == "http" else LocalCaseService(db, audit))
        target = settings.mcp_url
    else:
        customers, cases, retriever = build_tool_backends(settings, secrets, db, audit)
        mcp_server = build_mcp_server(ToolServices(customers, cases, retriever, tokens, audit))
        target = mcp_server

    gateway = MCPToolGateway(target, tokens, audit, timeout_s=settings.tool_timeout_s, max_retries=settings.max_retries)
    model = model or build_chat_model(settings)

    async with open_memory(settings, secrets) as (checkpointer, store):
        graph = build_graph(GraphDeps(settings, model, gateway, audit)).compile(checkpointer=checkpointer, store=store)
        yield Container(
            settings=settings, secrets=secrets, db=db, audit=audit, runs=runs, cases=cases, customers=customers,
            retriever=retriever, tokens=tokens, mcp_server=mcp_server, gateway=gateway, model=model, graph=graph,
            store=store, checkpointer=checkpointer, validator=build_validator(settings, secrets),
            limiter=TokenBucketLimiter(settings.rate_limit_per_minute),
        )
    db.close()
