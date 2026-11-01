"""Runtime configuration.

All settings come from environment variables (12-factor). Secrets are NOT read
here — they are resolved through ``ccagent.secrets`` so that production can use
Azure Key Vault without code changes.

``Settings.validate_for_environment`` enforces "production guard rails": the
service refuses to start in ``prod`` with any local/mock component configured.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    return value if value not in (None, "") else default


def _int(name: str, default: int) -> int:
    return int(_env(name, str(default)))  # type: ignore[arg-type]


def _float(name: str, default: float) -> float:
    return float(_env(name, str(default)))  # type: ignore[arg-type]


class ConfigurationError(RuntimeError):
    """Raised when configuration is unsafe for the target environment."""


@dataclass(frozen=True)
class Settings:
    # --- environment ---------------------------------------------------
    env: str = "local"  # local | dev | test | prod
    data_dir: Path = Path("./.data")

    # --- model provider ------------------------------------------------
    llm_provider: str = "offline"  # offline | azure_foundry
    foundry_project_endpoint: str | None = None
    azure_openai_endpoint: str | None = None
    azure_openai_deployment: str = "gpt-4o"
    azure_openai_api_version: str = "2024-10-21"

    # --- retrieval -----------------------------------------------------
    retriever: str = "local"  # local | azure_ai_search
    azure_search_endpoint: str | None = None
    azure_search_index: str = "contact-centre-kb"
    azure_search_semantic_config: str | None = "default"
    retrieval_top_k: int = 4

    # --- enterprise systems --------------------------------------------
    customer_service: str = "mock"  # mock | http
    customer_api_base_url: str | None = None
    case_service: str = "local"  # local | http
    case_api_base_url: str | None = None
    service_auth: str = "local"  # local (HS256 dev tokens) | azure (managed identity + Entra)
    mcp_mode: str = "inprocess"  # inprocess | http
    mcp_url: str | None = None

    # --- persistence ---------------------------------------------------
    persistence: str = "sqlite"  # sqlite | postgres
    sqlite_path: str = "./.data/ccagent.db"
    audit_db_path: str | None = None  # shared audit store; defaults to sqlite_path
    memory_ttl_minutes: float = 60 * 24 * 90  # 90 days long-term memory retention
    short_term_max_messages: int = 20

    # --- identity --------------------------------------------------------
    auth_mode: str = "dev"  # dev | entra
    entra_tenant_id: str | None = None
    entra_audience: str | None = None
    dev_issuer: str = "ccagent-dev"
    dev_audience: str = "ccagent-api"

    # --- resilience ------------------------------------------------------
    llm_timeout_s: float = 20.0
    tool_timeout_s: float = 8.0
    max_retries: int = 2
    graph_timeout_s: float = 60.0

    # --- rate limiting / request limits ---------------------------------
    rate_limit_per_minute: int = 60
    max_message_chars: int = 2000

    # --- business policy ------------------------------------------------
    dispute_review_threshold_cad: float = 500.0
    intent_confidence_floor: float = 0.55
    complaint_ack_sla_hours: int = 48

    # --- telemetry -------------------------------------------------------
    otel_exporter: str = "none"  # none | console | otlp | azure_monitor
    otel_service_name: str = "ccagent-api"

    require_gateway: bool = False  # /v1 traffic must carry the gateway's ingress token

    allowed_origins: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_env(cls) -> Settings:
        data_dir = Path(_env("CCAGENT_DATA_DIR", "./.data"))  # type: ignore[arg-type]
        return cls(
            env=_env("CCAGENT_ENV", "local"),  # type: ignore[arg-type]
            data_dir=data_dir,
            llm_provider=_env("CCAGENT_LLM_PROVIDER", "offline"),  # type: ignore[arg-type]
            foundry_project_endpoint=_env("AZURE_AI_FOUNDRY_PROJECT_ENDPOINT"),
            azure_openai_endpoint=_env("AZURE_OPENAI_ENDPOINT"),
            azure_openai_deployment=_env("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),  # type: ignore[arg-type]
            azure_openai_api_version=_env("AZURE_OPENAI_API_VERSION", "2024-10-21"),  # type: ignore[arg-type]
            retriever=_env("CCAGENT_RETRIEVER", "local"),  # type: ignore[arg-type]
            azure_search_endpoint=_env("AZURE_SEARCH_ENDPOINT"),
            azure_search_index=_env("AZURE_SEARCH_INDEX", "contact-centre-kb"),  # type: ignore[arg-type]
            azure_search_semantic_config=_env("AZURE_SEARCH_SEMANTIC_CONFIG", "default"),
            retrieval_top_k=_int("CCAGENT_RETRIEVAL_TOP_K", 4),
            customer_service=_env("CCAGENT_CUSTOMER_SERVICE", "mock"),  # type: ignore[arg-type]
            customer_api_base_url=_env("CUSTOMER_API_BASE_URL"),
            case_service=_env("CCAGENT_CASE_SERVICE", "local"),  # type: ignore[arg-type]
            case_api_base_url=_env("CASE_API_BASE_URL"),
            service_auth=_env("CCAGENT_SERVICE_AUTH", "local"),  # type: ignore[arg-type]
            mcp_mode=_env("CCAGENT_MCP_MODE", "inprocess"),  # type: ignore[arg-type]
            mcp_url=_env("CCAGENT_MCP_URL"),
            persistence=_env("CCAGENT_PERSISTENCE", "sqlite"),  # type: ignore[arg-type]
            sqlite_path=_env("CCAGENT_SQLITE_PATH", str(data_dir / "ccagent.db")),  # type: ignore[arg-type]
            audit_db_path=_env("CCAGENT_AUDIT_DB_PATH"),
            memory_ttl_minutes=_float("CCAGENT_MEMORY_TTL_MINUTES", 60 * 24 * 90),
            short_term_max_messages=_int("CCAGENT_SHORT_TERM_MAX_MESSAGES", 20),
            auth_mode=_env("CCAGENT_AUTH_MODE", "dev"),  # type: ignore[arg-type]
            entra_tenant_id=_env("ENTRA_TENANT_ID"),
            entra_audience=_env("ENTRA_AUDIENCE"),
            llm_timeout_s=_float("CCAGENT_LLM_TIMEOUT_S", 20.0),
            tool_timeout_s=_float("CCAGENT_TOOL_TIMEOUT_S", 8.0),
            max_retries=_int("CCAGENT_MAX_RETRIES", 2),
            graph_timeout_s=_float("CCAGENT_GRAPH_TIMEOUT_S", 60.0),
            rate_limit_per_minute=_int("CCAGENT_RATE_LIMIT_PER_MINUTE", 60),
            max_message_chars=_int("CCAGENT_MAX_MESSAGE_CHARS", 2000),
            dispute_review_threshold_cad=_float("CCAGENT_DISPUTE_REVIEW_THRESHOLD_CAD", 500.0),
            intent_confidence_floor=_float("CCAGENT_INTENT_CONFIDENCE_FLOOR", 0.55),
            complaint_ack_sla_hours=_int("CCAGENT_COMPLAINT_ACK_SLA_HOURS", 48),
            otel_exporter=_env("CCAGENT_OTEL_EXPORTER", "none"),  # type: ignore[arg-type]
            otel_service_name=_env("OTEL_SERVICE_NAME", "ccagent-api"),  # type: ignore[arg-type]
            require_gateway=(_env("CCAGENT_REQUIRE_GATEWAY", "false") or "").lower() == "true",
            allowed_origins=tuple(
                o.strip() for o in (_env("CCAGENT_ALLOWED_ORIGINS", "") or "").split(",") if o.strip()
            ),
        )

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    def validate_for_environment(self) -> None:
        """Fail fast if a non-production component is configured in prod."""
        if not self.is_prod:
            return
        problems: list[str] = []
        if self.llm_provider == "offline":
            problems.append("CCAGENT_LLM_PROVIDER=offline is not allowed in prod")
        if self.auth_mode != "entra":
            problems.append("CCAGENT_AUTH_MODE must be 'entra' in prod")
        if self.persistence != "postgres":
            problems.append("CCAGENT_PERSISTENCE must be 'postgres' in prod (durable, shared across workers)")
        if self.customer_service == "mock":
            problems.append("CCAGENT_CUSTOMER_SERVICE=mock is not allowed in prod")
        if self.retriever == "local":
            problems.append("CCAGENT_RETRIEVER must be 'azure_ai_search' in prod")
        if self.case_service == "local":
            problems.append("CCAGENT_CASE_SERVICE must be 'http' in prod")
        if self.service_auth != "azure":
            problems.append("CCAGENT_SERVICE_AUTH must be 'azure' (managed identity) in prod")
        if self.otel_exporter == "none":
            problems.append("Telemetry exporter must be configured in prod")
        if problems:
            raise ConfigurationError("; ".join(problems))
