"""Microsoft Foundry (Azure AI Foundry) project integration via the
``azure-ai-projects`` SDK.

Used for:
  * resolving the Azure OpenAI endpoint attached to the project;
  * discovering the project's Azure AI Search connection (RAG);
  * fetching the Application Insights connection string so OpenTelemetry
    traces land in the Foundry project's tracing view;
  * (evals/foundry_eval.py) running Foundry evaluations.

API surface targets azure-ai-projects 1.x; confirm method names against the
SDK version approved in your environment.
"""

from __future__ import annotations

from functools import lru_cache

from ..config import Settings


@lru_cache(maxsize=1)
def project_client(endpoint: str):
    from azure.ai.projects import AIProjectClient
    from azure.identity import DefaultAzureCredential

    return AIProjectClient(endpoint=endpoint, credential=DefaultAzureCredential())


def _require(settings: Settings) -> str:
    if not settings.foundry_project_endpoint:
        raise RuntimeError("AZURE_AI_FOUNDRY_PROJECT_ENDPOINT is not configured")
    return settings.foundry_project_endpoint


def resolve_openai_endpoint(settings: Settings) -> str:
    """Project endpoint looks like https://<resource>.services.ai.azure.com/api/projects/<project>;
    the Azure OpenAI inference endpoint is the resource root."""
    endpoint = _require(settings)
    return endpoint.split("/api/projects/")[0]


def app_insights_connection_string(settings: Settings) -> str | None:
    try:
        return project_client(_require(settings)).telemetry.get_application_insights_connection_string()
    except Exception:  # tracing must never take the service down
        return None


def search_endpoint(settings: Settings) -> str | None:
    from azure.ai.projects.models import ConnectionType

    conn = project_client(_require(settings)).connections.get_default(ConnectionType.AZURE_AI_SEARCH)
    return getattr(conn, "target", None)
