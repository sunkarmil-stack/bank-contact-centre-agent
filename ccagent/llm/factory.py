"""Model factory: offline (deterministic) or Azure OpenAI via Microsoft Foundry.

Foundry path:
  * Authentication with Entra ID (``DefaultAzureCredential`` → managed identity
    in Azure) — no API keys.
  * Endpoint discovered from the Foundry project (``AIProjectClient``) if not
    configured explicitly.
  * ``temperature=0`` + JSON response format for deterministic, parseable
    outputs; client-side retries disabled because retries are governed by
    ``ccagent.resilience`` (bounded, observable).
"""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel

from ..config import Settings
from .offline_model import OfflineCallCentreModel


def build_chat_model(settings: Settings) -> BaseChatModel:
    if settings.llm_provider == "offline":
        return OfflineCallCentreModel()
    if settings.llm_provider == "azure_foundry":
        from azure.identity import DefaultAzureCredential, get_bearer_token_provider
        from langchain_openai import AzureChatOpenAI

        from .foundry import resolve_openai_endpoint

        endpoint = settings.azure_openai_endpoint or resolve_openai_endpoint(settings)
        model = AzureChatOpenAI(
            azure_endpoint=endpoint,
            azure_deployment=settings.azure_openai_deployment,
            api_version=settings.azure_openai_api_version,
            azure_ad_token_provider=get_bearer_token_provider(
                DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
            ),
            temperature=0,
            timeout=settings.llm_timeout_s,
            max_retries=0,
        )
        return model.bind(response_format={"type": "json_object"})  # type: ignore[return-value]
    raise ValueError(f"unknown llm provider {settings.llm_provider}")
