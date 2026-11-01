"""Schema-validated LLM calls with bounded correction retries and timeouts."""

from __future__ import annotations

import json
import re
import time
from typing import Literal, TypeVar

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, HumanMessage
from pydantic import BaseModel, Field, ValidationError

from ..resilience import call_with_resilience
from ..telemetry import METRICS, SpanKind, span

T = TypeVar("T", bound=BaseModel)

INTENTS = Literal[
    "card_lost_stolen", "transaction_dispute", "account_inquiry", "product_question", "complaint",
    "fraud_report", "human_agent_request", "vulnerable_support", "general",
]


class IntentResult(BaseModel):
    intent: INTENTS
    confidence: float = Field(ge=0, le=1)
    sentiment: Literal["negative", "neutral", "positive"] = "neutral"
    vulnerability: bool = False
    entities: dict = Field(default_factory=dict)
    rationale: str = ""


class DraftAnswer(BaseModel):
    answer: str = Field(min_length=1, max_length=2000)
    citations: list[str] = Field(default_factory=list)
    next_best_actions: list[str] = Field(default_factory=list)


class CallSummary(BaseModel):
    summary: str = Field(min_length=1, max_length=1500)
    disposition_code: str = Field(pattern=r"^[A-Z\-]{3,20}$")


class OutputValidationError(Exception):
    pass


def _extract_json(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(json)?|```$", "", text, flags=re.M).strip()
    return text


async def invoke_structured(
    model: BaseChatModel,
    messages: list[BaseMessage],
    schema: type[T],
    *,
    name: str,
    timeout_s: float,
    max_attempts: int = 3,
) -> T:
    """Call the model, parse + validate JSON; on failure send a correction
    message and retry (bounded). Transient model errors are retried by
    ``call_with_resilience``."""
    convo = list(messages)
    last_err: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        started = time.perf_counter()
        with span(f"llm.{name}", SpanKind.LLM, **{"llm.attempt": attempt, "llm.schema": schema.__name__}):
            msg = await call_with_resilience(lambda c=convo: model.ainvoke(c), timeout_s=timeout_s, max_retries=1)
        METRICS.observe(f"llm_latency_s.{name}", time.perf_counter() - started)
        raw = msg.content if isinstance(msg.content, str) else json.dumps(msg.content)
        try:
            return schema.model_validate_json(_extract_json(raw))
        except (ValidationError, ValueError) as e:
            last_err = e
            METRICS.inc("llm_output_invalid_total", task=name)
            convo = convo + [
                msg,
                HumanMessage(
                    content="Correction: your previous reply was not valid JSON for the required schema. "
                    f"Reply with ONLY a JSON object matching: {json.dumps(schema.model_json_schema())[:1500]}"
                ),
            ]
    raise OutputValidationError(f"{name}: model output failed validation after {max_attempts} attempts: {last_err}")
