"""Guardrails: input screening, indirect-injection filtering of retrieved
content, and output validation.

Defense in depth (see docs/04-security-governance.md):
  1. Deterministic screening here (cheap, auditable, always on).
  2. Optional Azure AI Content Safety Prompt Shields (``PromptShieldsClient``).
  3. Structural defenses: the LLM never chooses identities, customer IDs or
     approvals — those are bound by the orchestrator/tool gateway — and
     high-risk actions always go through human review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .pii import contains_pii

_INJECTION_PATTERNS = [
    r"ignore (all |any )?(the )?(previous|prior|above) (instructions|rules|prompts?)",
    r"disregard (all |the )?(previous|prior|above|system)",
    r"(reveal|print|show|repeat) (me )?(your|the) (system|hidden|developer) (prompt|instructions|message)",
    r"you are now (in )?(dan|developer mode|jailbreak|unrestricted)",
    r"\bact as (an? )?(admin|administrator|supervisor|system|root)\b",
    r"\bdeveloper mode\b",
    r"\bjailbreak\b",
    r"approve (this|the) (request|action|transaction) (yourself|automatically|without review)",
    r"(bypass|skip|disable) (the )?(verification|authentication|review|approval|guardrails?)",
    r"</?(system|assistant|tool)>",
    r"\bcustomer[_ ]?ref\s*[:=]",
    r"BEGIN (SYSTEM|ADMIN) (PROMPT|OVERRIDE)",
]
_INJECTION_RX = [re.compile(p, re.I) for p in _INJECTION_PATTERNS]

# Statements a bank contact-centre assistant must not make.
_PROHIBITED_OUTPUT = [
    (re.compile(r"\byou should (buy|sell|invest)\b", re.I), "investment_advice"),
    (re.compile(r"\b(guarantee|guaranteed)\b", re.I), "guarantee_language"),
    (re.compile(r"\byou will (definitely )?(be|get) refunded\b", re.I), "refund_promise"),
    (re.compile(r"\b(system prompt|developer message)\b", re.I), "prompt_leakage"),
    (re.compile(r"\byour (pin|password) is\b", re.I), "credential_disclosure"),
]


@dataclass
class GuardDecision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    risk_score: float = 0.0


def screen_input(text: str, max_chars: int) -> GuardDecision:
    reasons: list[str] = []
    score = 0.0
    if len(text) > max_chars:
        reasons.append("input_too_long")
        score = max(score, 0.6)
    hits = [rx.pattern for rx in _INJECTION_RX if rx.search(text)]
    if hits:
        reasons.append("prompt_injection_suspected")
        score = max(score, min(1.0, 0.7 + 0.1 * len(hits)))
    # long base64-ish blobs are a common smuggling vector
    if re.search(r"[A-Za-z0-9+/]{120,}={0,2}", text):
        reasons.append("encoded_payload_suspected")
        score = max(score, 0.7)
    return GuardDecision(allowed=score < 0.7, reasons=reasons, risk_score=score)


def filter_retrieved(chunks: list[dict]) -> tuple[list[dict], list[str]]:
    """Drop retrieved chunks that carry instructions (indirect prompt injection)."""
    kept, dropped = [], []
    for c in chunks:
        if any(rx.search(c.get("content", "")) for rx in _INJECTION_RX):
            dropped.append(c.get("doc_id", "?"))
        else:
            kept.append(c)
    return kept, dropped


def spotlight(chunks: list[dict]) -> str:
    """Wrap untrusted retrieved text in explicit data delimiters."""
    parts = []
    for c in chunks:
        parts.append(
            f"<<DOC id={c['doc_id']} title=\"{c.get('title', '')}\">>\n{c['content']}\n<<END DOC {c['doc_id']}>>"
        )
    return "\n".join(parts)


@dataclass
class OutputCheck:
    ok: bool
    violations: list[str] = field(default_factory=list)


def validate_output(
    answer: str,
    citations: list[str],
    allowed_doc_ids: set[str],
    requires_citation: bool,
    max_chars: int = 1500,
) -> OutputCheck:
    violations: list[str] = []
    if not answer or not answer.strip():
        violations.append("empty_answer")
    if len(answer) > max_chars:
        violations.append("answer_too_long")
    if contains_pii(answer):
        violations.append("pii_in_output")
    for rx, label in _PROHIBITED_OUTPUT:
        if rx.search(answer):
            violations.append(label)
    if requires_citation:
        if not citations:
            violations.append("missing_citation")
        elif not set(citations) <= allowed_doc_ids:
            violations.append("citation_not_in_retrieved_context")
    return OutputCheck(ok=not violations, violations=violations)


class PromptShieldsClient:
    """Optional: Azure AI Content Safety Prompt Shields (user + document attacks).

    POST {endpoint}/contentsafety/text:shieldPrompt?api-version=2024-09-01
    Authenticated with Entra ID (scope https://cognitiveservices.azure.com/.default).
    """

    def __init__(self, endpoint: str, timeout_s: float = 3.0) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.timeout_s = timeout_s

    def shield(self, user_prompt: str, documents: list[str]) -> bool:
        import httpx
        from azure.identity import DefaultAzureCredential

        token = DefaultAzureCredential().get_token("https://cognitiveservices.azure.com/.default").token
        r = httpx.post(
            f"{self.endpoint}/contentsafety/text:shieldPrompt",
            params={"api-version": "2024-09-01"},
            headers={"Authorization": f"Bearer {token}"},
            json={"userPrompt": user_prompt, "documents": documents},
            timeout=self.timeout_s,
        )
        r.raise_for_status()
        body = r.json()
        attacked = body.get("userPromptAnalysis", {}).get("attackDetected", False)
        attacked |= any(d.get("attackDetected") for d in body.get("documentsAnalysis", []))
        return not attacked
