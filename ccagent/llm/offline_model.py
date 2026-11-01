"""Deterministic offline chat model.

A real LangChain ``BaseChatModel`` so the agents exercise the exact same code
path (prompt → model.ainvoke → JSON → schema validation → retry) as with
Azure OpenAI in Microsoft Foundry — but with no network, no keys and fully
reproducible outputs for tests, demos and the CI evaluation gate.

It implements three prompt contracts, selected by the ``TASK:`` line in the
system prompt: ``classify_intent``, ``draft_answer`` and ``summarize``.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

_INTENT_RULES: list[tuple[str, list[tuple[str, float]]]] = [
    ("fraud_report", [(r"\bscam|scammed|fraud|hacked|someone (else )?(has|got) (access|into)|phish|account takeover", 1.0),
                      (r"didn'?t (make|authori[sz]e)|unauthori[sz]ed", 0.5)]),
    ("card_lost_stolen", [(r"\b(lost|stolen|misplaced|can'?t find)\b.*\bcard\b|\bcard\b.*\b(lost|stolen|missing)\b", 1.0),
                          (r"\b(lock|freeze|block)\b.*\bcard\b", 0.8)]),
    ("transaction_dispute", [(r"\bdispute|don'?t recogni[sz]e|charged twice|double charged|never (received|arrived)|refund\b", 1.0),
                             (r"\bcharge\b|\btransaction\b", 0.3)]),
    ("complaint", [(r"\bcomplain|complaint|unacceptable|terrible service|worst|file a grievance|ombuds", 1.0),
                   (r"\bfrustrat|angry|upset|disappointed\b", 0.4)]),
    ("human_agent_request", [(r"\b(speak|talk) (to|with) (a |an )?(human|person|agent|representative|someone)|\breal person\b", 1.0)]),
    ("account_inquiry", [(r"\bbalance|recent transactions|last (few )?transactions|statement|how much (money|do i have)", 1.0)]),
    ("product_question", [(r"\bfee|fees|monthly|travel|abroad|e-?transfer|interac|limit|waive|how (do|does|can)|what is", 0.7)]),
]

_NEG = re.compile(r"\b(angry|furious|terrible|unacceptable|ridiculous|worst|frustrat\w*|upset|disgusted|fed up)\b", re.I)
_POS = re.compile(r"\b(thanks|thank you|great|appreciate|perfect)\b", re.I)
_VULN = re.compile(r"\b(passed away|bereave\w*|died|funeral|hospital|terminal|lost my job|can'?t afford|"
                   r"financial hardship|confused|dementia)\b", re.I)


def classify(text: str) -> dict:
    scores: dict[str, float] = {}
    for intent, rules in _INTENT_RULES:
        s = sum(w for rx, w in rules if re.search(rx, text, re.I))
        if s:
            scores[intent] = s
    vulnerable = bool(_VULN.search(text))
    if scores:
        intent = max(scores, key=lambda k: scores[k])
        top = scores[intent]
        second = sorted(scores.values(), reverse=True)[1] if len(scores) > 1 else 0.0
        confidence = round(min(0.97, 0.55 + 0.3 * min(top, 1.0) + 0.15 * (top - second)), 2)
    else:
        intent, confidence = ("vulnerable_support", 0.8) if vulnerable else ("general", 0.4)
    if vulnerable and intent in ("general", "product_question"):
        intent, confidence = "vulnerable_support", 0.8
    sentiment = "negative" if _NEG.search(text) else ("positive" if _POS.search(text) else "neutral")
    entities: dict[str, Any] = {}
    if m := re.search(r"\b(SYN-T-\d{4})\b", text, re.I):
        entities["txn_id"] = m.group(1).upper()
    if m := re.search(r"\$\s?(\d+(?:\.\d{2})?)", text):
        entities["amount_cad"] = float(m.group(1))
    if m := re.search(r"ending (?:in )?(\d{4})", text, re.I):
        entities["card_last4"] = m.group(1)
    return {
        "intent": intent,
        "confidence": confidence,
        "sentiment": sentiment,
        "vulnerability": vulnerable,
        "entities": entities,
        "rationale": f"keyword match: {sorted(scores) or ['none']}",
    }


_DOC_RX = re.compile(r"<<DOC id=(\S+) title=\"([^\"]*)\">>\n(.*?)\n<<END DOC \1>>", re.S)


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]


def _overlap(a: str, b: str) -> int:
    ta = set(re.findall(r"[a-z]{4,}", a.lower()))
    tb = set(re.findall(r"[a-z]{4,}", b.lower()))
    return len(ta & tb)


def draft(system: str, user: str) -> dict:
    question = re.search(r"QUESTION:\s*(.*?)(?:\n[A-Z_]+:|\Z)", user, re.S)
    q = question.group(1).strip() if question else user
    facts_m = re.search(r"FACTS:\s*(.*?)(?:\n[A-Z_]+:|\Z)", user, re.S)
    facts = [f.strip("- ").strip() for f in (facts_m.group(1).splitlines() if facts_m else []) if f.strip("- ").strip()]
    docs = _DOC_RX.findall(user)
    parts: list[str] = []
    if facts and facts != ["none"]:
        parts.append(" ".join(f if f.endswith(".") else f + "." for f in facts))
    citations: list[str] = []
    if docs and facts and facts != ["none"]:
        # Facts are the answer; the top document is cited as the policy basis for them.
        citations.append(docs[0][0])
    elif docs:
        ranked = []
        for rank, (doc_id, _title, content) in enumerate(docs[:2]):
            for i, sent in enumerate(_sentences(content)):
                if sent.lower().startswith(("agents ", "agent ")):
                    continue  # internal instructions are not read out to clients
                ranked.append((_overlap(q, sent) - 0.01 * i - 1.5 * rank, doc_id, sent))
        ranked.sort(key=lambda x: x[0], reverse=True)
        chosen = []
        for score, doc_id, sent in ranked:
            if len(chosen) >= 3:
                break
            if score >= 0 or not chosen:
                chosen.append((doc_id, sent))
        for doc_id, _ in chosen:
            if doc_id not in citations:
                citations.append(doc_id)
        if chosen:
            parts.append(" ".join(s for _, s in chosen))
    if not parts:
        parts.append("I want to make sure you get accurate help, so I'll connect you with a colleague who can assist.")
    answer = " ".join(parts)
    if citations:
        answer += " (Source: " + ", ".join(citations) + ")"
    nba = []
    if "dispute" in user.lower():
        nba.append("Offer to open a dispute for unrecognised transactions")
    if "lock" in user.lower():
        nba.append("Confirm the replacement card mailing address on file")
    return {"answer": answer, "citations": citations, "next_best_actions": nba}


_SUMMARY_TOPIC = {
    "card_lost_stolen": "reported a lost or stolen card", "transaction_dispute": "asked to dispute a transaction",
    "complaint": "raised a complaint", "fraud_report": "reported a suspected scam or fraud",
    "account_inquiry": "asked about their account balance and recent activity",
    "product_question": "asked a product or policy question", "human_agent_request": "asked to speak with a person",
    "vulnerable_support": "shared difficult personal circumstances", "blocked": "sent a message blocked by the safety screen",
}


def summarize(user: str) -> dict:
    intent = re.search(r"INTENT:\s*(\S+)", user)
    outcome = re.search(r"OUTCOME:\s*(.*)", user)
    case = re.search(r"CASE:\s*(\S+)", user)
    i = intent.group(1) if intent else "general"
    o = outcome.group(1).strip() if outcome else "handled"
    disposition = {
        "card_lost_stolen": "CARD-LOCK", "transaction_dispute": "DISPUTE", "complaint": "COMPLAINT",
        "fraud_report": "FRAUD-XFER", "account_inquiry": "ACCT-INFO", "product_question": "INFO-PROVIDED",
        "human_agent_request": "XFER-AGENT", "vulnerable_support": "VULN-XFER", "blocked": "BLOCKED",
    }.get(i, "GENERAL")
    text = f"Client {_SUMMARY_TOPIC.get(i, 'made a general enquiry')}. Outcome: {o}."
    if case and case.group(1) != "none":
        text += f" Case {case.group(1)}."
    return {"summary": text, "disposition_code": disposition}


class OfflineCallCentreModel(BaseChatModel):
    """Deterministic, network-free stand-in for an Azure OpenAI deployment."""

    fault_mode: str | None = None  # e.g. "malformed_once" to test output validation + retry
    _faults_emitted: int = 0

    @property
    def _llm_type(self) -> str:
        return "offline-call-centre"

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs) -> ChatResult:
        system = next((m.content for m in messages if m.type == "system"), "")
        user = "\n".join(str(m.content) for m in messages if m.type in ("human", "user"))
        last_user = next((str(m.content) for m in reversed(messages)
                          if m.type in ("human", "user") and not str(m.content).startswith("Correction:")), "")
        fault = self.fault_mode or os.getenv("CCAGENT_OFFLINE_FAULT")
        if fault == "malformed_once" and self._faults_emitted == 0 and "correction" not in user.lower():
            self._faults_emitted = 1
            content = "Sure! Here is the answer: {not valid json"
        elif "TASK: classify_intent" in system:
            content = json.dumps(classify(last_user.split("UTTERANCE:", 1)[-1]))
        elif "TASK: draft_answer" in system:
            content = json.dumps(draft(system, last_user))
        elif "TASK: summarize" in system:
            content = json.dumps(summarize(last_user))
        else:
            content = json.dumps({"answer": "I can help with banking questions."})
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=content))])
