"""PII / PCI detection and redaction.

Applied at every trust boundary: inbound utterances (before the LLM sees them),
log records, LangSmith/OTel span payloads, long-term memory writes and
outbound responses.

Production note: pair this deterministic layer with an enterprise DLP service
(e.g. Microsoft Purview / Azure AI Language PII detection). Regex alone is a
floor, not a ceiling.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


@dataclass(frozen=True)
class PIIFinding:
    kind: str
    start: int
    end: int


_CARD = re.compile(r"(?<![A-Za-z0-9])(?:\d[ -]?){13,19}(?![A-Za-z0-9])")
_SIN = re.compile(r"(?<![A-Za-z0-9])\d{3}[ -]?\d{3}[ -]?\d{3}(?![A-Za-z0-9])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<![A-Za-z0-9])(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}(?![A-Za-z0-9])")
_POSTAL = re.compile(r"\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z][ -]?\d[ABCEGHJ-NPRSTV-Z]\d\b", re.I)
_ACCOUNT = re.compile(r"\b(?:acct|account|a/c)\s*(?:no\.?|number|#)?\s*[:#]?\s*(\d{5,12})\b", re.I)
_DOB = re.compile(r"\b(?:dob|date of birth|born)\s*[:]?\s*\d{4}-\d{2}-\d{2}\b", re.I)


def find_pii(text: str) -> list[PIIFinding]:
    findings: list[PIIFinding] = []
    for m in _CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            findings.append(PIIFinding("CARD", m.start(), m.end()))
    for m in _SIN.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if len(digits) == 9 and digits[0] not in "08" and _luhn_ok(digits):
            findings.append(PIIFinding("SIN", m.start(), m.end()))
    for kind, rx in (("EMAIL", _EMAIL), ("PHONE", _PHONE), ("POSTAL_CODE", _POSTAL), ("DOB", _DOB)):
        findings.extend(PIIFinding(kind, m.start(), m.end()) for m in rx.finditer(text))
    for m in _ACCOUNT.finditer(text):
        findings.append(PIIFinding("ACCOUNT", m.start(1), m.end(1)))
    # resolve overlaps: keep earliest/longest span
    findings.sort(key=lambda f: (f.start, -(f.end - f.start)))
    resolved: list[PIIFinding] = []
    last_end = -1
    for f in findings:
        if f.start >= last_end:
            resolved.append(f)
            last_end = f.end
    return resolved


def redact(text: str) -> tuple[str, list[str]]:
    """Return (redacted_text, kinds_found)."""
    if not text:
        return text, []
    findings = find_pii(text)
    if not findings:
        return text, []
    out, cursor = [], 0
    for f in findings:
        out.append(text[cursor:f.start])
        out.append(f"[REDACTED_{f.kind}]")
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out), sorted({f.kind for f in findings})


def redact_obj(obj):
    """Recursively redact strings inside dicts/lists (for logs, spans, memory)."""
    if isinstance(obj, str):
        return redact(obj)[0]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(redact_obj(v) for v in obj)
    return obj


def contains_pii(text: str) -> bool:
    return bool(find_pii(text or ""))
