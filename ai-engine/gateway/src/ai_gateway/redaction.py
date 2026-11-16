"""Redaction before anything reaches a model (threat model LLM02).

Secrets are always removed, for every provider including mock. Personal data (email
addresses, phone numbers, IPv4 addresses) is removed for any non-mock provider when the
tenant policy asks for it (the default). Redaction is one-way: nothing maps placeholders back.
"""

from __future__ import annotations

import re

SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(nss|nsk|nsc|whs)_[A-Za-z0-9_\-]{8,}"), "[secret]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer [secret]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S+"), r"\1=[secret]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[aws-access-key]"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{10,}"), "[secret]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[private-key]"),
]

PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[email]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[ip]"),
    (re.compile(r"(?<!\w)\+?\d[\d \-()]{8,}\d(?!\w)"), "[phone]"),
]


def redact(text: str, *, pii: bool) -> tuple[str, int]:
    count = 0
    for pattern, repl in SECRET_PATTERNS + (PII_PATTERNS if pii else []):
        text, n = pattern.subn(repl, text)
        count += n
    return text, count
