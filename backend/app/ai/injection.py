"""Prompt-injection heuristics (threat model LLM01).

Used twice: to flag evidence that contains instruction-like text (shown to the analyst and passed
to the model as ``suspicious``), and to reject model output that repeats or obeys such text. A
heuristic, not a guarantee: the real defences are that evidence is data, the model has no tools,
and every claim must cite evidence (see validator.py).
"""

from __future__ import annotations

import re

PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.I)
    for p in (
        r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|any|your)\b.{0,20}"
        r"\b(instructions?|rules?|prompts?|guidelines?|directions?)\b",
        r"\byou are now\b|\bact as (an?|the)\b|\bpretend (to be|you are)\b|\bnew persona\b",
        r"\b(system|developer) (prompt|message|mode)\b|\breveal (your|the) (prompt|instructions|system)\b",
        r"<!--|-->|</?\s*(system|assistant|user|instructions?)\s*>",
        r"^\s*(assistant|system)\s*:",
        r"\b(approve|authori[sz]e)\b.{0,30}\b(every|all|any|pending)\b.{0,30}\b(actions?|requests?|changes?)\b",
        r"\bmark (this|it|the alert|all alerts?)\b.{0,20}\b(as )?(false positive|benign|resolved|closed)\b",
        r"\b(close|resolve|delete|suppress)\b.{0,10}\b(all|every)\b.{0,20}\b(alerts?|incidents?|cases?)\b",
        r"\b(exfiltrate|send (the|all) (data|secrets|credentials) to)\b",
        r"\bdo not (tell|inform|alert) (the )?(analyst|user|human|operator)s?\b",
    )
)


def is_suspicious(text: str | None) -> bool:
    if not text:
        return False
    return any(p.search(text) for p in PATTERNS)
