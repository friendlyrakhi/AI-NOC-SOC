"""Validation of model output (docs/02 §5.3, threat model LLM01/LLM05/LLM06/LLM09).

Nothing a model returns is trusted. Every response is checked here before it is stored or shown:

- shape: must match the output contract, otherwise the run is ``rejected``;
- claims: each must cite at least one evidence ref that was actually supplied; claims with
  unknown refs, instruction-like text, links, HTML or markdown are dropped;
- suggested actions: only keys from the task's allow-list, with valid citations, at most three;
- query (query-assist only): target and filter names and values from allow-lists.

Result: ``grounded`` (nothing dropped), ``partially_grounded`` (something dropped),
``insufficient_evidence`` (no usable claims) or ``rejected`` (unusable output). Confidence is
capped accordingly, so a degraded answer never looks certain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.ai.injection import is_suspicious

Status = Literal["grounded", "partially_grounded", "insufficient_evidence", "rejected"]

_MARKUP = re.compile(r"https?://|www\.|<[a-z/!]|\]\(|javascript:|data:", re.I)
SEVERITIES = {"critical", "high", "medium", "low", "info"}
STATUSES = {"new", "acknowledged", "in_progress", "resolved", "closed", "suppressed"}
MAX_ACTIONS = 3


class _M(BaseModel):
    model_config = ConfigDict(extra="ignore")


class _Claim(_M):
    text: str = Field(max_length=1200)
    citations: list[str] = Field(default_factory=list, max_length=20)


class _Action(_M):
    action_key: str = Field(max_length=80)
    rationale: str = Field(max_length=600)
    citations: list[str] = Field(default_factory=list, max_length=20)


class _Query(_M):
    target: str
    filters: dict[str, Any] = Field(default_factory=dict)
    explanation: str = Field(default="", max_length=600)


class _Output(_M):
    claims: list[_Claim] = Field(default_factory=list, max_length=30)
    gaps: list[str] = Field(default_factory=list, max_length=20)
    confidence: float = 0.0
    suggested_actions: list[_Action] = Field(default_factory=list, max_length=10)
    query: _Query | None = None


@dataclass
class Validated:
    status: Status
    claims: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    suggested_actions: list[dict[str, Any]] = field(default_factory=list)
    query: dict[str, Any] | None = None
    confidence: float = 0.0
    notes: list[str] = field(default_factory=list)


def _clean_text(text: str) -> str:
    return " ".join(text.split())[:1200]


def _check_query(q: _Query, notes: list[str]) -> dict[str, Any] | None:
    if q.target not in {"alerts", "incidents", "events"}:
        notes.append("query: unknown target")
        return None
    f = q.filters
    out = {
        "severity": [s for s in f.get("severity", []) if isinstance(s, str) and s in SEVERITIES][:5],
        "status": [s for s in f.get("status", []) if isinstance(s, str) and s in STATUSES][:6],
        "domain": f.get("domain") if f.get("domain") in {"noc", "soc"} else "",
        "connector": f.get("connector")
        if isinstance(f.get("connector"), str) and re.fullmatch(r"[a-z0-9_.]{0,64}", f.get("connector", ""))
        else "",
        "q": re.sub(r"[^\w .:\-]", "", str(f.get("q", "")))[:100] if isinstance(f.get("q", ""), str) else "",
    }
    extra = set(f) - set(out)
    if extra:
        notes.append(f"query: ignored filters {sorted(extra)}")
    explanation = q.explanation if not (is_suspicious(q.explanation) or _MARKUP.search(q.explanation)) else ""
    return {"target": q.target, "filters": out, "explanation": _clean_text(explanation)}


def validate(raw: Any, *, refs: set[str], allowed_actions: set[str], task: str) -> Validated:
    notes: list[str] = []
    try:
        out = _Output.model_validate(raw)
    except ValidationError:
        return Validated(
            status="rejected", gaps=["The model's answer did not match the required format."], notes=["schema"]
        )

    claims: list[dict[str, Any]] = []
    for i, c in enumerate(out.claims):
        cites = list(dict.fromkeys(c.citations))
        if not cites:
            notes.append(f"claim {i}: no citations")
        elif not set(cites) <= refs:
            notes.append(f"claim {i}: cites unknown evidence {sorted(set(cites) - refs)}")
        elif is_suspicious(c.text):
            notes.append(f"claim {i}: instruction-like text")
        elif _MARKUP.search(c.text):
            notes.append(f"claim {i}: links or markup")
        elif not c.text.strip():
            notes.append(f"claim {i}: empty")
        else:
            claims.append({"text": _clean_text(c.text), "citations": cites})

    actions: list[dict[str, Any]] = []
    for a in out.suggested_actions:
        if a.action_key not in allowed_actions:
            notes.append(f"action {a.action_key!r}: not allowed for this task")
        elif not a.citations or not set(a.citations) <= refs:
            notes.append(f"action {a.action_key!r}: missing or unknown citations")
        elif is_suspicious(a.rationale) or _MARKUP.search(a.rationale):
            notes.append(f"action {a.action_key!r}: instruction-like rationale")
        elif len(actions) >= MAX_ACTIONS:
            notes.append(f"action {a.action_key!r}: over the limit of {MAX_ACTIONS}")
        else:
            actions.append(
                {
                    "action_key": a.action_key,
                    "rationale": _clean_text(a.rationale),
                    "citations": list(dict.fromkeys(a.citations)),
                }
            )

    query = None
    if task == "query_assist" and out.query is not None:
        query = _check_query(out.query, notes)
    elif out.query is not None:
        notes.append("query: not expected for this task")

    gaps = [_clean_text(g)[:400] for g in out.gaps if g.strip() and not is_suspicious(g) and not _MARKUP.search(g)][:10]
    confidence = max(0.0, min(1.0, float(out.confidence)))

    usable = bool(claims) or (task == "query_assist" and query is not None)
    if not usable:
        status: Status = "insufficient_evidence"
        confidence = 0.0
        if not gaps:
            gaps = ["Insufficient evidence to answer."]
    elif notes:
        status = "partially_grounded"
        confidence = min(confidence, 0.5)
    else:
        status = "grounded"
    return Validated(
        status=status,
        claims=claims,
        gaps=gaps,
        suggested_actions=actions,
        query=query,
        confidence=round(confidence, 3),
        notes=notes,
    )
