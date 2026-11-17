"""Gateway wire contract (API -> gateway) and the structured output every provider must return.

Evidence is untrusted data. The gateway never interprets it; it only redacts it, wraps it as
JSON inside a clearly delimited block, and passes it to the model.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Task = Literal[
    "alert_summary", "incident_summary", "triage", "rca", "pir_draft", "query_assist", "chat", "daily_briefing"
]
ProviderName = Literal["mock", "ollama", "anthropic"]

MAX_EVIDENCE_ITEMS = 60
MAX_EVIDENCE_TEXT = 2000
MAX_QUESTION = 2000


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceItem(_M):
    ref: str = Field(pattern=r"^E\d{1,3}$")
    type: Literal["alert", "incident", "timeline", "asset", "service", "vuln", "event", "runbook", "ticket", "kpi"]
    id: str = Field(max_length=100)
    title: str = Field(max_length=500)
    text: str = Field(default="", max_length=MAX_EVIDENCE_TEXT)
    severity: str | None = None
    at: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    # Set by the API's injection heuristics: the item contains instruction-like content.
    suspicious: bool = False


class Policy(_M):
    provider: ProviderName = "mock"
    # Tenant opted in to sending (redacted) evidence to a cloud provider.
    allow_cloud: bool = False
    redact_pii: bool = True
    max_output_tokens: int = Field(default=2000, ge=100, le=16000)


class GenerateRequest(_M):
    task: Task
    tenant_id: str = Field(max_length=64)
    subject: dict[str, Any] = Field(default_factory=dict)
    question: str | None = Field(default=None, max_length=MAX_QUESTION)
    evidence: list[EvidenceItem] = Field(default_factory=list, max_length=MAX_EVIDENCE_ITEMS)
    allowed_actions: list[str] = Field(default_factory=list, max_length=50)
    policy: Policy = Field(default_factory=Policy)


# ---------------------------------------------------------------- structured output
class Claim(_M):
    text: str = Field(max_length=1200)
    citations: list[str] = Field(default_factory=list, max_length=20)


class SuggestedAction(_M):
    action_key: str = Field(max_length=80)
    rationale: str = Field(max_length=600)
    citations: list[str] = Field(default_factory=list, max_length=20)


class SuggestedQuery(_M):
    target: Literal["alerts", "incidents", "events"]
    filters: dict[str, Any] = Field(default_factory=dict)
    explanation: str = Field(default="", max_length=600)


class AiOutput(_M):
    claims: list[Claim] = Field(default_factory=list, max_length=30)
    gaps: list[str] = Field(default_factory=list, max_length=20)
    confidence: float = Field(default=0.0, ge=0, le=1)
    suggested_actions: list[SuggestedAction] = Field(default_factory=list, max_length=10)
    query: SuggestedQuery | None = None


# JSON schema handed to providers that support constrained decoding (all fields required,
# no extra properties, as structured-output APIs require).
OUTPUT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "claims": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"text": {"type": "string"}, "citations": {"type": "array", "items": {"type": "string"}}},
                "required": ["text", "citations"],
                "additionalProperties": False,
            },
        },
        "gaps": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number"},
        "suggested_actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "action_key": {"type": "string"},
                    "rationale": {"type": "string"},
                    "citations": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["action_key", "rationale", "citations"],
                "additionalProperties": False,
            },
        },
        "query": {
            "anyOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "enum": ["alerts", "incidents", "events"]},
                        "filters": {
                            "type": "object",
                            "properties": {
                                "severity": {"type": "array", "items": {"type": "string"}},
                                "status": {"type": "array", "items": {"type": "string"}},
                                "domain": {"type": "string"},
                                "connector": {"type": "string"},
                                "q": {"type": "string"},
                            },
                            "required": ["severity", "status", "domain", "connector", "q"],
                            "additionalProperties": False,
                        },
                        "explanation": {"type": "string"},
                    },
                    "required": ["target", "filters", "explanation"],
                    "additionalProperties": False,
                },
            ]
        },
    },
    "required": ["claims", "gaps", "confidence", "suggested_actions", "query"],
    "additionalProperties": False,
}


class Usage(_M):
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    redactions: int = 0


class GenerateResponse(_M):
    output: AiOutput
    provider: ProviderName
    model: str
    template: str  # "<id>@<version>"
    usage: Usage
    # Raw model text when the provider's output could not be parsed (kept for diagnosis).
    raw_error: str | None = None


class EmbedRequest(_M):
    texts: list[str] = Field(min_length=1, max_length=64)


class EmbedResponse(_M):
    model: str
    dimensions: int
    vectors: list[list[float]]
