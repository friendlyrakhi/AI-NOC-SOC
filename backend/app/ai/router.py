"""AI endpoints (docs/05 §2.8). Every response is evidence-grounded, validated and labelled.

Permissions: ``ai:use`` plus read access to the subject. Settings need ``ai:admin``; changing the
provider or cloud opt-in also needs a step-up.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import text

from app.ai import client, service
from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.core.tenancy.common import record, tenant_tx
from app.errors import forbidden, not_found
from app.services import Services, get_services

router = APIRouter(prefix="/ai", tags=["ai"])
Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]

IncidentTask = Literal["summary", "triage", "rca", "pir-draft"]
TASK_OF = {"summary": "incident_summary", "triage": "triage", "rca": "rca", "pir-draft": "pir_draft"}


class AiEvidenceRef(BaseModel):
    ref: str
    type: str
    id: str
    title: str
    suspicious: bool


class AiRunOut(BaseModel):
    id: UUID
    task: str
    subject_type: str
    subject_id: UUID | None
    provider: str
    model: str
    template: str
    question: str | None
    evidence: list[AiEvidenceRef]
    output: dict[str, Any]
    validation_status: Literal["grounded", "partially_grounded", "insufficient_evidence", "rejected"]
    validation_notes: list[str]
    confidence: float
    suspicious_count: int
    tokens_in: int
    tokens_out: int
    latency_ms: int
    redactions: int
    created_at: datetime
    my_rating: int | None = None
    # Always true: the UI must label AI output as AI-generated.
    ai_generated: bool = True


def _need(p: Principal, perm: str) -> None:
    if not p.has(perm):
        raise forbidden()


@router.post("/alerts/{alert_id}/summary", response_model=AiRunOut, **requires("ai:use"))
async def alert_summary(alert_id: UUID, services: Svc, p: P) -> AiRunOut:
    _need(p, "alert:read")
    return AiRunOut(**await service.run(services, p, task="alert_summary", subject_type="alert", subject_id=alert_id))


@router.post("/incidents/{incident_id}/{task}", response_model=AiRunOut, **requires("ai:use"))
async def incident_task(incident_id: UUID, task: IncidentTask, services: Svc, p: P) -> AiRunOut:
    _need(p, "incident:read")
    return AiRunOut(
        **await service.run(services, p, task=TASK_OF[task], subject_type="incident", subject_id=incident_id)
    )


class AiQueryAssistIn(BaseModel):
    intent: str = Field(min_length=3, max_length=500)


@router.post("/query-assist", response_model=AiRunOut, **requires("ai:use"))
async def query_assist(body: AiQueryAssistIn, services: Svc, p: P) -> AiRunOut:
    """Returns a *suggested* search. It is never executed here; the analyst runs it."""
    return AiRunOut(
        **await service.run(
            services, p, task="query_assist", subject_type="none", subject_id=None, question=body.intent
        )
    )


class AiChatIn(BaseModel):
    subject_type: Literal["alert", "incident"]
    subject_id: UUID
    question: str = Field(min_length=2, max_length=2000)


@router.post("/chat", response_model=AiRunOut, **requires("ai:use"))
async def chat(body: AiChatIn, services: Svc, p: P) -> AiRunOut:
    _need(p, "alert:read" if body.subject_type == "alert" else "incident:read")
    return AiRunOut(
        **await service.run(
            services, p, task="chat", subject_type=body.subject_type, subject_id=body.subject_id, question=body.question
        )
    )


@router.get("/runs", response_model=list[AiRunOut], **requires("ai:use"))
async def list_runs(
    services: Svc,
    p: P,
    subject_type: Literal["alert", "incident", "none"],
    subject_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> list[AiRunOut]:
    async with tenant_tx(services, p) as conn:
        ids = [
            r[0]
            for r in await conn.execute(
                text(
                    "SELECT id FROM ai_runs WHERE subject_type = :t AND (CAST(:s AS uuid) IS NULL OR subject_id = :s) "
                    "ORDER BY created_at DESC LIMIT :l"
                ),
                {"t": subject_type, "s": subject_id, "l": limit},
            )
        ]
    return [AiRunOut(**await service.get_run(services, p, i)) for i in ids]


@router.get("/runs/{run_id}", response_model=AiRunOut, **requires("ai:use"))
async def get_run(run_id: UUID, services: Svc, p: P) -> AiRunOut:
    return AiRunOut(**await service.get_run(services, p, run_id))


class AiFeedbackIn(BaseModel):
    rating: Literal[-1, 1]
    comment: str = Field(default="", max_length=2000)


@router.post("/runs/{run_id}/feedback", response_model=AiRunOut, **requires("ai:use"))
async def feedback(run_id: UUID, body: AiFeedbackIn, services: Svc, p: P) -> AiRunOut:
    async with tenant_tx(services, p) as conn:
        if not (await conn.execute(text("SELECT 1 FROM ai_runs WHERE id = :i"), {"i": run_id})).first():
            raise not_found("AI run")
        await conn.execute(
            text(
                "INSERT INTO ai_feedback (tenant_id, ai_run_id, user_id, rating, comment) VALUES (app_tenant(), :r, "
                ":u, :g, :c) "
                "ON CONFLICT (ai_run_id, user_id) DO UPDATE SET rating = EXCLUDED.rating, comment = EXCLUDED.comment, "
                "created_at = now()"
            ),
            {"r": run_id, "u": p.user_id, "g": body.rating, "c": body.comment},
        )
    return AiRunOut(**await service.get_run(services, p, run_id))


# ============================================================ settings and usage
class AiSettingsOut(BaseModel):
    provider: Literal["mock", "ollama", "anthropic"]
    allow_cloud: bool
    redact_pii: bool
    daily_token_budget: int
    auto_summarize: bool
    providers_available: dict[str, bool]
    gateway_reachable: bool


class AiSettingsIn(BaseModel):
    provider: Literal["mock", "ollama", "anthropic"]
    allow_cloud: bool = False
    redact_pii: bool = True
    daily_token_budget: int = Field(default=200_000, ge=0, le=100_000_000)
    auto_summarize: bool = False

    @model_validator(mode="after")
    def _cloud(self) -> AiSettingsIn:
        if self.provider == "anthropic" and not self.allow_cloud:
            raise ValueError("a cloud provider requires allow_cloud (explicit opt-in)")
        return self


async def _settings_out(services: Services, p: Principal) -> AiSettingsOut:
    async with tenant_tx(services, p) as conn:
        cfg = await service.load_settings(conn)
    health = await client.health(services)
    return AiSettingsOut(
        **cfg.__dict__,
        providers_available=(health or {}).get("providers", {"mock": False}),
        gateway_reachable=health is not None,
    )


@router.get("/settings", response_model=AiSettingsOut, **requires("ai:admin"))
async def get_settings(services: Svc, p: P) -> AiSettingsOut:
    return await _settings_out(services, p)


@router.put("/settings", response_model=AiSettingsOut, **requires("ai:admin", step_up=True))
async def put_settings(body: AiSettingsIn, services: Svc, p: P) -> AiSettingsOut:
    async with tenant_tx(services, p) as conn:
        await conn.execute(
            text(
                "INSERT INTO ai_settings (tenant_id, provider, allow_cloud, redact_pii, daily_token_budget, "
                "auto_summarize, "
                "updated_by) VALUES (app_tenant(), :p, :c, :r, :b, :a, :u) ON CONFLICT (tenant_id) DO UPDATE SET "
                "provider = EXCLUDED.provider, allow_cloud = EXCLUDED.allow_cloud, redact_pii = EXCLUDED.redact_pii, "
                "daily_token_budget = EXCLUDED.daily_token_budget, auto_summarize = EXCLUDED.auto_summarize, "
                "updated_by = EXCLUDED.updated_by, updated_at = now()"
            ),
            {
                "p": body.provider,
                "c": body.allow_cloud,
                "r": body.redact_pii,
                "b": body.daily_token_budget,
                "a": body.auto_summarize,
                "u": p.user_id,
            },
        )
        await record(conn, p, "ai.settings.update", target_type="ai_settings", details=body.model_dump())
    return await _settings_out(services, p)


class AiUsageOut(BaseModel):
    tokens_today: int
    daily_token_budget: int
    runs_30d: int
    by_task: dict[str, int]
    by_status: dict[str, int]
    by_provider: dict[str, int]
    feedback_up: int
    feedback_down: int


@router.get("/usage", response_model=AiUsageOut, **requires("ai:admin"))
async def usage(services: Svc, p: P) -> AiUsageOut:
    since = datetime.now(UTC) - timedelta(days=30)
    async with tenant_tx(services, p) as conn:
        cfg = await service.load_settings(conn)
        today = await service.tokens_today(conn)

        async def group(col: str) -> dict[str, int]:
            rows = await conn.execute(
                text(f"SELECT {col}, count(*) FROM ai_runs WHERE created_at >= :s GROUP BY 1"),  # nosec B608
                {"s": since},
            )
            return {str(r[0]): int(r[1]) for r in rows}

        by_task, by_status, by_provider = await group("task"), await group("validation_status"), await group("provider")
        fb = {
            int(r[0]): int(r[1])
            for r in await conn.execute(text("SELECT rating, count(*) FROM ai_feedback GROUP BY 1"))
        }
    return AiUsageOut(
        tokens_today=today,
        daily_token_budget=cfg.daily_token_budget,
        runs_30d=sum(by_task.values()),
        by_task=by_task,
        by_status=by_status,
        by_provider=by_provider,
        feedback_up=fb.get(1, 0),
        feedback_down=fb.get(-1, 0),
    )


# ============================================================ daily briefing (P6)
@router.post("/briefing", response_model=AiRunOut, **requires("ai:use"))
async def generate_briefing(services: Svc, p: P) -> AiRunOut:
    """Generates the daily briefing from the last 24 hours' KPIs, open priority incidents and
    notable unescalated alerts. AI-generated and cited like every other AI output."""
    _need(p, "analytics:read")
    _need(p, "incident:read")
    return AiRunOut(**await service.run(services, p, task="daily_briefing", subject_type="none", subject_id=None))


@router.get("/briefing/latest", response_model=AiRunOut | None, **requires("analytics:read"))
async def latest_briefing(services: Svc, p: P) -> AiRunOut | None:
    """The most recent briefing (read-only, also for executives without ai:use), or null."""
    async with tenant_tx(services, p) as conn:
        run_id = (
            await conn.execute(
                text("SELECT id FROM ai_runs WHERE task = 'daily_briefing' ORDER BY created_at DESC LIMIT 1")
            )
        ).scalar_one_or_none()
    if run_id is None:
        return None
    return AiRunOut(**await service.get_run(services, p, run_id))
