"""One AI run: settings and budget -> evidence -> gateway -> validation -> stored run + citations.

The AI can only *describe*: nothing here changes an alert, incident or anything else. A run's
output is stored for review and shown with its validation status and citations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.ai import client, evidence
from app.ai.actions import allowed_for
from app.ai.validator import Validated, validate
from app.core.authz.principal import Principal
from app.core.tenancy.common import record, tenant_tx
from app.errors import ProblemError
from app.services import Services

ACTION_TASKS = {"triage"}  # the only task allowed to suggest actions
OUTPUT_TOKENS = {"query_assist": 600, "chat": 1200}


@dataclass(frozen=True)
class AiSettings:
    provider: str = "mock"
    allow_cloud: bool = False
    redact_pii: bool = True
    daily_token_budget: int = 200_000
    auto_summarize: bool = False


async def load_settings(conn: AsyncConnection) -> AiSettings:
    row = (
        await conn.execute(
            text("SELECT provider, allow_cloud, redact_pii, daily_token_budget, auto_summarize FROM ai_settings")
        )
    ).one_or_none()
    return AiSettings(**row._mapping) if row else AiSettings()


async def tokens_today(conn: AsyncConnection) -> int:
    since = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    used = (
        await conn.execute(
            text("SELECT coalesce(sum(tokens_in + tokens_out), 0) FROM ai_runs WHERE created_at >= :s"), {"s": since}
        )
    ).scalar_one()
    return int(used)


async def run(
    services: Services,
    p: Principal,
    *,
    task: str,
    subject_type: str,
    subject_id: UUID | None,
    question: str | None = None,
) -> dict[str, Any]:
    async with tenant_tx(services, p) as conn:
        cfg = await load_settings(conn)
        if await tokens_today(conn) >= cfg.daily_token_budget:
            raise ProblemError(
                429,
                "ai.budget_exhausted",
                "AI budget used up",
                "This tenant has used today's AI token budget. An AI administrator can raise it.",
            )
        if subject_type == "alert" and subject_id:
            ev = await evidence.for_alert(services, conn, subject_id)
        elif subject_type == "incident" and subject_id:
            ev = await evidence.for_incident(services, conn, subject_id)
        else:
            ev = evidence.EvidenceSet(subject={"type": "none"})

    allowed = allowed_for(ev.connectors) if task in ACTION_TASKS else []
    body = {
        "task": task,
        "tenant_id": str(p.tenant_id),
        "subject": ev.subject,
        "question": question,
        "evidence": ev.items,
        "allowed_actions": allowed,
        "policy": {
            "provider": cfg.provider,
            "allow_cloud": cfg.allow_cloud,
            "redact_pii": cfg.redact_pii,
            "max_output_tokens": OUTPUT_TOKENS.get(task, 2000),
        },
    }
    refused = False
    try:
        response = await client.generate(services, body)
        checked = validate(response["output"], refs=ev.refs, allowed_actions=set(allowed), task=task)
        provider, model, template, usage = (
            response["provider"],
            response["model"],
            response["template"],
            response["usage"],
        )
    except client.GatewayError as exc:
        if exc.code != "ai.refused":
            raise
        refused = True
        checked = Validated(status="rejected", gaps=["The model declined to answer this request."], notes=["refusal"])
        provider, model, template, usage = cfg.provider, "unknown", f"{task}@?", {}

    output = {
        "claims": checked.claims,
        "gaps": checked.gaps,
        "suggested_actions": checked.suggested_actions,
        "query": checked.query,
    }
    evidence_index = [{k: i[k] for k in ("ref", "type", "id", "title", "suspicious")} for i in ev.items]
    async with tenant_tx(services, p) as conn:
        run_id = (
            await conn.execute(
                text(
                    "INSERT INTO ai_runs (tenant_id, task, subject_type, subject_id, provider, model, template, "
                    "question, "
                    "evidence, output, validation_status, validation_notes, confidence, suspicious_count, tokens_in, "
                    "tokens_out, latency_ms, redactions, requested_by) VALUES (app_tenant(), :task, :st, :sid, :prov, "
                    ":model, :tpl, :q, CAST(:ev AS jsonb), CAST(:out AS jsonb), :status, CAST(:notes AS jsonb), :conf, "
                    ":susp, :tin, :tout, :lat, :red, :u) RETURNING id, created_at"
                ),
                {
                    "task": task,
                    "st": subject_type,
                    "sid": subject_id,
                    "prov": provider,
                    "model": model,
                    "tpl": template,
                    "q": question,
                    "ev": json.dumps(evidence_index),
                    "out": json.dumps(output),
                    "status": checked.status,
                    "notes": json.dumps(checked.notes),
                    "conf": checked.confidence,
                    "susp": ev.suspicious,
                    "tin": int(usage.get("tokens_in", 0)),
                    "tout": int(usage.get("tokens_out", 0)),
                    "lat": int(usage.get("latency_ms", 0)),
                    "red": int(usage.get("redactions", 0)),
                    "u": p.user_id,
                },
            )
        ).one()
        by_ref = {i["ref"]: i for i in ev.items}
        for idx, claim in enumerate(checked.claims):
            for ref in claim["citations"]:
                await conn.execute(
                    text(
                        "INSERT INTO ai_citations (tenant_id, ai_run_id, claim_index, evidence_ref, evidence_type, "
                        "evidence_id) "
                        "VALUES (app_tenant(), :r, :c, :ref, :t, :i) ON CONFLICT DO NOTHING"
                    ),
                    {"r": run_id.id, "c": idx, "ref": ref, "t": by_ref[ref]["type"], "i": by_ref[ref]["id"]},
                )
        await record(
            conn,
            p,
            "ai.run",
            target_type="ai_run",
            target_id=run_id.id,
            details={
                "task": task,
                "subject_type": subject_type,
                "subject_id": str(subject_id) if subject_id else None,
                "provider": provider,
                "status": checked.status,
                "suspicious_evidence": ev.suspicious,
                "refused": refused,
            },
        )
    return await get_run(services, p, run_id.id)


async def get_run(services: Services, p: Principal, run_id: UUID) -> dict[str, Any]:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT id, task, subject_type, subject_id, provider, model, template, question, evidence, output, "
                    "validation_status, validation_notes, confidence::float AS confidence, suspicious_count, "
                    "tokens_in, "
                    "tokens_out, latency_ms, redactions, created_at, "
                    "(SELECT rating FROM ai_feedback f WHERE f.ai_run_id = r.id AND f.user_id = :u) AS my_rating "
                    "FROM ai_runs r WHERE id = :i"
                ),
                {"i": run_id, "u": p.user_id},
            )
        ).one_or_none()
    if row is None:
        from app.errors import not_found

        raise not_found("AI run")
    return dict(row._mapping)
