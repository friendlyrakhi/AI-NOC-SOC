"""Workflow-worker endpoints (``X-Workflow-Token``).

The worker identifies requests and runs by id only. The owning tenant is looked up in the
database (never taken from the worker), and every operation then runs inside that tenant's
RLS context. Execution is possible only through ``claim``, which re-checks the database.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.actions import service
from app.actions.dsl import validate_definition
from app.core.authz.deps import internal
from app.errors import ProblemError, not_found
from app.services import Services, get_services

router = APIRouter(prefix="/internal/workflow", tags=["internal"])
Svc = Annotated[Services, Depends(get_services)]
AUTH = internal("workflow")


async def _owner(services: Services, fn: str, oid: UUID) -> UUID:
    async with services.app_db.engine.begin() as conn:
        tenant = (await conn.execute(text(f"SELECT {fn}(:i)"), {"i": oid})).scalar_one_or_none()  # nosec B608 - fixed names
    if tenant is None:
        raise not_found("Object")
    return tenant  # type: ignore[no-any-return]


# ---------------------------------------------------------------- actions
@router.post("/actions/{request_id}/claim", **AUTH)
async def claim(request_id: UUID, services: Svc) -> dict[str, Any]:
    tenant = await _owner(services, "action_request_owner", request_id)
    async with services.app_db.tenant(tenant) as conn:
        try:
            return {"claimed": True, "spec": await service.claim(conn, request_id)}
        except service.ActionRefusedError as exc:
            refusal = {"claimed": False, "code": exc.code, "detail": exc.detail}
    return refusal


class CompleteIn(BaseModel):
    status: Literal["succeeded", "failed"]
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = Field(default=None, max_length=1000)


@router.post("/actions/{request_id}/complete", **AUTH)
async def complete(request_id: UUID, body: CompleteIn, services: Svc) -> dict[str, str]:
    tenant = await _owner(services, "action_request_owner", request_id)
    async with services.app_db.tenant(tenant) as conn:
        await service.complete(conn, request_id, status=body.status, result=body.result, error=body.error)
    return {"status": body.status}


@router.post("/actions/{request_id}/platform-execute", **AUTH)
async def platform_execute(request_id: UUID, services: Svc) -> dict[str, Any]:
    tenant = await _owner(services, "action_request_owner", request_id)
    async with services.app_db.tenant(tenant) as conn:
        req = (await conn.execute(text("SELECT * FROM action_requests WHERE id = :i"), {"i": request_id})).one()
        if req.status != "executing" or req.connector_id != "platform":
            raise ProblemError(409, "action.not_executing", "Not executing", "Claim the request first.")
        return await service.platform_execute(
            conn, {"action_key": req.action_key, "target": req.target, "params": req.params, "mode": req.execution_mode}
        )


@router.post("/actions/{request_id}/expire", **AUTH)
async def expire(request_id: UUID, services: Svc) -> dict[str, str]:
    tenant = await _owner(services, "action_request_owner", request_id)
    async with services.app_db.tenant(tenant) as conn:
        row = (
            await conn.execute(
                text(
                    "UPDATE action_requests SET status = 'expired', updated_at = now(), version = version + 1 "
                    "WHERE id = :i AND status = 'pending_approval' RETURNING incident_id, action_key"
                ),
                {"i": request_id},
            )
        ).one_or_none()
        if row is not None and row.incident_id is not None:
            from app.incidents import store

            await store.timeline(
                conn,
                row.incident_id,
                "action_result",
                {
                    "request_id": str(request_id),
                    "action": row.action_key,
                    "status": "expired",
                    "detail": "No decision before the approval window closed.",
                },
            )
        status = (
            await conn.execute(text("SELECT status FROM action_requests WHERE id = :i"), {"i": request_id})
        ).scalar_one()
    return {"status": status}


@router.get("/actions/{request_id}", **AUTH)
async def request_status(request_id: UUID, services: Svc) -> dict[str, Any]:
    tenant = await _owner(services, "action_request_owner", request_id)
    async with services.app_db.tenant(tenant) as conn:
        row = (
            await conn.execute(
                text("SELECT status, required_approvals FROM action_requests WHERE id = :i"), {"i": request_id}
            )
        ).one()
    return {"status": row.status, "required_approvals": row.required_approvals}


# ---------------------------------------------------------------- playbook runs
@router.post("/runs/{workflow_run_id}/steps/{step_id}/request", **AUTH)
async def request_step(workflow_run_id: UUID, step_id: str, services: Svc) -> dict[str, Any]:
    """Creates the action request for one step from the run's pinned, published version. The
    worker passes only ids: the action, target and parameters come from the database."""
    tenant = await _owner(services, "workflow_run_owner", workflow_run_id)
    async with services.app_db.tenant(tenant) as conn:
        run = (
            await conn.execute(
                text(
                    "SELECT r.*, v.definition FROM workflow_runs r JOIN playbook_versions v ON v.id = "
                    "r.playbook_version_id "
                    "WHERE r.id = :i"
                ),
                {"i": workflow_run_id},
            )
        ).one()
        parsed, problems = validate_definition(run.definition)
        if parsed is None:
            raise ProblemError(409, "playbook.invalid", "Invalid playbook", "; ".join(problems))
        step = next((s for s in parsed.steps if s.id == step_id), None)
        if step is None:
            raise not_found("Step")
        asset_id = (
            await service.primary_asset(conn, run.incident_id) if step.target == "incident.primary_asset" else None
        )
        if step.target == "incident.primary_asset" and asset_id is None:
            return {
                "request_id": None,
                "status": "denied",
                "needs_approval": False,
                "detail": "The incident has no asset to act on.",
            }
        created = await service.create_request(
            conn,
            action_key=step.action,
            asset_id=asset_id,
            incident_id=run.incident_id,
            params=step.params,
            justification=step.justification or f"Playbook step {step.id}",
            mode=run.mode,
            requested_by_type="playbook",
            requested_by=run.started_by,
            expiry_minutes=parsed.approval_timeout_minutes,
            workflow_run_id=workflow_run_id,
            step_id=step.id,
            idempotency_key=f"run:{workflow_run_id}:{step.id}",
        )
    row = created.row
    return {
        "request_id": str(row["id"]),
        "status": row["status"],
        "needs_approval": row["status"] == "pending_approval",
        "detail": "; ".join(created.decision.reasons),
    }


@router.post("/runs/{workflow_run_id}/checkpoint", **AUTH)
async def checkpoint(workflow_run_id: UUID, services: Svc) -> dict[str, Any]:
    """Called before every step: halts on the kill switch (except dry runs) or a cancelled run."""
    tenant = await _owner(services, "workflow_run_owner", workflow_run_id)
    async with services.app_db.tenant(tenant) as conn:
        run = (
            await conn.execute(
                text("SELECT status, mode, kill_switch_engaged() AS killed FROM workflow_runs WHERE id = :i"),
                {"i": workflow_run_id},
            )
        ).one()
    if run.status != "running":
        return {"halt": True, "reason": f"run {run.status}"}
    if run.killed and run.mode != "dry_run":
        return {"halt": True, "reason": "kill switch engaged"}
    return {"halt": False, "reason": ""}


class StepResultIn(BaseModel):
    step_id: str = Field(max_length=41)
    status: str = Field(max_length=20)
    request_id: str | None = None
    detail: str = Field(default="", max_length=500)


@router.post("/runs/{workflow_run_id}/step-result", **AUTH)
async def step_result(workflow_run_id: UUID, body: StepResultIn, services: Svc) -> dict[str, str]:
    tenant = await _owner(services, "workflow_run_owner", workflow_run_id)
    async with services.app_db.tenant(tenant) as conn:
        await conn.execute(
            text(
                "UPDATE workflow_runs SET steps = steps || jsonb_build_object(CAST(:s AS text), CAST(:v AS jsonb)) "
                "WHERE id = :i"
            ),
            {
                "s": body.step_id,
                "v": json.dumps({"status": body.status, "request_id": body.request_id, "detail": body.detail}),
                "i": workflow_run_id,
            },
        )
    return {"status": "recorded"}


class FinishIn(BaseModel):
    status: Literal["succeeded", "failed", "halted", "cancelled"]
    error: str | None = Field(default=None, max_length=1000)


@router.post("/runs/{workflow_run_id}/finish", **AUTH)
async def finish(workflow_run_id: UUID, body: FinishIn, services: Svc) -> dict[str, str]:
    tenant = await _owner(services, "workflow_run_owner", workflow_run_id)
    async with services.app_db.tenant(tenant) as conn:
        await conn.execute(
            text(
                "UPDATE workflow_runs SET status = CASE WHEN status = 'running' THEN :s ELSE status END, error = :e, "
                "ended_at = coalesce(ended_at, now()) WHERE id = :i"
            ),
            {"s": body.status, "e": body.error, "i": workflow_run_id},
        )
    return {"status": body.status}
