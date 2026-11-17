"""Automation API (docs/05 §2.9): catalog, policies, action requests, approvals, kill switch,
playbooks and workflow runs.

Everything that executes goes through a Temporal workflow and the workflow worker. This router
only records requests and decisions and starts or signals workflows; the worker must still claim
each request from the database before it runs (see service.claim).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.actions import service, temporal
from app.actions.catalog import TIER_TEXT, catalog, raise_tier
from app.actions.dsl import validate_definition
from app.core.authz.deps import get_principal, platform_admin, requires
from app.core.authz.principal import Principal
from app.core.tenancy.common import record, tenant_tx
from app.errors import ProblemError, not_found
from app.services import Services, get_services

router = APIRouter(tags=["automation"])
Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]

Mode = Literal["dry_run", "simulate", "live"]


# ============================================================ catalog and tenant policy
class CatalogEntry(BaseModel):
    key: str
    connector_id: str
    tier: str
    effective_tier: str
    tier_meaning: str
    reversible: bool
    target_kind: str
    params_schema: dict[str, Any]
    description: str
    allowed: bool
    require_justification: bool


@router.get("/actions/catalog", response_model=list[CatalogEntry], **requires("action:read"))
async def get_catalog(services: Svc, p: P) -> list[CatalogEntry]:
    async with tenant_tx(services, p) as conn:
        policies = {r.action_key: r for r in await conn.execute(text("SELECT * FROM action_policies"))}
    out = []
    for a in catalog().values():
        pol = policies.get(a.key)
        eff = raise_tier(a.tier, pol.tier_override if pol else None)
        out.append(
            CatalogEntry(
                key=a.key,
                connector_id=a.connector_id,
                tier=a.tier,
                effective_tier=eff,
                tier_meaning=TIER_TEXT[eff],
                reversible=a.reversible,
                target_kind=a.target_kind,
                params_schema=a.params_schema,
                description=a.description,
                allowed=pol.allowed if pol else True,
                require_justification=pol.require_justification if pol else False,
            )
        )
    return out


class PolicyIn(BaseModel):
    tier_override: Literal["T0", "T1", "T2", "T3"] | None = None
    allowed: bool = True
    require_justification: bool = False


@router.put("/actions/policies/{action_key}", response_model=CatalogEntry, **requires("action:policy", step_up=True))
async def put_policy(action_key: str, body: PolicyIn, services: Svc, p: P) -> CatalogEntry:
    action = catalog().get(action_key)
    if action is None:
        raise not_found("Action")
    if body.tier_override and raise_tier(action.tier, body.tier_override) != body.tier_override:
        raise ProblemError(
            422,
            "action.tier_lowering",
            "Tier cannot be lowered",
            f"{action_key} is {action.tier}; overrides may only raise it.",
        )
    async with tenant_tx(services, p) as conn:
        await conn.execute(
            text(
                "INSERT INTO action_policies (tenant_id, action_key, tier_override, allowed, require_justification, "
                "updated_by) "
                "VALUES (app_tenant(), :k, :t, :a, :j, :u) ON CONFLICT (tenant_id, action_key) DO UPDATE SET "
                "tier_override = EXCLUDED.tier_override, allowed = EXCLUDED.allowed, "
                "require_justification = EXCLUDED.require_justification, updated_by = EXCLUDED.updated_by, "
                "updated_at = now()"
            ),
            {
                "k": action_key,
                "t": body.tier_override,
                "a": body.allowed,
                "j": body.require_justification,
                "u": p.user_id,
            },
        )
        await record(
            conn, p, "action.policy.update", target_type="action", target_id=action_key, details=body.model_dump()
        )
    return next(e for e in await get_catalog(services, p) if e.key == action_key)


# ============================================================ action requests
class RequestIn(BaseModel):
    action_key: str = Field(max_length=80)
    asset_id: UUID | None = None
    incident_id: UUID | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    justification: str = Field(default="", max_length=1000)
    mode: Mode = "simulate"
    ai_run_id: UUID | None = None


class ApprovalOut(BaseModel):
    approver_id: UUID
    approver_name: str | None
    decision: str
    comment: str
    decided_at: datetime


class RequestOut(BaseModel):
    id: UUID
    action_key: str
    connector_id: str
    incident_id: UUID | None
    workflow_run_id: UUID | None
    step_id: str | None
    target: dict[str, Any]
    params: dict[str, Any]
    tier: str
    required_approvals: int
    requested_by_type: str
    requested_by: UUID | None
    requested_by_name: str | None = None
    ai_run_id: UUID | None
    justification: str
    policy_decision: dict[str, Any]
    execution_mode: str
    status: str
    result: dict[str, Any] | None
    error: str | None
    expires_at: datetime | None
    executed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    approvals: list[ApprovalOut] = Field(default_factory=list)


_REQUEST_SELECT = """
SELECT r.*, u.display_name AS requested_by_name,
  coalesce((SELECT json_agg(json_build_object('approver_id', a.approver_id, 'approver_name', au.display_name,
             'decision', a.decision, 'comment', a.comment, 'decided_at', a.decided_at) ORDER BY a.decided_at)
            FROM approvals a LEFT JOIN users au ON au.id = a.approver_id
            WHERE a.action_request_id = r.id), '[]') AS approvals
FROM action_requests r LEFT JOIN users u ON u.id = r.requested_by
"""


async def _load(conn: Any, request_id: UUID) -> RequestOut:
    row = (await conn.execute(text(f"{_REQUEST_SELECT} WHERE r.id = :i"), {"i": request_id})).one_or_none()  # nosec B608
    if row is None:
        raise not_found("Action request")
    return RequestOut(**row._mapping)


@router.post(
    "/actions/requests", response_model=RequestOut, status_code=status.HTTP_201_CREATED, **requires("action:request")
)
async def create_request(
    body: RequestIn,
    services: Svc,
    p: P,
    idempotency_key: Annotated[str | None, Header(max_length=100)] = None,
) -> RequestOut:
    if body.mode == "live":
        raise ProblemError(
            422, "action.execution_disabled", "Live execution disabled", "Only dry_run and simulate are available."
        )
    await temporal._client(services)  # fail before recording anything if the engine is down
    async with tenant_tx(services, p) as conn:
        asset_id = body.asset_id
        known = catalog().get(body.action_key)
        if asset_id is None and body.incident_id is not None and known is not None and known.target_kind == "asset":
            # Same rule as playbook steps: an asset action on an incident targets its primary asset.
            asset_id = await service.primary_asset(conn, body.incident_id)
        created = await service.create_request(
            conn,
            action_key=body.action_key,
            asset_id=asset_id,
            incident_id=body.incident_id,
            params=body.params,
            justification=body.justification,
            mode=body.mode,
            requested_by_type="ai" if body.ai_run_id else "user",
            requested_by=p.user_id,
            ai_run_id=body.ai_run_id,
            expiry_minutes=services.settings.approval_expiry_minutes,
            idempotency_key=f"{p.user_id}:{idempotency_key}" if idempotency_key else None,
        )
        await record(
            conn,
            p,
            "action.request",
            target_type="action_request",
            target_id=created.row["id"],
            details={
                "action": body.action_key,
                "mode": body.mode,
                "decision": created.decision.decision,
                "tier": created.decision.tier,
                "ai_run": str(body.ai_run_id) if body.ai_run_id else None,
            },
        )
    row = created.row
    if row["status"] in ("approved", "pending_approval") and not row["temporal_workflow_id"]:
        workflow_id = await temporal.start_action(
            services,
            str(row["id"]),
            needs_approval=row["status"] == "pending_approval",
            expires_in_seconds=services.settings.approval_expiry_minutes * 60,
        )
        async with tenant_tx(services, p) as conn:
            await conn.execute(
                text("UPDATE action_requests SET temporal_workflow_id = :w WHERE id = :i"),
                {"w": workflow_id, "i": row["id"]},
            )
    async with tenant_tx(services, p) as conn:
        return await _load(conn, row["id"])


@router.get("/actions/requests", response_model=list[RequestOut], **requires("action:read"))
async def list_requests(
    services: Svc,
    p: P,
    status_: Annotated[list[str] | None, Query(alias="status")] = None,
    incident_id: UUID | None = None,
    workflow_run_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[RequestOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(
            text(
                f"{_REQUEST_SELECT} WHERE (CAST(:st AS text[]) IS NULL OR r.status = ANY(:st)) "  # nosec B608
                "AND (CAST(:inc AS uuid) IS NULL OR r.incident_id = :inc) "
                "AND (CAST(:run AS uuid) IS NULL OR r.workflow_run_id = :run) ORDER BY r.created_at DESC LIMIT :l"
            ),
            {"st": status_, "inc": incident_id, "run": workflow_run_id, "l": limit},
        )
        return [RequestOut(**r._mapping) for r in rows]


@router.get("/actions/requests/{request_id}", response_model=RequestOut, **requires("action:read"))
async def get_request(request_id: UUID, services: Svc, p: P) -> RequestOut:
    async with tenant_tx(services, p) as conn:
        return await _load(conn, request_id)


class DecisionIn(BaseModel):
    comment: str = Field(default="", max_length=2000)


async def _mark_expired(services: Services, p: Principal, request_id: UUID) -> None:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text(
                    "UPDATE action_requests SET status = 'expired', updated_at = now(), version = version + 1 "
                    "WHERE id = :i AND status = 'pending_approval' RETURNING temporal_workflow_id, workflow_run_id"
                ),
                {"i": request_id},
            )
        ).one_or_none()
    if row is not None:
        workflow_id = f"playbook-{row.workflow_run_id}" if row.workflow_run_id else row.temporal_workflow_id
        if workflow_id:
            await temporal.signal_decision(services, workflow_id, str(request_id), "expired")


async def _decide(services: Services, p: Principal, request_id: UUID, decision: str, comment: str) -> RequestOut:
    if p.user_id is None or p.step_up_at is None:
        raise ProblemError(
            403, "action.user_required", "Approver required", "Approvals must come from a signed-in person."
        )
    try:
        async with tenant_tx(services, p) as conn:
            outcome = await service.approve_or_deny(
                conn, request_id, approver=p.user_id, decision=decision, comment=comment, step_up_at=p.step_up_at
            )
            await record(
                conn,
                p,
                f"action.{decision}",
                target_type="action_request",
                target_id=request_id,
                details={
                    "status": outcome["status"],
                    "approvals": outcome["approvals"],
                    "required": outcome["required"],
                },
            )
    except ProblemError as exc:
        if exc.code == "action.expired":
            await _mark_expired(services, p, request_id)
        raise
    if outcome["status"] in ("approved", "denied"):
        workflow_id = f"playbook-{outcome['run_id']}" if outcome["run_id"] else outcome["workflow_id"]
        if workflow_id:
            await temporal.signal_decision(services, workflow_id, str(request_id), outcome["status"])
    async with tenant_tx(services, p) as conn:
        return await _load(conn, request_id)


@router.post(
    "/actions/requests/{request_id}/approve", response_model=RequestOut, **requires("action:approve", step_up=True)
)
async def approve(request_id: UUID, body: DecisionIn, services: Svc, p: P) -> RequestOut:
    return await _decide(services, p, request_id, "approve", body.comment)


@router.post(
    "/actions/requests/{request_id}/deny", response_model=RequestOut, **requires("action:approve", step_up=True)
)
async def deny(request_id: UUID, body: DecisionIn, services: Svc, p: P) -> RequestOut:
    return await _decide(services, p, request_id, "deny", body.comment)


@router.post("/actions/requests/{request_id}/cancel", response_model=RequestOut, **requires("action:request"))
async def cancel_request(request_id: UUID, services: Svc, p: P) -> RequestOut:
    async with tenant_tx(services, p) as conn:
        req = (
            await conn.execute(text("SELECT * FROM action_requests WHERE id = :i FOR UPDATE"), {"i": request_id})
        ).one_or_none()
        if req is None:
            raise not_found("Action request")
        if req.requested_by != p.user_id and not p.has("action:approve"):
            raise ProblemError(
                403, "action.not_requester", "Not yours", "Only the requester or an approver can cancel."
            )
        if req.status not in ("pending_approval", "approved"):
            raise ProblemError(409, "action.not_cancellable", "Cannot cancel", f"The request is {req.status}.")
        await conn.execute(
            text(
                "UPDATE action_requests SET status = 'cancelled', updated_at = now(), version = version + 1 WHERE id "
                "= :i"
            ),
            {"i": request_id},
        )
        await record(conn, p, "action.cancel", target_type="action_request", target_id=request_id)
    workflow_id = f"playbook-{req.workflow_run_id}" if req.workflow_run_id else req.temporal_workflow_id
    if workflow_id:
        await temporal.signal_decision(services, workflow_id, str(request_id), "cancelled")
    async with tenant_tx(services, p) as conn:
        return await _load(conn, request_id)


@router.get("/approvals/inbox", response_model=list[RequestOut], **requires("action:approve"))
async def inbox(services: Svc, p: P) -> list[RequestOut]:
    """Requests waiting for the caller: not their own, not yet decided by them, not expired."""
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(
            text(
                f"{_REQUEST_SELECT} WHERE r.status = 'pending_approval' AND (r.expires_at IS NULL OR r.expires_at > "
                f"now()) "  # nosec B608
                "AND r.requested_by IS DISTINCT FROM :me "
                "AND NOT EXISTS (SELECT 1 FROM approvals a WHERE a.action_request_id = r.id AND a.approver_id = :me) "
                "ORDER BY r.tier DESC, r.created_at"
            ),
            {"me": p.user_id},
        )
        return [RequestOut(**r._mapping) for r in rows]


# ============================================================ kill switch
class KillSwitchOut(BaseModel):
    engaged: bool
    tenant_engaged: bool
    global_engaged: bool
    reason: str
    changed_at: datetime | None


class KillSwitchIn(BaseModel):
    engaged: bool
    reason: str = Field(min_length=1, max_length=500)


async def _killswitch(conn: Any) -> KillSwitchOut:
    t = (await conn.execute(text("SELECT engaged, reason, changed_at FROM tenant_kill_switches"))).one_or_none()
    g = (await conn.execute(text("SELECT engaged, reason, changed_at FROM global_kill_switch WHERE id = 1"))).one()
    return KillSwitchOut(
        engaged=bool(g.engaged or (t and t.engaged)),
        tenant_engaged=bool(t and t.engaged),
        global_engaged=bool(g.engaged),
        reason=(g.reason if g.engaged else (t.reason if t else "")) or "",
        changed_at=(t.changed_at if t else g.changed_at),
    )


@router.get("/killswitch", response_model=KillSwitchOut, **requires("action:read"))
async def get_killswitch(services: Svc, p: P) -> KillSwitchOut:
    async with tenant_tx(services, p) as conn:
        return await _killswitch(conn)


@router.post("/killswitch", response_model=KillSwitchOut, **requires("automation:killswitch", step_up=True))
async def set_killswitch(body: KillSwitchIn, services: Svc, p: P) -> KillSwitchOut:
    async with tenant_tx(services, p) as conn:
        await conn.execute(
            text(
                "INSERT INTO tenant_kill_switches (tenant_id, engaged, reason, changed_by) VALUES (app_tenant(), :e, "
                ":r, :u) "
                "ON CONFLICT (tenant_id) DO UPDATE SET engaged = EXCLUDED.engaged, reason = EXCLUDED.reason, "
                "changed_by = EXCLUDED.changed_by, changed_at = now()"
            ),
            {"e": body.engaged, "r": body.reason, "u": p.user_id},
        )
        await record(
            conn, p, "automation.killswitch", target_type="tenant", target_id=p.tenant_id, details=body.model_dump()
        )
        return await _killswitch(conn)


@router.post("/platform/killswitch", status_code=status.HTTP_204_NO_CONTENT, **platform_admin())
async def set_global_killswitch(body: KillSwitchIn, services: Svc, p: P) -> Response:
    async with services.app_db.engine.begin() as conn:
        await conn.execute(
            text("SELECT set_global_kill_switch(:e, :r, :u)"), {"e": body.engaged, "r": body.reason, "u": p.user_id}
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ============================================================ playbooks
class VersionOut(BaseModel):
    id: UUID
    version: int
    status: str
    definition: dict[str, Any]
    created_at: datetime
    published_at: datetime | None


class PlaybookOut(BaseModel):
    id: UUID
    key: str
    name: str
    domain: str
    description: str
    published_version: int | None
    max_tier: str | None
    versions: list[VersionOut] = Field(default_factory=list)


class PlaybookIn(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,60}$")
    name: str = Field(min_length=1, max_length=200)
    domain: Literal["noc", "soc", "joint"]
    description: str = Field(default="", max_length=2000)
    definition: dict[str, Any]


class VersionIn(BaseModel):
    definition: dict[str, Any]


def _max_tier(definition: dict[str, Any]) -> str | None:
    tiers = [catalog()[s["action"]].tier for s in definition.get("steps", []) if s.get("action") in catalog()]
    return max(tiers) if tiers else None


async def _playbook(conn: Any, playbook_id: UUID) -> PlaybookOut:
    pb = (await conn.execute(text("SELECT * FROM playbooks WHERE id = :i"), {"i": playbook_id})).one_or_none()
    if pb is None:
        raise not_found("Playbook")
    versions = [
        VersionOut(**v._mapping)
        for v in await conn.execute(
            text(
                "SELECT id, version, status, definition, created_at, published_at FROM playbook_versions "
                "WHERE playbook_id = :i ORDER BY version DESC"
            ),
            {"i": playbook_id},
        )
    ]
    published = next((v for v in versions if v.status == "published"), None)
    return PlaybookOut(
        id=pb.id,
        key=pb.key,
        name=pb.name,
        domain=pb.domain,
        description=pb.description,
        published_version=published.version if published else None,
        max_tier=_max_tier((published or versions[0]).definition) if versions else None,
        versions=versions,
    )


def _validated(definition: dict[str, Any]) -> dict[str, Any]:
    parsed, problems = validate_definition(definition)
    if parsed is None:
        raise ProblemError(422, "playbook.invalid", "Invalid playbook", "; ".join(problems[:10]))
    return parsed.model_dump()


@router.get("/playbooks", response_model=list[PlaybookOut], **requires("playbook:read"))
async def list_playbooks(services: Svc, p: P) -> list[PlaybookOut]:
    async with tenant_tx(services, p) as conn:
        ids = [r[0] for r in await conn.execute(text("SELECT id FROM playbooks ORDER BY name"))]
        return [await _playbook(conn, i) for i in ids]


@router.post("/playbooks", response_model=PlaybookOut, status_code=status.HTTP_201_CREATED, **requires("playbook:edit"))
async def create_playbook(body: PlaybookIn, services: Svc, p: P) -> PlaybookOut:
    definition = _validated(body.definition)
    async with tenant_tx(services, p) as conn:
        if (await conn.execute(text("SELECT 1 FROM playbooks WHERE key = :k"), {"k": body.key})).first():
            raise ProblemError(409, "playbook.key_taken", "Key in use", "Another playbook has that key.")
        pid = (
            await conn.execute(
                text(
                    "INSERT INTO playbooks (tenant_id, key, name, domain, description, created_by) "
                    "VALUES (app_tenant(), :k, :n, :d, :ds, :u) RETURNING id"
                ),
                {"k": body.key, "n": body.name, "d": body.domain, "ds": body.description, "u": p.user_id},
            )
        ).scalar_one()
        await conn.execute(
            text(
                "INSERT INTO playbook_versions (tenant_id, playbook_id, version, definition, created_by) "
                "VALUES (app_tenant(), :p, 1, CAST(:d AS jsonb), :u)"
            ),
            {"p": pid, "d": json.dumps(definition), "u": p.user_id},
        )
        await record(conn, p, "playbook.create", target_type="playbook", target_id=pid, details={"key": body.key})
        return await _playbook(conn, pid)


@router.get("/playbooks/{playbook_id}", response_model=PlaybookOut, **requires("playbook:read"))
async def get_playbook(playbook_id: UUID, services: Svc, p: P) -> PlaybookOut:
    async with tenant_tx(services, p) as conn:
        return await _playbook(conn, playbook_id)


@router.post(
    "/playbooks/{playbook_id}/versions",
    response_model=PlaybookOut,
    status_code=status.HTTP_201_CREATED,
    **requires("playbook:edit"),
)
async def new_version(playbook_id: UUID, body: VersionIn, services: Svc, p: P) -> PlaybookOut:
    definition = _validated(body.definition)
    async with tenant_tx(services, p) as conn:
        await _playbook(conn, playbook_id)
        n = (
            await conn.execute(
                text("SELECT coalesce(max(version), 0) + 1 FROM playbook_versions WHERE playbook_id = :p"),
                {"p": playbook_id},
            )
        ).scalar_one()
        await conn.execute(
            text(
                "INSERT INTO playbook_versions (tenant_id, playbook_id, version, definition, created_by) "
                "VALUES (app_tenant(), :p, :v, CAST(:d AS jsonb), :u)"
            ),
            {"p": playbook_id, "v": n, "d": json.dumps(definition), "u": p.user_id},
        )
        await record(
            conn, p, "playbook.version.create", target_type="playbook", target_id=playbook_id, details={"version": n}
        )
        return await _playbook(conn, playbook_id)


@router.post(
    "/playbooks/{playbook_id}/versions/{version}/publish",
    response_model=PlaybookOut,
    **requires("playbook:publish", step_up=True),
)
async def publish(playbook_id: UUID, version: int, services: Svc, p: P) -> PlaybookOut:
    async with tenant_tx(services, p) as conn:
        v = (
            await conn.execute(
                text("SELECT id, status, definition FROM playbook_versions WHERE playbook_id = :p AND version = :v"),
                {"p": playbook_id, "v": version},
            )
        ).one_or_none()
        if v is None:
            raise not_found("Playbook version")
        if v.status != "draft":
            raise ProblemError(409, "playbook.not_draft", "Not a draft", "Only drafts can be published.")
        _validated(v.definition)  # re-validate against today's catalog
        previous = (
            await conn.execute(
                text(
                    "SELECT version, definition FROM playbook_versions WHERE playbook_id = :p AND status = 'published'"
                ),
                {"p": playbook_id},
            )
        ).one_or_none()
        await conn.execute(
            text("UPDATE playbook_versions SET status = 'retired' WHERE playbook_id = :p AND status = 'published'"),
            {"p": playbook_id},
        )
        await conn.execute(
            text(
                "UPDATE playbook_versions SET status = 'published', published_by = :u, published_at = now() WHERE id "
                "= :i"
            ),
            {"u": p.user_id, "i": v.id},
        )
        old_steps = [s["action"] for s in (previous.definition["steps"] if previous else [])]
        new_steps = [s["action"] for s in v.definition["steps"]]
        await record(
            conn,
            p,
            "playbook.publish",
            target_type="playbook",
            target_id=playbook_id,
            details={
                "version": version,
                "previous_version": previous.version if previous else None,
                "steps_before": old_steps,
                "steps_after": new_steps,
            },
        )
        return await _playbook(conn, playbook_id)


class RunIn(BaseModel):
    incident_id: UUID
    mode: Mode = "simulate"


class WorkflowRunOut(BaseModel):
    id: UUID
    playbook_id: UUID
    playbook_name: str
    version: int
    incident_id: UUID | None
    mode: str
    status: str
    steps: dict[str, Any]
    error: str | None
    started_at: datetime
    ended_at: datetime | None


_RUN_SELECT = """
SELECT r.id, pb.id AS playbook_id, pb.name AS playbook_name, v.version, r.incident_id, r.mode, r.status, r.steps,
       r.error,
       r.started_at, r.ended_at
FROM workflow_runs r JOIN playbook_versions v ON v.id = r.playbook_version_id JOIN playbooks pb ON pb.id = v.playbook_id
"""


@router.post(
    "/playbooks/{playbook_id}/run",
    response_model=WorkflowRunOut,
    status_code=status.HTTP_201_CREATED,
    **requires("playbook:run"),
)
async def run_playbook(playbook_id: UUID, body: RunIn, services: Svc, p: P) -> WorkflowRunOut:
    if body.mode == "live":
        raise ProblemError(
            422, "action.execution_disabled", "Live execution disabled", "Only dry_run and simulate are available."
        )
    await temporal._client(services)
    async with tenant_tx(services, p) as conn:
        v = (
            await conn.execute(
                text("SELECT id, definition FROM playbook_versions WHERE playbook_id = :p AND status = 'published'"),
                {"p": playbook_id},
            )
        ).one_or_none()
        if v is None:
            raise ProblemError(409, "playbook.not_published", "Not published", "Publish a version before running it.")
        if not (await conn.execute(text("SELECT 1 FROM incidents WHERE id = :i"), {"i": body.incident_id})).first():
            raise not_found("Incident")
        run_id = (
            await conn.execute(
                text(
                    "INSERT INTO workflow_runs (tenant_id, playbook_version_id, incident_id, mode, started_by) "
                    "VALUES (app_tenant(), :v, :i, :m, :u) RETURNING id"
                ),
                {"v": v.id, "i": body.incident_id, "m": body.mode, "u": p.user_id},
            )
        ).scalar_one()
        await record(
            conn,
            p,
            "playbook.run",
            target_type="workflow_run",
            target_id=run_id,
            details={"playbook": str(playbook_id), "mode": body.mode, "incident": str(body.incident_id)},
        )
    steps = [
        {"id": s["id"], "requires": s.get("requires", []), "on_failure": s.get("on_failure", "stop")}
        for s in v.definition["steps"]
    ]
    workflow_id = await temporal.start_playbook(
        services, str(run_id), steps, v.definition.get("approval_timeout_minutes", 30) * 60
    )
    async with tenant_tx(services, p) as conn:
        await conn.execute(
            text("UPDATE workflow_runs SET temporal_workflow_id = :w WHERE id = :i"), {"w": workflow_id, "i": run_id}
        )
        row = (await conn.execute(text(f"{_RUN_SELECT} WHERE r.id = :i"), {"i": run_id})).one()  # nosec B608
        return WorkflowRunOut(**row._mapping)


@router.get("/workflow-runs", response_model=list[WorkflowRunOut], **requires("playbook:read"))
async def list_runs(
    services: Svc, p: P, incident_id: UUID | None = None, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[WorkflowRunOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(
            text(
                f"{_RUN_SELECT} WHERE (CAST(:i AS uuid) IS NULL OR r.incident_id = :i) ORDER BY r.started_at DESC "
                f"LIMIT :l"
            ),  # nosec B608
            {"i": incident_id, "l": limit},
        )
        return [WorkflowRunOut(**r._mapping) for r in rows]


@router.get("/workflow-runs/{workflow_run_id}", response_model=WorkflowRunOut, **requires("playbook:read"))
async def get_run(workflow_run_id: UUID, services: Svc, p: P) -> WorkflowRunOut:
    async with tenant_tx(services, p) as conn:
        row = (await conn.execute(text(f"{_RUN_SELECT} WHERE r.id = :i"), {"i": workflow_run_id})).one_or_none()  # nosec B608
    if row is None:
        raise not_found("Workflow run")
    return WorkflowRunOut(**row._mapping)


@router.post("/workflow-runs/{workflow_run_id}/cancel", response_model=WorkflowRunOut, **requires("playbook:run"))
async def cancel_run(workflow_run_id: UUID, services: Svc, p: P) -> WorkflowRunOut:
    async with tenant_tx(services, p) as conn:
        run = (
            await conn.execute(
                text("SELECT status, temporal_workflow_id FROM workflow_runs WHERE id = :i FOR UPDATE"),
                {"i": workflow_run_id},
            )
        ).one_or_none()
        if run is None:
            raise not_found("Workflow run")
        if run.status != "running":
            raise ProblemError(409, "run.not_running", "Not running", f"The run is {run.status}.")
        await conn.execute(
            text("UPDATE workflow_runs SET status = 'cancelled', ended_at = now() WHERE id = :i"),
            {"i": workflow_run_id},
        )
        await conn.execute(
            text(
                "UPDATE action_requests SET status = 'cancelled', updated_at = now() WHERE workflow_run_id = :i "
                "AND status IN ('pending_approval', 'approved')"
            ),
            {"i": workflow_run_id},
        )
        await record(conn, p, "playbook.run.cancel", target_type="workflow_run", target_id=workflow_run_id)
    if run.temporal_workflow_id:
        await temporal.cancel(services, run.temporal_workflow_id)
    return await get_run(workflow_run_id, services, p)
