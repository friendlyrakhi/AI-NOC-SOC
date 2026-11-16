"""Incidents, timeline, tasks, ITSM links, correlation rules and SLA policy (docs/05 §2.6).

Portal views: ``portal=noc`` returns NOC and joint incidents, ``portal=soc`` SOC and joint, so
a joint incident appears in both portals. Status changes keep MTTA/MTTR timestamps; every
change is written to the append-only timeline and the tenant audit log.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app import live
from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.core.tenancy.common import record, tenant_tx
from app.errors import ProblemError, not_found
from app.incidents import store
from app.incidents.correlation import BUILTIN_RULES, RULE_KEYS, effective_rules
from app.incidents.engine import INCIDENT_TO_ITSM, ITSM_STATE_NAMES
from app.incidents.sla import compute_metrics, evaluate, merged_targets
from app.integrations.common import build
from app.services import Services, get_services
from nocsoc_connector_sdk import ActionInvocation

router = APIRouter(tags=["incidents"])
Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]

IncidentStatus = Literal["open", "investigating", "contained", "mitigated", "resolved", "closed"]
Priority = Literal["P1", "P2", "P3", "P4"]
Severity = Literal["critical", "high", "medium", "low", "info"]


# ============================================================ models
class ServiceRef(BaseModel):
    id: UUID
    name: str
    tier: int


class SlaOut(BaseModel):
    ack_due_at: datetime
    resolve_due_at: datetime
    ack_breached: bool
    resolve_breached: bool


class ExternalTicketOut(BaseModel):
    system: str
    external_number: str
    external_state: str
    sync_state: str
    last_sync_origin: str
    last_synced_at: datetime


class IncidentOut(BaseModel):
    id: UUID
    number: str
    domain: Literal["noc", "soc", "joint"]
    title: str
    summary: str
    severity: Severity
    priority: Priority
    status: IncidentStatus
    commander_id: UUID | None
    assignee_id: UUID | None
    services: list[ServiceRef]
    detected_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    created_by_type: Literal["correlation", "user"]
    alert_count: int
    sla: SlaOut
    external_tickets: list[ExternalTicketOut]
    sandbox: bool
    updated_at: datetime
    version: int


class IncidentPage(BaseModel):
    items: list[IncidentOut]
    total: int
    limit: int
    offset: int


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    domain: Literal["noc", "soc"]
    severity: Severity
    summary: str = Field(default="", max_length=8000)
    alert_ids: list[UUID] = Field(default_factory=list, max_length=200)


class IncidentPatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    summary: str | None = Field(default=None, max_length=8000)
    priority: Priority | None = None
    assignee_id: UUID | None = None
    commander_id: UUID | None = None
    clear_assignee: bool = False
    version: int = Field(ge=1)


class StatusChange(BaseModel):
    to: IncidentStatus
    reason: str | None = Field(default=None, max_length=1000)
    version: int = Field(ge=1)


class Escalation(BaseModel):
    to_domain: Literal["joint"] = "joint"
    reason: str = Field(min_length=1, max_length=1000)


class AlertLinks(BaseModel):
    alert_ids: list[UUID] = Field(min_length=1, max_length=200)


class CommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


class TimelineOut(BaseModel):
    id: int
    kind: str
    actor_type: str
    actor_id: UUID | None
    actor_name: str | None
    body: dict[str, Any]
    at: datetime


class TaskOut(BaseModel):
    id: UUID
    title: str
    status: Literal["open", "in_progress", "done"]
    assignee_id: UUID | None
    due_at: datetime | None
    runbook_ref: str | None
    updated_at: datetime
    version: int


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    assignee_id: UUID | None = None
    due_at: datetime | None = None
    runbook_ref: str | None = Field(default=None, max_length=300)


class TaskPatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    status: Literal["open", "in_progress", "done"] | None = None
    assignee_id: UUID | None = None
    version: int = Field(ge=1)


class LinkedAlert(BaseModel):
    id: UUID
    title: str
    severity: Severity
    status: str
    domain: str
    connector_id: str
    asset_name: str | None
    last_seen: datetime
    occurrence_count: int
    added_by: str
    rule_key: str | None
    reason: str


# ============================================================ helpers
_INCIDENT_SELECT = """
SELECT i.*,
       (SELECT count(*) FROM incident_alerts ia WHERE ia.incident_id = i.id) AS alert_count,
       coalesce((SELECT json_agg(json_build_object('id', s.id, 'name', s.name, 'tier', s.tier) ORDER BY s.tier, s.name)
                   FROM services s WHERE s.id = ANY(i.impacted_service_ids)), '[]') AS services,
       coalesce((SELECT json_agg(json_build_object('system', t.system, 'external_number', t.external_number,
                                 'external_state', t.external_state, 'sync_state', t.sync_state,
                                 'last_sync_origin', t.last_sync_origin, 'last_synced_at', t.last_synced_at))
                   FROM external_tickets t WHERE t.incident_id = i.id), '[]') AS external_tickets
  FROM incidents i
"""


async def _targets(conn: AsyncConnection) -> dict[str, dict[str, int]]:
    custom = (await conn.execute(text("SELECT targets FROM sla_policies"))).scalar_one_or_none()
    return merged_targets(custom)


def _out(row: Any, targets: dict[str, dict[str, int]], now: datetime) -> IncidentOut:
    m = dict(row._mapping)
    sla = evaluate(m["priority"], m["detected_at"], m["acknowledged_at"], m["resolved_at"], now, targets)
    return IncidentOut(
        **{k: m[k] for k in IncidentOut.model_fields if k in m and k != "sla"}, sla=SlaOut(**sla.__dict__)
    )


async def _load(conn: AsyncConnection, incident_id: UUID) -> IncidentOut:
    row = (await conn.execute(text(f"{_INCIDENT_SELECT} WHERE i.id = :id"), {"id": incident_id})).one_or_none()  # nosec B608
    if row is None:
        raise not_found("Incident")
    return _out(row, await _targets(conn), datetime.now(UTC))


async def _check_member(conn: AsyncConnection, user_id: UUID | None) -> None:
    if user_id is None:
        return
    ok = (
        await conn.execute(
            text("SELECT 1 FROM memberships WHERE tenant_id = app_tenant() AND user_id = :u AND status = 'active'"),
            {"u": user_id},
        )
    ).first()
    if not ok:
        raise ProblemError(
            422, "incident.unknown_user", "Unknown user", "Assignees must be active members of this tenant."
        )


def _portal_clause(portal: str | None, domain: str | None) -> tuple[str, dict[str, Any]]:
    if domain:
        return "i.domain = :dom", {"dom": domain}
    if portal:
        return "i.domain IN (:dom, 'joint')", {"dom": portal}
    return "TRUE", {}


async def _notify(services: Services, p: Principal, incident_id: UUID | str) -> None:
    await live.publish(services.valkey, p.tenant_id, {"type": "incident.changed", "id": str(incident_id)})


# ============================================================ list, metrics, create
SORTS = {
    "priority": "i.priority, i.detected_at DESC, i.id",
    "detected": "i.detected_at DESC, i.id",
    "updated": "i.updated_at DESC, i.id",
}


@router.get("/incidents", response_model=IncidentPage, **requires("incident:read"))
async def list_incidents(
    services: Svc,
    p: P,
    portal: Literal["noc", "soc"] | None = None,
    domain: Literal["noc", "soc", "joint"] | None = None,
    status_: Annotated[list[IncidentStatus] | None, Query(alias="status")] = None,
    priority: Annotated[list[Priority] | None, Query()] = None,
    open_only: bool = False,
    q: str | None = Query(default=None, max_length=200),
    sort: Literal["priority", "detected", "updated"] = "priority",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> IncidentPage:
    clause, params = _portal_clause(portal, domain)
    where = [clause]
    if status_:
        where.append("i.status = ANY(:st)")
        params["st"] = status_
    if open_only:
        where.append("i.status NOT IN ('resolved', 'closed')")
    if priority:
        where.append("i.priority = ANY(:pr)")
        params["pr"] = priority
    if q:
        where.append("(i.search @@ plainto_tsquery('simple', :q) OR i.number ILIKE :ql)")
        params["q"] = q
        params["ql"] = q.replace("\\", "").replace("%", "").replace("_", "") + "%"
    sql_where = " AND ".join(where)  # fixed fragments; values are bound
    async with tenant_tx(services, p) as conn:
        total = (await conn.execute(text(f"SELECT count(*) FROM incidents i WHERE {sql_where}"), params)).scalar_one()  # nosec B608
        rows = await conn.execute(
            text(f"{_INCIDENT_SELECT} WHERE {sql_where} ORDER BY {SORTS[sort]} LIMIT :l OFFSET :o"),  # nosec B608
            {**params, "l": limit, "o": offset},
        )
        targets = await _targets(conn)
        now = datetime.now(UTC)
        items = [_out(r, targets, now) for r in rows]
    return IncidentPage(items=items, total=total, limit=limit, offset=offset)


class MetricsOut(BaseModel):
    portal: str | None
    days: int
    total: int
    open: int
    acknowledged: int
    resolved: int
    mtta_seconds: float | None
    mttr_seconds: float | None
    ack_sla_attainment: float | None
    resolve_sla_attainment: float | None
    by_priority: dict[str, int]


@router.get("/incidents/metrics", response_model=MetricsOut, **requires("incident:read"))
async def incident_metrics(
    services: Svc,
    p: P,
    portal: Literal["noc", "soc"] | None = None,
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> MetricsOut:
    """MTTA = mean(acknowledged - detected) over acknowledged incidents; MTTR = mean(resolved -
    detected) over resolved incidents. SLA attainment counts only incidents whose target has
    either been met or has already passed."""
    clause, params = _portal_clause(portal, None)
    params["since"] = datetime.now(UTC) - timedelta(days=days)
    async with tenant_tx(services, p) as conn:
        rows = list(
            await conn.execute(
                text(
                    "SELECT priority, status, detected_at, acknowledged_at, resolved_at FROM incidents i "
                    f"WHERE {clause} AND detected_at >= :since"  # nosec B608
                ),
                params,
            )
        )
        targets = await _targets(conn)
    return MetricsOut(portal=portal, days=days, **compute_metrics(rows, targets, datetime.now(UTC)))


@router.post(
    "/incidents", response_model=IncidentOut, status_code=status.HTTP_201_CREATED, **requires("incident:create")
)
async def create_incident(body: IncidentCreate, services: Svc, p: P) -> IncidentOut:
    async with tenant_tx(services, p) as conn:
        await store.lock_tenant_incidents(conn)
        service_ids: list[str] = []
        if body.alert_ids:
            rows = list(
                await conn.execute(
                    text("SELECT id, service_id, sandbox FROM alerts WHERE id = ANY(:ids)"), {"ids": body.alert_ids}
                )
            )
            if len(rows) != len(set(body.alert_ids)):
                raise not_found("Alert")
            service_ids = sorted({str(r.service_id) for r in rows if r.service_id})
        priority = {"critical": "P1", "high": "P2", "medium": "P3"}.get(body.severity, "P4")
        incident_id, number = await store.create_incident(
            conn,
            domain=body.domain,
            title=body.title,
            severity=body.severity,
            priority=priority,
            detected_at=datetime.now(UTC),
            services=service_ids,
            created_by_type="user",
            created_by=p.user_id,
            summary=body.summary,
            sandbox=False,
        )
        for alert_id in body.alert_ids:
            if not await store.link_alert(
                conn,
                incident_id,
                alert_id,
                added_by="user",
                rule_key=None,
                reason="Linked by analyst",
                actor_id=p.user_id,
            ):
                raise ProblemError(
                    409, "incident.alert_linked", "Alert already linked", "An alert is already in an incident."
                )
        await record(
            conn, p, "incident.create", target_type="incident", target_id=incident_id, details={"number": number}
        )
        out = await _load(conn, incident_id)
    await _notify(services, p, incident_id)
    return out


# ============================================================ one incident
@router.get("/incidents/{incident_id}", response_model=IncidentOut, **requires("incident:read"))
async def get_incident(incident_id: UUID, services: Svc, p: P) -> IncidentOut:
    async with tenant_tx(services, p) as conn:
        return await _load(conn, incident_id)


@router.patch("/incidents/{incident_id}", response_model=IncidentOut, **requires("incident:update"))
async def patch_incident(incident_id: UUID, body: IncidentPatch, services: Svc, p: P) -> IncidentOut:
    async with tenant_tx(services, p) as conn:
        current = await _load(conn, incident_id)
        await _check_member(conn, body.assignee_id)
        await _check_member(conn, body.commander_id)
        sets, params = ["updated_at = now()", "version = version + 1"], {"id": incident_id, "v": body.version}
        changed: dict[str, Any] = {}
        for field_ in ("title", "summary", "priority", "assignee_id", "commander_id"):
            value = getattr(body, field_)
            if value is not None:
                sets.append(f"{field_} = :{field_}")
                params[field_] = value
                changed[field_] = value
        if body.clear_assignee:
            sets.append("assignee_id = NULL")
            changed["assignee_id"] = None
        result = await conn.execute(
            text(f"UPDATE incidents SET {', '.join(sets)} WHERE id = :id AND version = :v"),  # nosec B608
            params,
        )
        if result.rowcount == 0:
            raise ProblemError(409, "conflict.version", "Changed by someone else", "Reload and try again.")
        if "assignee_id" in changed or "commander_id" in changed:
            await store.timeline(
                conn,
                incident_id,
                "assignment",
                {k: str(v) if v else None for k, v in changed.items() if k in ("assignee_id", "commander_id")},
                actor_type="user",
                actor_id=p.user_id,
            )
        if "priority" in changed and changed["priority"] != current.priority:
            await store.timeline(
                conn,
                incident_id,
                "state_change",
                {"priority_from": current.priority, "priority_to": changed["priority"]},
                actor_type="user",
                actor_id=p.user_id,
            )
        await record(
            conn,
            p,
            "incident.update",
            target_type="incident",
            target_id=incident_id,
            details={k: str(v) for k, v in changed.items() if k != "summary"},
        )
        out = await _load(conn, incident_id)
    await _notify(services, p, incident_id)
    return out


@router.post("/incidents/{incident_id}/status", response_model=IncidentOut, **requires("incident:update"))
async def change_status(incident_id: UUID, body: StatusChange, services: Svc, p: P) -> IncidentOut:
    async with tenant_tx(services, p) as conn:
        current = await _load(conn, incident_id)
        if body.to not in store.STATUS_TRANSITIONS[current.status]:
            raise ProblemError(
                409,
                "incident.invalid_transition",
                "Transition not allowed",
                f"An incident in '{current.status}' cannot move to '{body.to}'.",
            )
        ok = await store.change_status(
            conn,
            incident_id,
            current.status,
            body.to,
            actor_type="user",
            actor_id=p.user_id,
            reason=body.reason,
            version=body.version,
        )
        if not ok:
            raise ProblemError(409, "conflict.version", "Changed by someone else", "Reload and try again.")
        await _push_itsm(conn, services, p, incident_id, body.to)
        await record(
            conn,
            p,
            "incident.status",
            target_type="incident",
            target_id=incident_id,
            details={"from": current.status, "to": body.to},
        )
        out = await _load(conn, incident_id)
    await _notify(services, p, incident_id)
    return out


@router.post("/incidents/{incident_id}/escalate", response_model=IncidentOut, **requires("incident:escalate"))
async def escalate(incident_id: UUID, body: Escalation, services: Svc, p: P) -> IncidentOut:
    async with tenant_tx(services, p) as conn:
        current = await _load(conn, incident_id)
        if current.domain == "joint":
            raise ProblemError(409, "incident.already_joint", "Already joint", "The incident is already shared.")
        await conn.execute(
            text("UPDATE incidents SET domain = 'joint', updated_at = now(), version = version + 1 WHERE id = :i"),
            {"i": incident_id},
        )
        await store.timeline(
            conn,
            incident_id,
            "escalation",
            {"from": current.domain, "to": "joint", "reason": body.reason},
            actor_type="user",
            actor_id=p.user_id,
        )
        await record(
            conn,
            p,
            "incident.escalate",
            target_type="incident",
            target_id=incident_id,
            details={"from": current.domain, "to": "joint"},
        )
        out = await _load(conn, incident_id)
    await _notify(services, p, incident_id)
    return out


@router.get("/incidents/{incident_id}/alerts", response_model=list[LinkedAlert], **requires("incident:read"))
async def incident_alerts(incident_id: UUID, services: Svc, p: P) -> list[LinkedAlert]:
    async with tenant_tx(services, p) as conn:
        await _load(conn, incident_id)
        rows = await conn.execute(
            text(
                "SELECT a.id, a.title, a.severity, a.status, a.domain, a.connector_id, s.name AS asset_name, "
                "a.last_seen, "
                "a.occurrence_count, ia.added_by, ia.rule_key, ia.reason FROM incident_alerts ia "
                "JOIN alerts a ON a.id = ia.alert_id LEFT JOIN assets s ON s.id = a.asset_id "
                "WHERE ia.incident_id = :i ORDER BY ia.added_at, a.id"
            ),
            {"i": incident_id},
        )
        return [LinkedAlert(**r._mapping) for r in rows]


@router.post("/incidents/{incident_id}/alerts", response_model=IncidentOut, **requires("incident:update"))
async def link_alerts(incident_id: UUID, body: AlertLinks, services: Svc, p: P) -> IncidentOut:
    async with tenant_tx(services, p) as conn:
        await _load(conn, incident_id)
        found = {
            r[0]
            for r in await conn.execute(text("SELECT id FROM alerts WHERE id = ANY(:ids)"), {"ids": body.alert_ids})
        }
        if found != set(body.alert_ids):
            raise not_found("Alert")
        linked = 0
        for alert_id in body.alert_ids:
            linked += await store.link_alert(
                conn,
                incident_id,
                alert_id,
                added_by="user",
                rule_key=None,
                reason="Linked by analyst",
                actor_id=p.user_id,
            )
        if linked != len(body.alert_ids):
            raise ProblemError(
                409, "incident.alert_linked", "Alert already linked", "An alert is already in an incident."
            )
        await record(
            conn,
            p,
            "incident.alerts.link",
            target_type="incident",
            target_id=incident_id,
            details={"alerts": [str(a) for a in body.alert_ids]},
        )
        out = await _load(conn, incident_id)
    await _notify(services, p, incident_id)
    return out


@router.delete(
    "/incidents/{incident_id}/alerts/{alert_id}", status_code=status.HTTP_204_NO_CONTENT, **requires("incident:update")
)
async def unlink_alert(incident_id: UUID, alert_id: UUID, services: Svc, p: P) -> Response:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text("DELETE FROM incident_alerts WHERE incident_id = :i AND alert_id = :a RETURNING alert_id"),
                {"i": incident_id, "a": alert_id},
            )
        ).one_or_none()
        if row is None:
            raise not_found("Linked alert")
        await store.timeline(
            conn, incident_id, "alert_removed", {"alert_id": str(alert_id)}, actor_type="user", actor_id=p.user_id
        )
        await record(
            conn,
            p,
            "incident.alerts.unlink",
            target_type="incident",
            target_id=incident_id,
            details={"alert": str(alert_id)},
        )
    await _notify(services, p, incident_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/incidents/{incident_id}/timeline", response_model=list[TimelineOut], **requires("incident:read"))
async def get_timeline(
    incident_id: UUID,
    services: Svc,
    p: P,
    after: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> list[TimelineOut]:
    """Oldest first. ``after`` is the last entry id already seen (for live polling)."""
    async with tenant_tx(services, p) as conn:
        await _load(conn, incident_id)
        rows = await conn.execute(
            text(
                "SELECT t.id, t.kind, t.actor_type, t.actor_id, u.display_name AS actor_name, t.body, t.at "
                "FROM timeline_entries t LEFT JOIN users u ON u.id = t.actor_id "
                "WHERE t.incident_id = :i AND t.id > :after ORDER BY t.id LIMIT :l"
            ),
            {"i": incident_id, "after": after, "l": limit},
        )
        return [TimelineOut(**r._mapping) for r in rows]


@router.post(
    "/incidents/{incident_id}/comments",
    status_code=status.HTTP_201_CREATED,
    response_model=TimelineOut,
    **requires("incident:comment"),
)
async def add_comment(incident_id: UUID, body: CommentIn, services: Svc, p: P) -> TimelineOut:
    async with tenant_tx(services, p) as conn:
        await _load(conn, incident_id)
        await store.timeline(conn, incident_id, "comment", {"text": body.body}, actor_type="user", actor_id=p.user_id)
        row = (
            await conn.execute(
                text(
                    "SELECT t.id, t.kind, t.actor_type, t.actor_id, u.display_name AS actor_name, t.body, t.at "
                    "FROM timeline_entries t LEFT JOIN users u ON u.id = t.actor_id "
                    "WHERE t.incident_id = :i ORDER BY t.id DESC LIMIT 1"
                ),
                {"i": incident_id},
            )
        ).one()
        await record(conn, p, "incident.comment", target_type="incident", target_id=incident_id)
    await _notify(services, p, incident_id)
    return TimelineOut(**row._mapping)


# ============================================================ tasks
@router.get("/incidents/{incident_id}/tasks", response_model=list[TaskOut], **requires("incident:read"))
async def list_tasks(incident_id: UUID, services: Svc, p: P) -> list[TaskOut]:
    async with tenant_tx(services, p) as conn:
        await _load(conn, incident_id)
        rows = await conn.execute(
            text(
                "SELECT id, title, status, assignee_id, due_at, runbook_ref, updated_at, version FROM incident_tasks "
                "WHERE incident_id = :i ORDER BY created_at, id"
            ),
            {"i": incident_id},
        )
        return [TaskOut(**r._mapping) for r in rows]


@router.post(
    "/incidents/{incident_id}/tasks",
    response_model=TaskOut,
    status_code=status.HTTP_201_CREATED,
    **requires("incident:update"),
)
async def create_task(incident_id: UUID, body: TaskCreate, services: Svc, p: P) -> TaskOut:
    async with tenant_tx(services, p) as conn:
        await _load(conn, incident_id)
        await _check_member(conn, body.assignee_id)
        row = (
            await conn.execute(
                text(
                    "INSERT INTO incident_tasks (tenant_id, incident_id, title, assignee_id, due_at, runbook_ref) "
                    "VALUES (app_tenant(), :i, :t, :a, :d, :r) "
                    "RETURNING id, title, status, assignee_id, due_at, runbook_ref, updated_at, version"
                ),
                {"i": incident_id, "t": body.title, "a": body.assignee_id, "d": body.due_at, "r": body.runbook_ref},
            )
        ).one()
        await store.timeline(
            conn,
            incident_id,
            "task",
            {"task_id": str(row.id), "title": body.title, "status": "open"},
            actor_type="user",
            actor_id=p.user_id,
        )
        await record(conn, p, "incident.task.create", target_type="incident", target_id=incident_id)
    await _notify(services, p, incident_id)
    return TaskOut(**row._mapping)


@router.patch("/incidents/{incident_id}/tasks/{task_id}", response_model=TaskOut, **requires("incident:update"))
async def patch_task(incident_id: UUID, task_id: UUID, body: TaskPatch, services: Svc, p: P) -> TaskOut:
    async with tenant_tx(services, p) as conn:
        await _check_member(conn, body.assignee_id)
        sets, params = (
            ["updated_at = now()", "version = version + 1"],
            {"i": incident_id, "t": task_id, "v": body.version},
        )
        for field_ in ("title", "status", "assignee_id"):
            value = getattr(body, field_)
            if value is not None:
                sets.append(f"{field_} = :{field_}")
                params[field_] = value
        row = (
            await conn.execute(
                text(
                    f"UPDATE incident_tasks SET {', '.join(sets)} WHERE id = :t AND incident_id = :i AND version = :v "
                    f""  # nosec B608
                    "RETURNING id, title, status, assignee_id, due_at, runbook_ref, updated_at, version"
                ),
                params,
            )
        ).one_or_none()
        if row is None:
            exists = (
                await conn.execute(text("SELECT 1 FROM incident_tasks WHERE id = :t AND incident_id = :i"), params)
            ).first()
            if not exists:
                raise not_found("Task")
            raise ProblemError(409, "conflict.version", "Changed by someone else", "Reload and try again.")
        await store.timeline(
            conn,
            incident_id,
            "task",
            {"task_id": str(task_id), "title": row.title, "status": row.status},
            actor_type="user",
            actor_id=p.user_id,
        )
        await record(conn, p, "incident.task.update", target_type="incident", target_id=incident_id)
    await _notify(services, p, incident_id)
    return TaskOut(**row._mapping)


# ============================================================ ITSM (ServiceNow sandbox)
class ExternalTicketCreate(BaseModel):
    system: Literal["servicenow"] = "servicenow"


async def _servicenow_instance(conn: AsyncConnection) -> Any:
    inst = (
        await conn.execute(
            text(
                "SELECT id, config FROM connector_instances WHERE definition_id = 'servicenow.itsm' AND enabled "
                "ORDER BY created_at LIMIT 1"
            )
        )
    ).one_or_none()
    if inst is None:
        raise ProblemError(
            409, "incident.no_itsm", "No ServiceNow integration", "Add an enabled ServiceNow sandbox integration first."
        )
    return inst


async def _push_itsm(conn: AsyncConnection, services: Services, p: Principal, incident_id: UUID, status_: str) -> None:
    """Outbound sync of a status change. Records the pushed state so the echo is ignored."""
    link = (
        await conn.execute(
            text("SELECT id, instance_id, external_id, external_number FROM external_tickets WHERE incident_id = :i"),
            {"i": incident_id},
        )
    ).one_or_none()
    state = INCIDENT_TO_ITSM.get(status_)
    if link is None or state is None or link.instance_id is None:
        return
    inst = (
        await conn.execute(text("SELECT config FROM connector_instances WHERE id = :i"), {"i": link.instance_id})
    ).one_or_none()
    if inst is None:
        return
    connector = build("servicenow.itsm", p.tenant_id or "", link.instance_id, inst.config)
    result = await connector.execute_action(
        ActionInvocation(
            key="itsm.update_incident",
            mode=services.settings.execution_mode,
            target={"sys_id": link.external_id},
            params={"state": state},
        )
    )
    ok = result.status == "succeeded"
    await conn.execute(
        text(
            "UPDATE external_tickets SET last_pushed_state = :s, sync_state = :ss, last_synced_at = now(), "
            "last_sync_origin = 'platform' WHERE id = :i"
        ),
        {"s": state, "ss": "synced" if ok else "error", "i": link.id},
    )
    await store.timeline(
        conn,
        incident_id,
        "external_sync",
        {
            "system": "servicenow",
            "number": link.external_number,
            "direction": "outbound",
            "state": ITSM_STATE_NAMES.get(state, state),
            "mode": result.mode,
            "simulated": result.simulated,
        },
    )


@router.post(
    "/incidents/{incident_id}/external-tickets",
    response_model=IncidentOut,
    status_code=status.HTTP_201_CREATED,
    **requires("incident:sync"),
)
async def create_external_ticket(incident_id: UUID, body: ExternalTicketCreate, services: Svc, p: P) -> IncidentOut:
    """Opens a ServiceNow incident through the sandbox connector (simulated action; nothing
    leaves the platform) and links it for two-way status sync."""
    async with tenant_tx(services, p) as conn:
        current = await _load(conn, incident_id)
        if current.external_tickets:
            raise ProblemError(409, "incident.ticket_exists", "Already linked", "This incident already has a ticket.")
        inst = await _servicenow_instance(conn)
        connector = build("servicenow.itsm", p.tenant_id or "", inst.id, inst.config)
        result = await connector.execute_action(
            ActionInvocation(
                key="itsm.create_incident",
                mode=services.settings.execution_mode,
                target={"ref": str(incident_id)},
                params={
                    "short_description": f"{current.number}: {current.title}"[:160],
                    "priority": current.priority[1],
                },
            )
        )
        if result.status != "succeeded" or not result.after.get("sys_id"):
            raise ProblemError(502, "incident.itsm_failed", "ServiceNow call failed", result.message[:300])
        await conn.execute(
            text(
                "INSERT INTO external_tickets (tenant_id, incident_id, instance_id, system, external_id, "
                "external_number, "
                "external_state, last_pushed_state, last_sync_origin) "
                "VALUES (app_tenant(), :i, :inst, 'servicenow', :x, :n, 'new', '1', 'platform')"
            ),
            {"i": incident_id, "inst": inst.id, "x": result.after["sys_id"], "n": result.after["number"]},
        )
        await store.timeline(
            conn,
            incident_id,
            "external_sync",
            {
                "system": "servicenow",
                "number": result.after["number"],
                "direction": "outbound",
                "state": "new",
                "mode": result.mode,
                "simulated": result.simulated,
            },
            actor_type="user",
            actor_id=p.user_id,
        )
        await record(
            conn,
            p,
            "incident.external_ticket.create",
            target_type="incident",
            target_id=incident_id,
            details={"system": "servicenow", "number": result.after["number"], "simulated": result.simulated},
        )
        out = await _load(conn, incident_id)
    await _notify(services, p, incident_id)
    return out


# ============================================================ correlation rules and SLA policy
class RuleOut(BaseModel):
    key: str
    title: str
    description: str
    enabled: bool
    window_minutes: int
    default_window_minutes: int


class RulePatch(BaseModel):
    enabled: bool
    window_minutes: int = Field(ge=1, le=1440)


@router.get("/correlation-rules", response_model=list[RuleOut], **requires("incident:read"))
async def list_rules(services: Svc, p: P) -> list[RuleOut]:
    async with tenant_tx(services, p) as conn:
        overrides = {
            r.rule_key: (r.enabled, r.window_minutes)
            for r in await conn.execute(text("SELECT rule_key, enabled, window_minutes FROM correlation_overrides"))
        }
    defaults = {r.key: r.window_minutes for r in BUILTIN_RULES}
    return [
        RuleOut(
            key=r.key,
            title=r.title,
            description=r.description,
            enabled=r.enabled,
            window_minutes=r.window_minutes,
            default_window_minutes=defaults[r.key],
        )
        for r in effective_rules(overrides)
    ]


@router.patch("/correlation-rules/{key}", response_model=list[RuleOut], **requires("correlation:manage", step_up=True))
async def patch_rule(key: str, body: RulePatch, services: Svc, p: P) -> list[RuleOut]:
    if key not in RULE_KEYS:
        raise not_found("Correlation rule")
    async with tenant_tx(services, p) as conn:
        await conn.execute(
            text(
                "INSERT INTO correlation_overrides (tenant_id, rule_key, enabled, window_minutes) "
                "VALUES (app_tenant(), :k, :e, :w) ON CONFLICT (tenant_id, rule_key) "
                "DO UPDATE SET enabled = EXCLUDED.enabled, window_minutes = EXCLUDED.window_minutes, updated_at = now()"
            ),
            {"k": key, "e": body.enabled, "w": body.window_minutes},
        )
        await record(
            conn, p, "correlation.rule.update", target_type="correlation_rule", target_id=key, details=body.model_dump()
        )
    return await list_rules(services, p)


class SlaTarget(BaseModel):
    ack: int = Field(ge=1, le=100_000)
    resolve: int = Field(ge=1, le=1_000_000)


class SlaPolicy(BaseModel):
    targets: dict[Priority, SlaTarget]
    custom: bool = False


@router.get("/sla-policy", response_model=SlaPolicy, **requires("incident:read"))
async def get_sla(services: Svc, p: P) -> SlaPolicy:
    async with tenant_tx(services, p) as conn:
        custom = (await conn.execute(text("SELECT targets FROM sla_policies"))).scalar_one_or_none()
    return SlaPolicy(targets=merged_targets(custom), custom=custom is not None)  # type: ignore[arg-type]


@router.put("/sla-policy", response_model=SlaPolicy, **requires("sla:manage", step_up=True))
async def put_sla(body: SlaPolicy, services: Svc, p: P) -> SlaPolicy:
    targets = {k: v.model_dump() for k, v in body.targets.items()}
    for prio, t in targets.items():
        if t["resolve"] < t["ack"]:
            raise ProblemError(
                422, "sla.invalid", "Invalid SLA", f"{prio}: resolve target must not be shorter than ack."
            )
    async with tenant_tx(services, p) as conn:
        await conn.execute(
            text(
                "INSERT INTO sla_policies (tenant_id, targets, updated_by) VALUES (app_tenant(), CAST(:t AS jsonb), "
                ":u) "
                "ON CONFLICT (tenant_id) DO UPDATE SET targets = EXCLUDED.targets, updated_by = EXCLUDED.updated_by, "
                "updated_at = now()"
            ),
            {"t": json.dumps(targets), "u": p.user_id},
        )
        await record(conn, p, "sla.update", target_type="sla_policy", details={str(k): v for k, v in targets.items()})
    return SlaPolicy(targets=merged_targets(targets), custom=True)  # type: ignore[arg-type]
