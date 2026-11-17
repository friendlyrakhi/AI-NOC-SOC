"""Threat hunting (P6): saved hunts and asynchronous hunt runs over the tenant's events.

A hunt is a saved ``EventQuery`` (the same constrained query the event search accepts). Running
it creates a ``hunt_runs`` row and executes in the background; results (up to 200 hits plus
facets) are stored with the run, so they stay reviewable and can be attached to an incident.
Per tenant at most ``hunt_max_concurrent`` runs at once and ``hunt_runs_per_hour`` per hour.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.core.tenancy.common import record, tenant_tx
from app.errors import ProblemError, not_found
from app.incidents import store as incident_store
from app.search_api import EventSearchIn, run_event_search, store
from app.searchstore import EventQuery
from app.services import Services, get_services

logger = logging.getLogger(__name__)
router = APIRouter(tags=["hunting"])
Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]

MAX_RESULTS = 200
STALE_AFTER = timedelta(minutes=5)
_TASKS: set[asyncio.Task[None]] = set()


class HuntIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    query: EventQuery


class HuntOut(BaseModel):
    id: UUID
    name: str
    description: str
    query: dict[str, Any]
    created_at: datetime
    last_run_at: datetime | None = None
    last_hit_count: int | None = None


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hunt_id: UUID | None = None
    query: EventQuery | None = None


class HuntRunOut(BaseModel):
    id: UUID
    hunt_id: UUID | None
    hunt_name: str | None = None
    query: dict[str, Any]
    status: Literal["queued", "running", "succeeded", "failed"]
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    hit_count: int
    truncated: bool
    error: str | None


class HuntResultsOut(HuntRunOut):
    results: list[dict[str, Any]]
    facets: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)


class AttachIn(BaseModel):
    incident_id: UUID
    note: str = Field(default="", max_length=1000)


_RUN_COLS = (
    "r.id, r.hunt_id, h.name AS hunt_name, r.query, r.status, r.created_at, r.started_at, r.finished_at, "
    "r.hit_count, r.truncated, r.error"
)


# ------------------------------------------------------------------ saved hunts
@router.get("/hunts", response_model=list[HuntOut], **requires("hunt:run"))
async def list_hunts(services: Svc, p: P) -> list[HuntOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(
            text(
                "SELECT h.id, h.name, h.description, h.query, h.created_at, lr.created_at AS last_run_at, "
                "lr.hit_count AS last_hit_count FROM hunts h LEFT JOIN LATERAL (SELECT created_at, hit_count FROM "
                "hunt_runs r WHERE r.hunt_id = h.id ORDER BY created_at DESC LIMIT 1) lr ON true ORDER BY h.name"
            )
        )
        return [HuntOut(**r._mapping) for r in rows]


@router.post("/hunts", response_model=HuntOut, status_code=status.HTTP_201_CREATED, **requires("hunt:run"))
async def create_hunt(body: HuntIn, services: Svc, p: P) -> HuntOut:
    query = body.query.model_dump(mode="json", exclude_none=True, exclude={"since", "until"})
    async with tenant_tx(services, p) as conn:
        if (await conn.execute(text("SELECT 1 FROM hunts WHERE name = :n"), {"n": body.name})).first():
            raise ProblemError(409, "hunt.name_taken", "Name in use", "Another saved hunt has this name.")
        row = (
            await conn.execute(
                text(
                    "INSERT INTO hunts (tenant_id, name, description, query, created_by) VALUES (app_tenant(), :n, :d, "
                    "CAST(:q AS jsonb), :u) RETURNING id, name, description, query, created_at"
                ),
                {"n": body.name, "d": body.description, "q": json.dumps(query), "u": p.user_id},
            )
        ).one()
        await record(conn, p, "hunt.create", target_type="hunt", target_id=row.id, details={"name": body.name})
    return HuntOut(**row._mapping)


@router.delete("/hunts/{hunt_id}", status_code=status.HTTP_204_NO_CONTENT, **requires("hunt:run"))
async def delete_hunt(hunt_id: UUID, services: Svc, p: P) -> Response:
    async with tenant_tx(services, p) as conn:
        row = (await conn.execute(text("DELETE FROM hunts WHERE id = :i RETURNING name"), {"i": hunt_id})).one_or_none()
        if row is None:
            raise not_found("Hunt")
        await record(conn, p, "hunt.delete", target_type="hunt", target_id=hunt_id, details={"name": row.name})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------------ runs
async def _execute(
    services: Services, tenant: UUID, user: UUID | None, hunt_run_id: UUID, principal: Principal
) -> None:
    async with services.app_db.tenant(tenant, user) as conn:
        row = (
            await conn.execute(
                text("UPDATE hunt_runs SET status = 'running', started_at = now() WHERE id = :i RETURNING query"),
                {"i": hunt_run_id},
            )
        ).one()
    try:
        query = EventQuery.model_validate(row.query)
        result = await run_event_search(services, principal, EventSearchIn(query=query, limit=MAX_RESULTS))
        items = [i.model_dump(mode="json", by_alias=True) for i in result.items]
        facets = {k: [f.model_dump() for f in v] for k, v in result.facets.items()}
        values: dict[str, Any] = {
            "s": "succeeded",
            "n": result.total,
            "t": result.total > len(items),
            "r": json.dumps({"items": items, "facets": facets}),
            "e": None,
        }
    except Exception as exc:
        detail = exc.detail if isinstance(exc, ProblemError) else type(exc).__name__
        logger.warning("hunt run failed: %s", detail)
        values = {
            "s": "failed",
            "n": 0,
            "t": False,
            "r": json.dumps({"items": [], "facets": {}}),
            "e": str(detail)[:500],
        }
    async with services.app_db.tenant(tenant, user) as conn:
        await conn.execute(
            text(
                "UPDATE hunt_runs SET status = :s, finished_at = now(), hit_count = :n, truncated = :t, "
                "results = CAST(:r AS jsonb), error = :e WHERE id = :i"
            ),
            {**values, "i": hunt_run_id},
        )


@router.post("/hunt/queries", response_model=HuntRunOut, status_code=status.HTTP_202_ACCEPTED, **requires("hunt:run"))
async def start_run(body: RunIn, services: Svc, p: P) -> HuntRunOut:
    """Starts a hunt (a saved one, or an ad-hoc query) and returns at once; poll the run."""
    store(services)  # 503 before recording anything if search is not configured
    if (body.hunt_id is None) == (body.query is None):
        raise ProblemError(422, "hunt.query_required", "Query required", "Give either hunt_id or query.")
    settings = services.settings
    async with tenant_tx(services, p) as conn:
        # Runs orphaned by an API restart are closed so they do not hold the concurrency slots.
        await conn.execute(
            text(
                "UPDATE hunt_runs SET status = 'failed', finished_at = now(), error = 'Interrupted' "
                "WHERE status IN ('queued', 'running') AND created_at < now() - make_interval(secs => :s)"
            ),
            {"s": STALE_AFTER.total_seconds()},
        )
        busy, hour = (
            await conn.execute(
                text(
                    "SELECT count(*) FILTER (WHERE status IN ('queued', 'running')), "
                    "count(*) FILTER (WHERE created_at > now() - interval '1 hour') FROM hunt_runs"
                )
            )
        ).one()
        if busy >= settings.hunt_max_concurrent:
            raise ProblemError(429, "hunt.busy", "Hunts running", "Wait for a running hunt to finish.")
        if hour >= settings.hunt_runs_per_hour:
            raise ProblemError(429, "hunt.quota", "Hunt quota used", "This tenant has used its hunts for this hour.")
        if body.hunt_id is not None:
            saved = (
                await conn.execute(text("SELECT query FROM hunts WHERE id = :i"), {"i": body.hunt_id})
            ).scalar_one_or_none()
            if saved is None:
                raise not_found("Hunt")
            query = EventQuery.model_validate(saved)
        elif body.query is not None:
            query = body.query
        else:  # unreachable: checked above
            raise ProblemError(422, "hunt.query_required", "Query required", "Give either hunt_id or query.")
        try:
            since, until = query.window()
        except ValueError as exc:
            raise ProblemError(422, "search.bad_window", "Invalid time window", str(exc)) from exc
        pinned = query.model_copy(update={"since": since, "until": until}).model_dump(mode="json", exclude_none=True)
        hunt_run_id = (
            await conn.execute(
                text(
                    "INSERT INTO hunt_runs (tenant_id, hunt_id, query, requested_by) VALUES (app_tenant(), :h, "
                    "CAST(:q AS jsonb), :u) RETURNING id"
                ),
                {"h": body.hunt_id, "q": json.dumps(pinned), "u": p.user_id},
            )
        ).scalar_one()
        await record(
            conn,
            p,
            "hunt.run",
            target_type="hunt_run",
            target_id=hunt_run_id,
            details={"hunt": str(body.hunt_id or "")},
        )
    tenant = p.tenant_id
    if tenant is None:  # tenant_tx above already required one
        raise ProblemError(409, "tenant.none_selected", "No tenant selected", "Select a tenant first.")
    task = asyncio.create_task(_execute(services, tenant, p.user_id, hunt_run_id, p))
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)
    return await get_run(hunt_run_id, services, p)


@router.get("/hunt/queries", response_model=list[HuntRunOut], **requires("hunt:run"))
async def list_runs(
    services: Svc, p: P, hunt_id: UUID | None = None, limit: Annotated[int, Query(ge=1, le=100)] = 25
) -> list[HuntRunOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(
            text(
                f"SELECT {_RUN_COLS} FROM hunt_runs r LEFT JOIN hunts h ON h.id = r.hunt_id "  # nosec B608
                "WHERE (CAST(:h AS uuid) IS NULL OR r.hunt_id = :h) ORDER BY r.created_at DESC LIMIT :l"
            ),
            {"h": hunt_id, "l": limit},
        )
        return [HuntRunOut(**r._mapping) for r in rows]


@router.get("/hunt/queries/{hunt_run_id}", response_model=HuntRunOut, **requires("hunt:run"))
async def get_run(hunt_run_id: UUID, services: Svc, p: P) -> HuntRunOut:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text(f"SELECT {_RUN_COLS} FROM hunt_runs r LEFT JOIN hunts h ON h.id = r.hunt_id WHERE r.id = :i"),  # nosec B608
                {"i": hunt_run_id},
            )
        ).one_or_none()
    if row is None:
        raise not_found("Hunt run")
    return HuntRunOut(**row._mapping)


@router.get("/hunt/queries/{hunt_run_id}/results", response_model=HuntResultsOut, **requires("hunt:run"))
async def get_results(hunt_run_id: UUID, services: Svc, p: P) -> HuntResultsOut:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text(
                    f"SELECT {_RUN_COLS}, r.results FROM hunt_runs r LEFT JOIN hunts h ON h.id = r.hunt_id "
                    f""  # nosec B608
                    "WHERE r.id = :i"
                ),
                {"i": hunt_run_id},
            )
        ).one_or_none()
    if row is None:
        raise not_found("Hunt run")
    data = dict(row._mapping)
    stored = data.pop("results") or {}
    return HuntResultsOut(**data, results=stored.get("items", []), facets=stored.get("facets", {}))


@router.post("/hunt/queries/{hunt_run_id}/attach", status_code=status.HTTP_204_NO_CONTENT, **requires("hunt:run"))
async def attach(hunt_run_id: UUID, body: AttachIn, services: Svc, p: P) -> Response:
    """Adds the run's summary to an incident timeline (results to case)."""
    if not p.has("incident:comment"):
        raise ProblemError(403, "authz.forbidden", "Forbidden", "Attaching results needs incident:comment.")
    async with tenant_tx(services, p) as conn:
        run = (
            await conn.execute(
                text(
                    "SELECT r.status, r.hit_count, r.query, h.name FROM hunt_runs r LEFT JOIN hunts h ON h.id = "
                    "r.hunt_id "
                    "WHERE r.id = :i"
                ),
                {"i": hunt_run_id},
            )
        ).one_or_none()
        if run is None:
            raise not_found("Hunt run")
        if run.status != "succeeded":
            raise ProblemError(409, "hunt.not_finished", "Not finished", "Only finished hunt runs can be attached.")
        if not (await conn.execute(text("SELECT 1 FROM incidents WHERE id = :i"), {"i": body.incident_id})).first():
            raise not_found("Incident")
        label = run.name or "Ad-hoc hunt"
        words = run.query.get("text") or "(no text)"
        summary = f"Hunt results attached: {label}, {run.hit_count} event(s) for query {words!r}."
        if body.note:
            summary += f" Note: {body.note}"
        await incident_store.timeline(
            conn,
            body.incident_id,
            "comment",
            {"text": summary, "hunt_run_id": str(hunt_run_id)},
            actor_type="user",
            actor_id=p.user_id,
        )
        await record(
            conn,
            p,
            "hunt.attach",
            target_type="incident",
            target_id=body.incident_id,
            details={"hunt_run": str(hunt_run_id), "hits": run.hit_count},
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
