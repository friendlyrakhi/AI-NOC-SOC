"""Search API on OpenSearch (P6): global entity search and the event search behind Investigate.

Every call goes through the façade in ``app.searchstore``: index names and the tenant filter
come from the principal; clients send only an ``EventQuery`` or plain text (SEC-ISO-03).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.core.cache import tenant_budget
from app.errors import ProblemError
from app.searchstore import (
    EventQuery,
    SearchStore,
    SearchUnavailableError,
    buckets,
    entities_index,
    entity_query_body,
    event_query_body,
    events_pattern,
    hits,
)
from app.services import Services, get_services

if TYPE_CHECKING:
    from app.topology import SearchHit

logger = logging.getLogger(__name__)
router = APIRouter(tags=["search"])
Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]

KIND_PERMISSION = {"incident": "incident:read", "alert": "alert:read", "asset": "asset:read"}


def store(services: Services) -> SearchStore:
    s = services.search_reader()
    if s is None:
        raise ProblemError(503, "search.disabled", "Search not configured", "Start the 'search' profile.")
    return s  # type: ignore[no-any-return]


async def entity_search(services: Services, p: Principal, q: str, limit: int) -> list[SearchHit] | None:
    """OpenSearch hits for global search, or None to fall back to Postgres (not configured,
    unreachable, or the tenant has nothing indexed yet)."""
    from app.topology import SearchHit

    s = services.search_reader()
    if s is None or p.tenant_id is None:
        return None
    kinds = [k for k, perm in KIND_PERMISSION.items() if p.has(perm)]
    if not kinds:
        return []
    try:
        result = await s.search(entities_index(p.tenant_id), entity_query_body(p.tenant_id, q, kinds, limit))
    except Exception as exc:  # degrade to Postgres, never fail the search box
        logger.warning("entity search fell back to postgres: %s", type(exc).__name__)
        return None
    docs, total = hits(result)
    if total == 0 and not result.get("_shards", {}).get("total"):
        return None  # no entity index yet for this tenant
    out = []
    for d in docs:
        title = f"{d['number']} {d['title']}" if d.get("number") else d.get("title", "")
        out.append(
            SearchHit(
                kind=d["kind"],
                id=d["id"],
                title=title,
                subtitle=d.get("subtitle", ""),
                severity=d.get("severity"),
                at=d.get("at"),
            )
        )
    return out


class EventSearchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: EventQuery = Field(default_factory=EventQuery)
    limit: int = Field(default=100, ge=1, le=500)
    facets: bool = True


class EventHit(BaseModel):
    event_id: str
    domain: str
    event_class: str = Field(alias="class")
    severity: str
    observed_at: datetime
    connector: str
    title: str
    asset: str | None = None
    actor_user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    outcome: str | None = None
    mitre: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    sandbox: bool = True

    model_config = {"populate_by_name": True}


class Facet(BaseModel):
    value: str
    count: int


class EventSearchOut(BaseModel):
    total: int
    since: datetime
    until: datetime
    items: list[EventHit]
    facets: dict[str, list[Facet]]


async def run_event_search(services: Services, p: Principal, body: EventSearchIn) -> EventSearchOut:
    if p.tenant_id is None:
        raise ProblemError(409, "tenant.none_selected", "No tenant selected", "Select a tenant first.")
    try:
        since, until = body.query.window()
    except ValueError as exc:
        raise ProblemError(422, "search.bad_window", "Invalid time window", str(exc)) from exc
    query = body.query.model_copy(update={"since": since, "until": until})
    try:
        result = await store(services).search(
            events_pattern(p.tenant_id),
            event_query_body(p.tenant_id, query, size=body.limit, aggregations=body.facets),
        )
    except SearchUnavailableError as exc:
        raise ProblemError(
            503, "search.unavailable", "Search unavailable", "The search store is not reachable."
        ) from exc
    docs, total = hits(result)
    return EventSearchOut(
        total=total,
        since=since.astimezone(UTC),
        until=until.astimezone(UTC),
        items=[EventHit.model_validate(d) for d in docs],
        facets={k: [Facet(value=str(b["value"]), count=b["count"]) for b in v] for k, v in buckets(result).items()},
    )


@router.post("/search/events", response_model=EventSearchOut, **requires("search:read"))
async def search_events(body: EventSearchIn, services: Svc, p: P) -> EventSearchOut:
    """Full-text and field search over the tenant's canonical events (last 30 days), with facets
    for pivoting (severity, asset, user, connector)."""
    await tenant_budget(services, p, "event-search")
    return await run_event_search(services, p, body)
