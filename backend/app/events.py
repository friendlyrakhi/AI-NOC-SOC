"""Canonical NOC/SOC event model (EventV1) and the event search API.

Every connector record that describes something that *happened* maps to one EventV1, whatever
its source or domain:

| class           | from                      | domain     |
|-----------------|---------------------------|------------|
| ``alert``       | AlertV1                   | noc or soc |
| ``detection``   | SecurityEventV1 (2004)    | soc        |
| ``authentication`` | SecurityEventV1 (3002) | soc        |
| ``process``     | SecurityEventV1 (1007)    | soc        |
| ``network``     | SecurityEventV1 (4001)    | soc        |
| ``api_activity``| SecurityEventV1 (6003)    | soc        |
| ``ticket``      | TicketV1                  | noc        |

Metrics are not events (they live in ``metrics``); assets and findings are state, not events.
Events are stored in ClickHouse (30-day TTL) behind the tenant row policy; reads always carry
the caller's tenant (threat model T8).
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.analytics import reader_query
from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.core.cache import tenant_budget
from app.core.types import IsoDatetime
from app.errors import ProblemError
from app.services import Services, get_services
from nocsoc_connector_sdk import AlertV1, SecurityEventV1, TicketV1

EventClass = Literal["alert", "detection", "authentication", "process", "network", "api_activity", "ticket"]
Severity = Literal["critical", "high", "medium", "low", "info"]

OCSF_CLASS: dict[int, EventClass] = {
    2004: "detection",
    3002: "authentication",
    1007: "process",
    4001: "network",
    6003: "api_activity",
}

EVENTS_TABLE = """CREATE TABLE IF NOT EXISTS {db}.events (
    tenant_id UUID, event_id String, schema_version LowCardinality(String) DEFAULT 'event@1',
    domain LowCardinality(String), class LowCardinality(String), severity LowCardinality(String),
    observed_at DateTime64(3, 'UTC'), ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
    connector LowCardinality(String), instance_id UUID, source_id String,
    title String, asset String, actor_user String, src_ip String, dst_ip String,
    outcome LowCardinality(String), mitre Array(String), attributes String CODEC(ZSTD(3))
) ENGINE = MergeTree ORDER BY (tenant_id, domain, observed_at, event_id)
  TTL toDateTime(observed_at) + INTERVAL 30 DAY"""

EVENT_COLUMNS = [
    "tenant_id",
    "event_id",
    "domain",
    "class",
    "severity",
    "observed_at",
    "connector",
    "instance_id",
    "source_id",
    "title",
    "asset",
    "actor_user",
    "src_ip",
    "dst_ip",
    "outcome",
    "mitre",
    "attributes",
]


class EventV1(BaseModel):
    """The canonical event. ``sandbox`` is always true in this build."""

    event_id: str
    domain: Literal["noc", "soc"]
    event_class: EventClass = Field(alias="class")
    severity: Severity
    observed_at: datetime
    connector: str
    instance_id: UUID
    source_id: str
    title: str
    asset: str
    actor_user: str
    src_ip: str
    dst_ip: str
    outcome: str
    mitre: list[str]
    attributes: dict[str, Any]
    sandbox: bool = True

    model_config = {"populate_by_name": True}


def to_event_row(
    rec: Any, *, tenant: UUID, instance: UUID, connector: str, event_id: str, source_id: str, index: int
) -> list[Any] | None:
    """One ClickHouse ``events`` row for a normalized record, or None if it is not an event."""
    eid = f"{event_id}:{index}"
    if isinstance(rec, AlertV1):
        asset = rec.asset_refs[0].value if rec.asset_refs else ""
        attrs = {
            "category": rec.category,
            "status": rec.status,
            "service": rec.service_hint,
            "dedup_key": rec.dedup_key,
        }
        return [
            tenant,
            eid,
            rec.domain,
            "alert",
            rec.severity,
            rec.observed_at,
            connector,
            instance,
            source_id,
            rec.title,
            asset,
            "",
            "",
            "",
            "unknown",
            list(rec.mitre_techniques),
            json.dumps(attrs),
        ]
    if isinstance(rec, SecurityEventV1):
        return [
            tenant,
            eid,
            "soc",
            OCSF_CLASS[rec.class_uid],
            rec.severity,
            rec.observed_at,
            connector,
            instance,
            source_id,
            rec.message[:500],
            rec.device_hostname or "",
            rec.actor_user or "",
            rec.src_ip or "",
            rec.dst_ip or "",
            rec.outcome,
            list(rec.mitre_techniques),
            json.dumps({"activity": rec.activity, "ocsf_class_uid": rec.class_uid}),
        ]
    if isinstance(rec, TicketV1):
        return [
            tenant,
            eid,
            "noc",
            "ticket",
            "info",
            rec.observed_at,
            connector,
            instance,
            source_id,
            f"{rec.number}: {rec.short_description}"[:500],
            "",
            "",
            "",
            "",
            "unknown",
            [],
            json.dumps({"state": rec.state, "external_id": rec.external_id}),
        ]
    return None


# ============================================================ API
router = APIRouter(tags=["events"])
Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]

MAX_WINDOW = timedelta(days=30)


class EventPage(BaseModel):
    items: list[EventV1]
    next_cursor: str | None = Field(description="Opaque; pass back as ``cursor`` for the next (older) page.")


class HistogramBucket(BaseModel):
    start: datetime
    severity: Severity
    count: int


def _cursor_encode(observed_at: datetime, event_id: str) -> str:
    return base64.urlsafe_b64encode(json.dumps([observed_at.isoformat(), event_id]).encode()).decode()


def _cursor_decode(cursor: str) -> tuple[datetime, str]:
    try:
        ts, eid = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        return datetime.fromisoformat(ts), str(eid)
    except Exception as exc:
        raise ProblemError(422, "events.bad_cursor", "Invalid cursor", "Start again without a cursor.") from exc


async def _reader(services: Services) -> Any:
    try:
        client = await services.analytics_reader()
    except Exception as exc:  # configured but not running (e.g. only the core profile is up)
        raise ProblemError(
            503, "analytics.unavailable", "Analytics unavailable", "The telemetry store is not reachable."
        ) from exc
    if client is None:
        raise ProblemError(503, "analytics.disabled", "Analytics not configured", "Start the 'analytics' profile.")
    return client


def _window(since: datetime | None, until: datetime | None) -> tuple[datetime, datetime]:
    until = until or datetime.now(UTC)
    since = since or until - timedelta(hours=24)
    if since >= until or until - since > MAX_WINDOW:
        raise ProblemError(422, "events.bad_window", "Invalid time window", "Use a window of up to 30 days.")
    return since, until


@router.get("/events", response_model=EventPage, **requires("search:read"))
async def search_events(
    services: Svc,
    p: P,
    domain: Literal["noc", "soc"] | None = None,
    event_class: Annotated[list[EventClass] | None, Query(alias="class")] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    connector: str | None = Query(default=None, max_length=64),
    q: str | None = Query(
        default=None, max_length=200, description="Case-insensitive substring of title, asset or user."
    ),
    since: IsoDatetime | None = None,
    until: IsoDatetime | None = None,
    cursor: str | None = Query(default=None, max_length=500),
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> EventPage:
    since, until = _window(since, until)
    await tenant_budget(services, p, "event-search")
    where = ["observed_at >= {since:DateTime64(3)}", "observed_at < {until:DateTime64(3)}"]
    params: dict[str, Any] = {"since": since, "until": until, "lim": limit + 1}
    if domain:
        where.append("domain = {domain:String}")
        params["domain"] = domain
    if event_class:
        where.append("class IN {classes:Array(String)}")
        params["classes"] = list(event_class)
    if severity:
        where.append("severity IN {sev:Array(String)}")
        params["sev"] = list(severity)
    if connector:
        where.append("connector = {conn:String}")
        params["conn"] = connector
    if q:
        where.append(
            "(positionCaseInsensitive(title, {q:String}) > 0 OR positionCaseInsensitive(asset, {q:String}) > 0 "
            "OR positionCaseInsensitive(actor_user, {q:String}) > 0)"
        )
        params["q"] = q
    if cursor:
        c_ts, c_id = _cursor_decode(cursor)
        where.append("(observed_at, event_id) < ({cts:DateTime64(3)}, {cid:String})")
        params["cts"], params["cid"] = c_ts, c_id
    sql = (
        "SELECT event_id, domain, class, severity, observed_at, connector, instance_id, source_id, title, asset, "
        "actor_user, src_ip, dst_ip, outcome, mitre, attributes FROM events WHERE "  # nosec B608 - fixed fragments, bound values
        + " AND ".join(where)
        + " ORDER BY observed_at DESC, event_id DESC LIMIT {lim:UInt32}"
    )
    rows = await reader_query(await _reader(services), p.tenant_id, sql, params)
    items = []
    for r in rows[:limit]:
        r["attributes"] = json.loads(r["attributes"] or "{}")
        if r["observed_at"].tzinfo is None:
            r["observed_at"] = r["observed_at"].replace(tzinfo=UTC)
        items.append(EventV1.model_validate(r))
    next_cursor = _cursor_encode(items[-1].observed_at, items[-1].event_id) if len(rows) > limit else None
    return EventPage(items=items, next_cursor=next_cursor)


@router.get("/events/histogram", response_model=list[HistogramBucket], **requires("search:read"))
async def events_histogram(
    services: Svc,
    p: P,
    domain: Literal["noc", "soc"] | None = None,
    since: IsoDatetime | None = None,
    until: IsoDatetime | None = None,
    bucket_minutes: Annotated[int, Query(ge=1, le=1440)] = 60,
) -> list[HistogramBucket]:
    since, until = _window(since, until)
    if (until - since) / timedelta(minutes=bucket_minutes) > 2000:
        raise ProblemError(
            422, "events.too_many_buckets", "Too many buckets", "Use a larger bucket or a shorter window."
        )
    sql = (
        "SELECT toStartOfInterval(observed_at, toIntervalMinute({b:UInt32})) AS start, severity, count() AS count "
        "FROM events WHERE observed_at >= {since:DateTime64(3)} AND observed_at < {until:DateTime64(3)} "
        "AND ({domain:String} = '' OR domain = {domain:String}) GROUP BY start, severity ORDER BY start, severity"
    )
    rows = await reader_query(
        await _reader(services),
        p.tenant_id,
        sql,
        {"b": bucket_minutes, "since": since, "until": until, "domain": domain or ""},
    )
    return [
        HistogramBucket(
            start=r["start"].replace(tzinfo=UTC) if r["start"].tzinfo is None else r["start"],
            severity=r["severity"],
            count=r["count"],
        )
        for r in rows
    ]
