"""Alert queues, assets and vulnerability findings (docs/05 §2.5-2.7).

Rows here come only from the ingestion pipeline (sandbox connectors in this build); every
row carries ``sandbox = true`` so the UI can label provenance. Alert text is attacker-
controllable data and is returned as plain strings for the UI to render as text.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.analytics import reader_query
from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.core.cache import cached_json, invalidate, tenant_key
from app.core.tenancy.common import record, tenant_tx
from app.errors import ProblemError, not_found
from app.services import Services, get_services

router = APIRouter(tags=["alerts"])
Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]

Severity = Literal["critical", "high", "medium", "low", "info"]
AlertStatus = Literal["new", "acknowledged", "in_progress", "resolved", "closed", "suppressed"]

# Allowed triage transitions. Re-opening a resolved alert is allowed unless a newer open
# alert with the same fingerprint exists (unique index -> 409).
TRANSITIONS: dict[str, set[str]] = {
    "new": {"acknowledged", "in_progress", "resolved", "suppressed"},
    "acknowledged": {"in_progress", "resolved", "suppressed"},
    "in_progress": {"resolved", "acknowledged"},
    "resolved": {"closed", "new"},
    "suppressed": {"new"},
    "closed": set(),
}


class AssetBrief(BaseModel):
    id: UUID
    name: str
    type: str


class AlertOut(BaseModel):
    id: UUID
    domain: Literal["noc", "soc"]
    connector_id: str
    source_instance_id: UUID | None
    source_alert_id: str
    title: str
    description: str
    severity: Severity
    status: AlertStatus
    category: str
    asset: AssetBrief | None
    service_hint: str | None
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    mitre_techniques: list[str]
    observables: list[dict[str, Any]]
    labels: dict[str, Any]
    sandbox: bool
    version: int


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    limit: int
    offset: int


class AlertTransition(BaseModel):
    status: AlertStatus
    version: int = Field(ge=1)
    note: str | None = Field(default=None, max_length=1000)


class SummaryOut(BaseModel):
    domain: Literal["noc", "soc"] | None
    total_open: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_connector: dict[str, int]
    last_ingested_at: datetime | None


_ALERT_SELECT = """
SELECT a.id, a.domain, a.connector_id, a.source_instance_id, a.source_alert_id, a.title, a.description,
       a.severity, a.status, a.category, a.service_hint, a.first_seen, a.last_seen, a.occurrence_count,
       a.mitre_techniques, a.observables, a.labels, a.sandbox, a.version,
       CASE WHEN s.id IS NULL THEN NULL ELSE json_build_object('id', s.id, 'name', s.name, 'type', s.type) END AS asset
  FROM alerts a LEFT JOIN assets s ON s.id = a.asset_id
"""

SORTS = {
    "last_seen": "a.last_seen DESC, a.id",
    "severity": "severity_rank(a.severity), a.last_seen DESC, a.id",
    "occurrences": "a.occurrence_count DESC, a.last_seen DESC, a.id",
}


@router.get("/alerts", response_model=AlertPage, **requires("alert:read"))
async def list_alerts(
    services: Svc,
    p: P,
    domain: Literal["noc", "soc"] | None = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    status: Annotated[list[AlertStatus] | None, Query()] = None,
    connector: str | None = Query(default=None, max_length=64),
    q: str | None = Query(default=None, max_length=200),
    sort: Literal["last_seen", "severity", "occurrences"] = "severity",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> AlertPage:
    where = ["TRUE"]
    params: dict[str, Any] = {"l": limit, "o": offset}
    if domain:
        where.append("a.domain = :d")
        params["d"] = domain
    if severity:
        where.append("a.severity = ANY(:sev)")
        params["sev"] = severity
    if status:
        where.append("a.status = ANY(:st)")
        params["st"] = status
    if connector:
        where.append("a.connector_id = :c")
        params["c"] = connector
    if q:
        where.append("(a.title ILIKE :q OR a.source_alert_id ILIKE :q OR s.name ILIKE :q)")
        params["q"] = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    clause = " AND ".join(where)  # fixed fragments only; values are bound parameters
    async with tenant_tx(services, p) as conn:
        total = (
            await conn.execute(
                text(f"SELECT count(*) FROM alerts a LEFT JOIN assets s ON s.id = a.asset_id WHERE {clause}"),  # nosec B608
                params,
            )
        ).scalar_one()
        rows = await conn.execute(
            text(f"{_ALERT_SELECT} WHERE {clause} ORDER BY {SORTS[sort]} LIMIT :l OFFSET :o"),  # nosec B608
            params,
        )
        items = [AlertOut(**r._mapping) for r in rows]
    return AlertPage(items=items, total=total, limit=limit, offset=offset)


SUMMARY_TTL_SECONDS = 10


def _summary_key(p: Principal, domain: str | None) -> str:
    return tenant_key(p.tenant_id, "cache", "alerts-summary", domain or "all")


@router.get("/alerts/summary", response_model=SummaryOut, **requires("alert:read"))
async def alerts_summary(services: Svc, p: P, domain: Literal["noc", "soc"] | None = None) -> SummaryOut:
    """Cached per tenant for 10 s (dashboards poll this); triage invalidates it immediately."""

    async def compute() -> dict[str, Any]:
        return (await _compute_summary(services, p, domain)).model_dump(mode="json")

    return SummaryOut.model_validate(await cached_json(services, _summary_key(p, domain), SUMMARY_TTL_SECONDS, compute))


async def _compute_summary(services: Services, p: Principal, domain: str | None) -> SummaryOut:
    params = {"d": domain}
    open_filter = "status NOT IN ('resolved', 'closed', 'suppressed') AND (CAST(:d AS text) IS NULL OR domain = :d)"
    async with tenant_tx(services, p) as conn:
        sev = await conn.execute(text(f"SELECT severity, count(*) FROM alerts WHERE {open_filter} GROUP BY 1"), params)  # nosec B608
        by_severity = {r[0]: r[1] for r in sev}
        st = await conn.execute(
            text("SELECT status, count(*) FROM alerts WHERE (CAST(:d AS text) IS NULL OR domain = :d) GROUP BY 1"),
            params,
        )
        by_status = {r[0]: r[1] for r in st}
        by_connector_sql = f"SELECT connector_id, count(*) FROM alerts WHERE {open_filter} GROUP BY 1"  # nosec B608
        cn = await conn.execute(text(by_connector_sql), params)
        by_connector = {r[0]: r[1] for r in cn}
        last = (
            await conn.execute(
                text("SELECT max(updated_at) FROM alerts WHERE (CAST(:d AS text) IS NULL OR domain = :d)"), params
            )
        ).scalar_one()
    return SummaryOut(
        domain=domain,  # type: ignore[arg-type]
        total_open=sum(by_severity.values()),
        by_severity=by_severity,
        by_status=by_status,
        by_connector=by_connector,
        last_ingested_at=last,
    )


@router.get("/alerts/{alert_id}", response_model=AlertOut, **requires("alert:read"))
async def get_alert(alert_id: UUID, services: Svc, p: P) -> AlertOut:
    async with tenant_tx(services, p) as conn:
        row = (await conn.execute(text(f"{_ALERT_SELECT} WHERE a.id = :id"), {"id": alert_id})).one_or_none()  # nosec B608
    if row is None:
        raise not_found("Alert")
    return AlertOut(**row._mapping)


@router.post("/alerts/{alert_id}/transition", response_model=AlertOut, **requires("alert:update"))
async def transition_alert(alert_id: UUID, body: AlertTransition, services: Svc, p: P) -> AlertOut:
    async with tenant_tx(services, p) as conn:
        current = (
            await conn.execute(text("SELECT status, version FROM alerts WHERE id = :id"), {"id": alert_id})
        ).one_or_none()
        if current is None:
            raise not_found("Alert")
        if body.status not in TRANSITIONS[current.status]:
            raise ProblemError(
                409,
                "alert.invalid_transition",
                "Transition not allowed",
                f"An alert in '{current.status}' cannot move to '{body.status}'.",
            )
        try:
            result = await conn.execute(
                text(
                    "UPDATE alerts SET status = :s, updated_at = now(), version = version + 1 "
                    "WHERE id = :id AND version = :v"
                ),
                {"s": body.status, "id": alert_id, "v": body.version},
            )
        except IntegrityError as exc:
            raise ProblemError(
                409, "alert.reopen_conflict", "Already open", "A newer open alert with the same fingerprint exists."
            ) from exc
        if result.rowcount == 0:
            raise ProblemError(409, "conflict.version", "Changed by someone else", "Reload and try again.")
        await record(
            conn,
            p,
            "alert.transition",
            target_type="alert",
            target_id=alert_id,
            details={"from": current.status, "to": body.status, "note": body.note},
        )
        row = (await conn.execute(text(f"{_ALERT_SELECT} WHERE a.id = :id"), {"id": alert_id})).one()  # nosec B608
    await invalidate(services, *(_summary_key(p, d) for d in (None, "noc", "soc")))
    return AlertOut(**row._mapping)


class RawEventOut(BaseModel):
    event_id: str
    connector: str
    stream: str
    trigger: str
    observed_at: datetime
    ingested_at: datetime
    payload: str


@router.get("/alerts/{alert_id}/raw", response_model=list[RawEventOut], **requires("alert:read"))
async def alert_raw(alert_id: UUID, services: Svc, p: P) -> list[RawEventOut]:
    """Source records behind an alert, from the telemetry store (7-day retention)."""
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(text("SELECT source_instance_id, raw_ref FROM alerts WHERE id = :id"), {"id": alert_id})
        ).one_or_none()
    if row is None:
        raise not_found("Alert")
    if row.source_instance_id is None or not row.raw_ref:
        return []
    try:
        client = await services.analytics_reader()
    except Exception as exc:
        raise ProblemError(
            503, "analytics.unavailable", "Analytics unavailable", "The telemetry store is not reachable."
        ) from exc
    if client is None:
        return []
    rows = await reader_query(
        client,
        p.tenant_id,
        "SELECT event_id, connector, stream, trigger, observed_at, ingested_at, payload FROM raw_events "
        "WHERE instance_id = {i:UUID} AND source_id = {s:String} ORDER BY ingested_at DESC LIMIT 10",
        {"i": str(row.source_instance_id), "s": row.raw_ref},
    )
    return [RawEventOut(**r) for r in rows]


# ============================================================ assets
class AssetOut(BaseModel):
    id: UUID
    type: str
    name: str
    environment: str
    criticality: int
    identifiers: list[dict[str, str]]
    sources: list[str]
    open_alerts: int
    open_vulns: int
    sandbox: bool
    first_seen: datetime
    last_seen: datetime


class AssetPage(BaseModel):
    items: list[AssetOut]
    total: int
    limit: int
    offset: int


@router.get("/assets", response_model=AssetPage, **requires("asset:read"))
async def list_assets(
    services: Svc,
    p: P,
    q: str | None = Query(default=None, max_length=200),
    type: str | None = Query(default=None, max_length=40),
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> AssetPage:
    params: dict[str, Any] = {"l": limit, "o": offset, "t": type, "q": None}
    if q:
        params["q"] = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    where = "(CAST(:t AS text) IS NULL OR s.type = :t) AND (CAST(:q AS text) IS NULL OR s.name ILIKE :q)"
    async with tenant_tx(services, p) as conn:
        total = (await conn.execute(text(f"SELECT count(*) FROM assets s WHERE {where}"), params)).scalar_one()  # nosec B608
        rows = await conn.execute(
            text(
                "SELECT s.id, s.type, s.name, s.environment, s.criticality, s.sources, s.sandbox, "
                "s.first_seen, s.last_seen, "
                "coalesce((SELECT json_agg(json_build_object('kind', i.kind, 'value', i.value) "
                "                          ORDER BY i.kind, i.value) "
                "          FROM asset_identifiers i WHERE i.asset_id = s.id), '[]') AS identifiers, "
                "(SELECT count(*) FROM alerts a WHERE a.asset_id = s.id "
                "   AND a.status NOT IN ('resolved','closed','suppressed')) AS open_alerts, "
                "(SELECT count(*) FROM vuln_findings v WHERE v.asset_id = s.id AND v.status = 'open') AS open_vulns "
                f"FROM assets s WHERE {where} ORDER BY s.name LIMIT :l OFFSET :o"  # nosec B608
            ),
            params,
        )
        items = [AssetOut(**r._mapping) for r in rows]
    return AssetPage(items=items, total=total, limit=limit, offset=offset)


# ============================================================ vulnerability findings
class VulnOut(BaseModel):
    id: UUID
    external_id: str
    connector_id: str
    vuln_id: str
    title: str
    severity: Severity
    cvss: float | None
    epss: float | None
    kev: bool
    status: str
    asset: AssetBrief | None
    first_found: datetime
    last_found: datetime
    sandbox: bool


class VulnPage(BaseModel):
    items: list[VulnOut]
    total: int
    limit: int
    offset: int


@router.get("/vulnerabilities", response_model=VulnPage, **requires("vuln:read"))
async def list_vulns(
    services: Svc,
    p: P,
    kev: bool | None = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    status: Literal["open", "fixed", "accepted"] | None = "open",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> VulnPage:
    params: dict[str, Any] = {"l": limit, "o": offset, "k": kev, "sev": severity, "st": status}
    where = (
        "(CAST(:k AS boolean) IS NULL OR v.kev = :k) AND (CAST(:sev AS text[]) IS NULL OR v.severity = ANY(:sev)) "
        "AND (CAST(:st AS text) IS NULL OR v.status = :st)"
    )
    async with tenant_tx(services, p) as conn:
        total = (await conn.execute(text(f"SELECT count(*) FROM vuln_findings v WHERE {where}"), params)).scalar_one()  # nosec B608
        rows = await conn.execute(
            text(
                "SELECT v.id, v.external_id, v.connector_id, v.vuln_id, v.title, v.severity, v.cvss::float AS cvss, "
                "v.epss::float AS epss, v.kev, v.status, v.first_found, v.last_found, v.sandbox, "
                "CASE WHEN s.id IS NULL THEN NULL "
                "     ELSE json_build_object('id', s.id, 'name', s.name, 'type', s.type) END AS asset "
                f"FROM vuln_findings v LEFT JOIN assets s ON s.id = v.asset_id WHERE {where} "  # nosec B608
                "ORDER BY v.kev DESC, severity_rank(v.severity), v.cvss DESC NULLS LAST, v.id LIMIT :l OFFSET :o"
            ),
            params,
        )
        items = [VulnOut(**r._mapping) for r in rows]
    return VulnPage(items=items, total=total, limit=limit, offset=offset)
