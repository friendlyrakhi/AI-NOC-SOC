"""Business services, topology, maintenance windows, suppression rules and global search
(docs/05 §2.4, §2.5, §2.10).

Services and their links normally come from the CMDB (ServiceNow sandbox). Maintenance windows
and suppression rules stop alerts from opening incidents; suppressed alerts stay visible with
the reason, and nothing is deleted.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import text

from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.core.tenancy.common import record, tenant_tx
from app.errors import not_found
from app.services import Services, get_services

router = APIRouter(tags=["topology and operations"])
Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]

OPEN_ALERT = "a.status NOT IN ('resolved', 'closed', 'suppressed')"
OPEN_INCIDENT = "i.status NOT IN ('resolved', 'closed')"


# ============================================================ services
class ServiceOut(BaseModel):
    id: UUID
    name: str
    tier: int
    owner_team: str | None
    aliases: list[str]
    members: int
    dependencies: int
    open_alerts: int
    open_incidents: int
    worst_open_severity: str | None
    health: Literal["healthy", "degraded", "down"]
    in_maintenance: bool
    sandbox: bool


class ServiceAssetOut(BaseModel):
    id: UUID
    name: str
    type: str
    role: Literal["member", "dependency"]
    open_alerts: int
    worst_open_severity: str | None


class ServiceDetail(ServiceOut):
    assets: list[ServiceAssetOut]


_SERVICE_SELECT = """
SELECT s.id, s.name, s.tier, s.owner_team, s.aliases, s.sandbox,
  (SELECT count(*) FROM service_assets sa WHERE sa.service_id = s.id AND sa.role = 'member') AS members,
  (SELECT count(*) FROM service_assets sa WHERE sa.service_id = s.id AND sa.role = 'dependency') AS dependencies,
  (SELECT count(*) FROM alerts a WHERE a.status NOT IN ('resolved', 'closed', 'suppressed')
      AND (a.service_id = s.id OR a.asset_id IN
      (SELECT asset_id FROM service_assets WHERE service_id = s.id))) AS open_alerts,
  (SELECT count(*) FROM incidents i WHERE i.status NOT IN ('resolved', 'closed')
      AND s.id = ANY(i.impacted_service_ids)) AS open_incidents,
  (SELECT a.severity FROM alerts a WHERE a.status NOT IN ('resolved', 'closed', 'suppressed')
      AND (a.service_id = s.id OR a.asset_id IN
      (SELECT asset_id FROM service_assets WHERE service_id = s.id)) ORDER BY severity_rank(a.severity) LIMIT 1)
      AS worst_open_severity,
  EXISTS (SELECT 1 FROM maintenance_windows m WHERE m.cancelled_at IS NULL AND m.starts_at <= now()
          AND m.ends_at > now() AND s.id = ANY(m.service_ids)) AS in_maintenance
FROM services s
"""


def _health(worst: str | None) -> Literal["healthy", "degraded", "down"]:
    """Derived from open alerts only: critical -> down, high/medium -> degraded."""
    if worst == "critical":
        return "down"
    if worst in ("high", "medium"):
        return "degraded"
    return "healthy"


@router.get("/services", response_model=list[ServiceOut], **requires("service:read"))
async def list_services(services: Svc, p: P) -> list[ServiceOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(text(f"{_SERVICE_SELECT} ORDER BY s.tier, s.name"))  # nosec B608
        return [ServiceOut(**r._mapping, health=_health(r.worst_open_severity)) for r in rows]


@router.get("/services/{service_id}", response_model=ServiceDetail, **requires("service:read"))
async def get_service(service_id: UUID, services: Svc, p: P) -> ServiceDetail:
    async with tenant_tx(services, p) as conn:
        row = (await conn.execute(text(f"{_SERVICE_SELECT} WHERE s.id = :id"), {"id": service_id})).one_or_none()  # nosec B608
        if row is None:
            raise not_found("Service")
        assets = await conn.execute(
            text(
                f"SELECT x.id, x.name, x.type, sa.role, "
                f"(SELECT count(*) FROM alerts a WHERE a.asset_id = x.id AND {OPEN_ALERT}) AS open_alerts, "
                f"(SELECT a.severity FROM alerts a WHERE a.asset_id = x.id AND {OPEN_ALERT} "
                "ORDER BY severity_rank(a.severity) LIMIT 1) AS worst_open_severity "
                "FROM service_assets sa JOIN assets x ON x.id = sa.asset_id WHERE sa.service_id = :id "
                "ORDER BY sa.role DESC, x.name"  # nosec B608
            ),
            {"id": service_id},
        )
        return ServiceDetail(
            **row._mapping,
            health=_health(row.worst_open_severity),
            assets=[ServiceAssetOut(**a._mapping) for a in assets],
        )


class AssetDetail(BaseModel):
    id: UUID
    type: str
    name: str
    environment: str
    criticality: int
    identifiers: list[dict[str, str]]
    sources: list[str]
    services: list[dict[str, Any]]
    open_alerts: int
    open_vulns: int
    sandbox: bool
    first_seen: datetime
    last_seen: datetime


@router.get("/assets/{asset_id}", response_model=AssetDetail, **requires("asset:read"))
async def get_asset(asset_id: UUID, services: Svc, p: P) -> AssetDetail:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT x.id, x.type, x.name, x.environment, x.criticality, x.sources, x.sandbox, x.first_seen, "
                    "x.last_seen, "
                    "coalesce((SELECT json_agg(json_build_object('kind', i.kind, 'value', i.value) ORDER BY i.kind) "
                    "          FROM asset_identifiers i WHERE i.asset_id = x.id), '[]') AS identifiers, "
                    "coalesce((SELECT json_agg(json_build_object('id', s.id, 'name', s.name, 'tier', s.tier, "
                    "          'role', sa.role) ORDER BY s.tier) FROM service_assets sa "
                    "          JOIN services s ON s.id = sa.service_id WHERE sa.asset_id = x.id), '[]') AS services, "
                    f"(SELECT count(*) FROM alerts a WHERE a.asset_id = x.id AND {OPEN_ALERT}) AS open_alerts, "
                    "(SELECT count(*) FROM vuln_findings v WHERE v.asset_id = x.id AND v.status = 'open') AS "
                    "open_vulns "
                    "FROM assets x WHERE x.id = :id"  # nosec B608
                ),
                {"id": asset_id},
            )
        ).one_or_none()
    if row is None:
        raise not_found("Asset")
    return AssetDetail(**row._mapping)


# ============================================================ maintenance windows
class MaintenanceOut(BaseModel):
    id: UUID
    title: str
    asset_ids: list[UUID]
    service_ids: list[UUID]
    starts_at: datetime
    ends_at: datetime
    reason: str
    state: Literal["scheduled", "active", "ended", "cancelled"]
    created_at: datetime


class MaintenanceCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    asset_ids: list[UUID] = Field(default_factory=list, max_length=200)
    service_ids: list[UUID] = Field(default_factory=list, max_length=50)
    starts_at: datetime
    ends_at: datetime
    reason: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def _check(self) -> MaintenanceCreate:
        if not (self.asset_ids or self.service_ids):
            raise ValueError("choose at least one asset or service")
        if self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be after starts_at")
        if self.ends_at - self.starts_at > timedelta(days=7):
            raise ValueError("a window may last at most 7 days")
        return self


def _mw_state(r: Any, now: datetime) -> str:
    if r.cancelled_at:
        return "cancelled"
    if r.ends_at <= now:
        return "ended"
    return "active" if r.starts_at <= now else "scheduled"


@router.get("/maintenance-windows", response_model=list[MaintenanceOut], **requires("maintenance:read"))
async def list_maintenance(services: Svc, p: P, include_past: bool = False) -> list[MaintenanceOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(
            text(
                "SELECT * FROM maintenance_windows WHERE :all OR (cancelled_at IS NULL AND ends_at > now()) "
                "ORDER BY starts_at DESC LIMIT 200"
            ),
            {"all": include_past},
        )
        now = datetime.now(UTC)
        return [MaintenanceOut(**{**r._mapping, "state": _mw_state(r, now)}) for r in rows]


@router.post(
    "/maintenance-windows",
    response_model=MaintenanceOut,
    status_code=status.HTTP_201_CREATED,
    **requires("maintenance:manage"),
)
async def create_maintenance(body: MaintenanceCreate, services: Svc, p: P) -> MaintenanceOut:
    async with tenant_tx(services, p) as conn:
        if body.asset_ids:
            n = (
                await conn.execute(text("SELECT count(*) FROM assets WHERE id = ANY(:i)"), {"i": body.asset_ids})
            ).scalar_one()
            if n != len(set(body.asset_ids)):
                raise not_found("Asset")
        if body.service_ids:
            n = (
                await conn.execute(text("SELECT count(*) FROM services WHERE id = ANY(:i)"), {"i": body.service_ids})
            ).scalar_one()
            if n != len(set(body.service_ids)):
                raise not_found("Service")
        row = (
            await conn.execute(
                text(
                    "INSERT INTO maintenance_windows (tenant_id, title, asset_ids, service_ids, starts_at, ends_at, "
                    "reason, "
                    "created_by) VALUES (app_tenant(), :t, CAST(:a AS uuid[]), CAST(:s AS uuid[]), :st, :en, :r, :u) "
                    "RETURNING *"
                ),
                {
                    "t": body.title,
                    "a": [str(x) for x in body.asset_ids],
                    "s": [str(x) for x in body.service_ids],
                    "st": body.starts_at,
                    "en": body.ends_at,
                    "r": body.reason,
                    "u": p.user_id,
                },
            )
        ).one()
        await record(
            conn,
            p,
            "maintenance.create",
            target_type="maintenance_window",
            target_id=row.id,
            details={"title": body.title, "starts_at": body.starts_at, "ends_at": body.ends_at},
        )
    return MaintenanceOut(**{**row._mapping, "state": _mw_state(row, datetime.now(UTC))})


@router.delete(
    "/maintenance-windows/{window_id}", status_code=status.HTTP_204_NO_CONTENT, **requires("maintenance:manage")
)
async def cancel_maintenance(window_id: UUID, services: Svc, p: P) -> Response:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text(
                    "UPDATE maintenance_windows SET cancelled_at = now() WHERE id = :i AND cancelled_at IS NULL "
                    "RETURNING id"
                ),
                {"i": window_id},
            )
        ).one_or_none()
        if row is None:
            raise not_found("Maintenance window")
        await record(conn, p, "maintenance.cancel", target_type="maintenance_window", target_id=window_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ============================================================ suppression rules
class SuppressionMatch(BaseModel):
    """All given conditions must match (at least one is required)."""

    connector: str | None = Field(default=None, max_length=64)
    domain: Literal["noc", "soc"] | None = None
    severity: list[Literal["critical", "high", "medium", "low", "info"]] | None = None
    asset_id: UUID | None = None
    title_contains: str | None = Field(default=None, min_length=3, max_length=200)

    @model_validator(mode="after")
    def _non_empty(self) -> SuppressionMatch:
        if not self.model_dump(exclude_none=True):
            raise ValueError("a suppression rule needs at least one condition")
        return self


class SuppressionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    match: SuppressionMatch
    reason: str = Field(min_length=1, max_length=1000)
    # Suppression always expires; permanent noise should be fixed at the source.
    expires_in_hours: int = Field(default=24, ge=1, le=24 * 30)


class SuppressionOut(BaseModel):
    id: UUID
    name: str
    match: dict[str, Any]
    reason: str
    expires_at: datetime
    enabled: bool
    hits: int
    created_at: datetime


@router.get("/suppression-rules", response_model=list[SuppressionOut], **requires("alert:read"))
async def list_suppression(services: Svc, p: P) -> list[SuppressionOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(
            text(
                "SELECT id, name, match, reason, expires_at, enabled, hits, created_at FROM suppression_rules "
                "WHERE enabled AND expires_at > now() ORDER BY created_at DESC"
            )
        )
        return [SuppressionOut(**r._mapping) for r in rows]


@router.post(
    "/suppression-rules",
    response_model=SuppressionOut,
    status_code=status.HTTP_201_CREATED,
    **requires("alert:suppress"),
)
async def create_suppression(body: SuppressionCreate, services: Svc, p: P) -> SuppressionOut:
    match = body.match.model_dump(mode="json", exclude_none=True)
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text(
                    "INSERT INTO suppression_rules (tenant_id, name, match, reason, expires_at, created_by) "
                    "VALUES (app_tenant(), :n, CAST(:m AS jsonb), :r, now() + make_interval(hours => :h), :u) "
                    "RETURNING id, name, match, reason, expires_at, enabled, hits, created_at"
                ),
                {"n": body.name, "m": json.dumps(match), "r": body.reason, "h": body.expires_in_hours, "u": p.user_id},
            )
        ).one()
        await record(
            conn,
            p,
            "suppression.create",
            target_type="suppression_rule",
            target_id=row.id,
            details={"name": body.name, "match": match, "hours": body.expires_in_hours},
        )
    return SuppressionOut(**row._mapping)


@router.delete("/suppression-rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, **requires("alert:suppress"))
async def delete_suppression(rule_id: UUID, services: Svc, p: P) -> Response:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text("UPDATE suppression_rules SET enabled = false WHERE id = :i AND enabled RETURNING id"),
                {"i": rule_id},
            )
        ).one_or_none()
        if row is None:
            raise not_found("Suppression rule")
        await record(conn, p, "suppression.disable", target_type="suppression_rule", target_id=rule_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ============================================================ search
class SearchHit(BaseModel):
    kind: Literal["alert", "incident", "asset", "service"]
    id: UUID
    title: str
    subtitle: str
    severity: str | None
    at: datetime | None


class SearchOut(BaseModel):
    query: str
    hits: list[SearchHit]
    engine: Literal["opensearch", "postgres"] = "postgres"


@router.get("/search", response_model=SearchOut, **requires("search:read"))
async def search(
    services: Svc,
    p: P,
    q: Annotated[str, Query(min_length=2, max_length=200)],
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> SearchOut:
    """Global search over alerts, incidents, assets and services. Results respect the caller's
    permissions per kind. Uses the tenant's OpenSearch entity index when the ``search`` profile
    runs (P6), otherwise Postgres full-text search (prefix match on the last word). Services
    always come from Postgres (few, and not indexed)."""
    from app.search_api import entity_search

    os_hits = await entity_search(services, p, q, limit)
    if os_hits is not None:
        if p.has("service:read"):
            async with tenant_tx(services, p) as conn:
                rows = await conn.execute(
                    text(
                        "SELECT 'service' AS kind, id, name AS title, 'tier ' || tier AS subtitle, "
                        "NULL AS severity, updated_at AS at FROM services WHERE name ILIKE :like "
                        "OR EXISTS (SELECT 1 FROM unnest(aliases) a WHERE a ILIKE :like) ORDER BY name LIMIT 5"
                    ),
                    {"like": f"%{q.replace('%', '').replace('_', '')}%"},
                )
                os_hits += [SearchHit(**r._mapping) for r in rows]
        return SearchOut(query=q, hits=os_hits[:limit], engine="opensearch")
    words = [w for w in "".join(c if c.isalnum() or c in "-_." else " " for c in q).split() if w][:8]
    if not words:
        return SearchOut(query=q, hits=[])
    tsq = (
        " & ".join(w.replace("'", "") for w in words[:-1])
        + (" & " if len(words) > 1 else "")
        + words[-1].replace("'", "")
        + ":*"
    )
    like = f"%{q.replace('%', '').replace('_', '')}%"
    parts: list[str] = []
    if p.has("incident:read"):
        parts.append(
            "SELECT 'incident' AS kind, id, number || ' ' || title AS title, domain || ' · ' || status AS subtitle, "
            "severity, detected_at AS at FROM incidents WHERE search @@ to_tsquery('simple', :tsq) OR number ILIKE "
            ":like"
        )
    if p.has("alert:read"):
        parts.append(
            "SELECT 'alert', id, title, connector_id || ' · ' || status, severity, last_seen FROM alerts "
            "WHERE search @@ to_tsquery('simple', :tsq)"
        )
    if p.has("asset:read"):
        parts.append(
            "SELECT 'asset', id, name, type || ' · ' || environment, NULL, last_seen FROM assets "
            "WHERE search @@ to_tsquery('simple', :tsq) OR name ILIKE :like"
        )
    if p.has("service:read"):
        parts.append(
            "SELECT 'service', id, name, 'tier ' || tier, NULL, updated_at FROM services WHERE name ILIKE :like "
            "OR EXISTS (SELECT 1 FROM unnest(aliases) a WHERE a ILIKE :like)"
        )
    if not parts:
        return SearchOut(query=q, hits=[])
    sql = " UNION ALL ".join(f"({x} LIMIT :l)" for x in parts) + " ORDER BY at DESC NULLS LAST LIMIT :l"
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(text(sql), {"tsq": tsq, "like": like, "l": limit})  # nosec B608 - fixed fragments
        return SearchOut(query=q, hits=[SearchHit(**r._mapping) for r in rows])
