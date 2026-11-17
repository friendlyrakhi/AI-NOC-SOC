"""KPIs and the Executive Command Center (P6), computed from ClickHouse facts.

Definitions (period P = detected/first seen within the last 24 h, 7 d, 30 d or 90 d; incidents
merged into another incident are excluded; portal NOC/SOC includes joint incidents):

| KPI | Value | Basis (drill-down records) |
|-----|-------|----------------------------|
| incidents_opened | count | incidents in P |
| open_incidents | count | incidents in P not resolved/closed |
| mtta | mean(acknowledged - detected), seconds | acknowledged incidents in P |
| mttr | mean(resolved - detected), seconds | resolved incidents in P |
| ack_sla | met / due | incidents in P whose ack outcome is known (acknowledged, or deadline passed) |
| resolve_sla | met / due | same for resolution |
| automation_rate | share with >= 1 succeeded action | incidents in P |
| alert_volume | count | alerts first seen in P |
| noise_ratio | share never escalated to an incident | alerts first seen in P |

These match ``app.incidents.sla.compute_metrics`` over the same Postgres rows (tested). Every
KPI has ``/analytics/kpis/{key}/records``: the exact records behind its basis, with the flag that
makes up the numerator, so a value can always be traced to records.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import text

from app.analytics import reader_query
from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.core.tenancy.common import tenant_tx
from app.errors import ProblemError
from app.services import Services, get_services

router = APIRouter(tags=["analytics"])
Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]

Period = Literal["24h", "7d", "30d", "90d"]
Domain = Literal["all", "noc", "soc"]
KpiKey = Literal[
    "incidents_opened",
    "open_incidents",
    "mtta",
    "mttr",
    "ack_sla",
    "resolve_sla",
    "automation_rate",
    "alert_volume",
    "noise_ratio",
]
PERIODS: dict[str, timedelta] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}

META: dict[str, tuple[str, str, str, str]] = {
    # key: (label, unit, record kind, description)
    "incidents_opened": ("Incidents opened", "count", "incident", "Incidents detected in the period."),
    "open_incidents": ("Still open", "count", "incident", "Incidents from the period not yet resolved or closed."),
    "mtta": ("MTTA", "seconds", "incident", "Mean time from detection to acknowledgement."),
    "mttr": ("MTTR", "seconds", "incident", "Mean time from detection to resolution."),
    "ack_sla": ("Acknowledge SLA met", "ratio", "incident", "Share of decided acknowledgement targets that were met."),
    "resolve_sla": ("Resolve SLA met", "ratio", "incident", "Share of decided resolution targets that were met."),
    "automation_rate": (
        "Automation rate",
        "ratio",
        "incident",
        "Share of incidents with at least one successful (simulated) action.",
    ),
    "alert_volume": ("Alerts", "count", "alert", "Alerts first seen in the period."),
    "noise_ratio": ("Noise ratio", "ratio", "alert", "Share of alerts never escalated to an incident."),
}

INCIDENT_DOMAIN = {
    "all": "1 = 1",
    "noc": "domain IN ('noc', 'joint')",
    "soc": "domain IN ('soc', 'joint')",
}
ALERT_DOMAIN = {"all": "1 = 1", "noc": "domain = 'noc'", "soc": "domain = 'soc'"}

_AUTOMATED = (
    "incident_id IN (SELECT assumeNotNull(incident_id) FROM action_facts FINAL "
    "WHERE status = 'succeeded' AND incident_id IS NOT NULL)"
)
_ACK_DUE = "(acknowledged_at IS NOT NULL OR {now:DateTime64(3)} > ack_due_at)"
_ACK_MET = "(ifNull(acknowledged_at, {now:DateTime64(3)}) <= ack_due_at)"
_RES_DUE = "(resolved_at IS NOT NULL OR {now:DateTime64(3)} > resolve_due_at)"
_RES_MET = "(ifNull(resolved_at, {now:DateTime64(3)}) <= resolve_due_at)"

INCIDENT_STATS = (
    "SELECT {group} count() AS total, countIf(status NOT IN ('resolved', 'closed')) AS open, "  # nosec B608 - fixed fragments, bound values
    "countIf(acknowledged_at IS NOT NULL) AS acked, "
    "sumIf(dateDiff('millisecond', detected_at, assumeNotNull(acknowledged_at)), acknowledged_at IS NOT NULL) AS "
    "ack_ms, "
    "countIf(resolved_at IS NOT NULL) AS resolved, "
    "sumIf(dateDiff('millisecond', detected_at, assumeNotNull(resolved_at)), resolved_at IS NOT NULL) AS res_ms, "
    f"countIf({_ACK_DUE}) AS ack_due, countIf({_ACK_DUE} AND {_ACK_MET}) AS ack_met, "
    f"countIf({_RES_DUE}) AS res_due, countIf({_RES_DUE} AND {_RES_MET}) AS res_met, "
    f"countIf({_AUTOMATED}) AS automated "
    "FROM incident_facts FINAL WHERE merged = 0 AND detected_at >= {since:DateTime64(3)} AND {domain} {group_by}"
)
ALERT_STATS = (
    "SELECT {group} count() AS total, countIf(incident_id IS NULL) AS not_escalated "
    "FROM alert_facts FINAL WHERE first_seen >= {since:DateTime64(3)} AND {domain} {group_by}"
)


class Kpi(BaseModel):
    key: KpiKey
    label: str
    unit: Literal["count", "seconds", "ratio"]
    value: float | None
    numerator: int | None
    basis: int
    records: Literal["incident", "alert"]
    description: str


class KpiSet(BaseModel):
    domain: Domain
    period: Period
    since: datetime
    computed_at: datetime
    kpis: list[Kpi]


class DrillItem(BaseModel):
    id: UUID
    number: str | None = None
    title: str
    severity: str
    status: str
    domain: str
    at: datetime
    seconds: float | None = None
    counted: bool | None = None


class Drill(BaseModel):
    key: KpiKey
    records: Literal["incident", "alert"]
    total: int
    counted: int | None
    items: list[DrillItem]


class SeriesPoint(BaseModel):
    start: datetime
    group: str
    count: int


# ------------------------------------------------------------------ helpers
async def reader(services: Services) -> Any:
    try:
        client = await services.analytics_reader()
    except Exception as exc:
        raise ProblemError(
            503, "analytics.unavailable", "Analytics unavailable", "The analytics store is not reachable."
        ) from exc
    if client is None:
        raise ProblemError(503, "analytics.disabled", "Analytics not configured", "Start the 'stream' profile.")
    return client


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def _mean(total_ms: float, n: int) -> float | None:
    return (total_ms / 1000 / n) if n else None


def _naive(dt: datetime) -> datetime:
    return dt.astimezone(UTC).replace(tzinfo=None)


def build_kpis(inc: dict[str, Any], al: dict[str, Any]) -> list[Kpi]:
    total, alerts = int(inc.get("total", 0)), int(al.get("total", 0))
    acked, resolved = int(inc.get("acked", 0)), int(inc.get("resolved", 0))
    ack_met, ack_due = int(inc.get("ack_met", 0)), int(inc.get("ack_due", 0))
    res_met, res_due = int(inc.get("res_met", 0)), int(inc.get("res_due", 0))
    values: dict[str, tuple[float | None, int | None, int]] = {
        "incidents_opened": (float(total), None, total),
        "open_incidents": (float(inc.get("open", 0)), None, int(inc.get("open", 0))),
        "mtta": (_mean(float(inc.get("ack_ms", 0)), acked), None, acked),
        "mttr": (_mean(float(inc.get("res_ms", 0)), resolved), None, resolved),
        "ack_sla": (_ratio(ack_met, ack_due), ack_met, ack_due),
        "resolve_sla": (_ratio(res_met, res_due), res_met, res_due),
        "automation_rate": (_ratio(int(inc.get("automated", 0)), total), int(inc.get("automated", 0)), total),
        "alert_volume": (float(alerts), None, alerts),
        "noise_ratio": (_ratio(int(al.get("not_escalated", 0)), alerts), int(al.get("not_escalated", 0)), alerts),
    }
    out = []
    for key, (value, numerator, basis) in values.items():
        label, unit, kind, description = META[key]
        if value is not None and math.isnan(value):
            value = None
        out.append(
            Kpi(
                key=key,  # type: ignore[arg-type]
                label=label,
                unit=unit,  # type: ignore[arg-type]
                value=value,
                numerator=numerator,
                basis=basis,
                records=kind,  # type: ignore[arg-type]
                description=description,
            )
        )
    return out


async def compute(
    services: Services, tenants: UUID | list[UUID], domain: str, period: str, *, by_tenant: bool = False
) -> tuple[datetime, datetime, list[dict[str, Any]], list[dict[str, Any]]]:
    now = datetime.now(UTC)
    since = now - PERIODS[period]
    client = await reader(services)
    group, group_by = ("tenant_id,", "GROUP BY tenant_id") if by_tenant else ("", "")
    params = {"since": _naive(since), "now": _naive(now)}
    inc = await reader_query(
        client,
        tenants,
        INCIDENT_STATS.replace("{domain}", INCIDENT_DOMAIN[domain])
        .replace("{group}", group)
        .replace("{group_by}", group_by),
        params,
    )
    al = await reader_query(
        client,
        tenants,
        ALERT_STATS.replace("{domain}", ALERT_DOMAIN[domain]).replace("{group}", group).replace("{group_by}", group_by),
        params,
    )
    return since, now, inc, al


# ------------------------------------------------------------------ endpoints
@router.get("/analytics/kpis", response_model=KpiSet, **requires("analytics:read"))
async def get_kpis(services: Svc, p: P, domain: Domain = "all", period: Period = "7d") -> KpiSet:
    since, now, inc, al = await compute(services, p.tenant_id, domain, period)  # type: ignore[arg-type]
    return KpiSet(
        domain=domain,
        period=period,
        since=since,
        computed_at=now,
        kpis=build_kpis(inc[0] if inc else {}, al[0] if al else {}),
    )


DRILL_INCIDENT = (
    "SELECT incident_id AS id, number, title, severity, status, domain, detected_at AS at, "  # nosec B608 - fixed fragments, bound values
    "if(acknowledged_at IS NULL, NULL, dateDiff('millisecond', detected_at, assumeNotNull(acknowledged_at)) / 1000) "
    "AS ack_s, if(resolved_at IS NULL, NULL, dateDiff('millisecond', detected_at, assumeNotNull(resolved_at)) / 1000) "
    f"AS res_s, {_ACK_DUE} AS ack_due, {_ACK_DUE} AND {_ACK_MET} AS ack_met, {_RES_DUE} AS res_due, "
    f"{_RES_DUE} AND {_RES_MET} AS res_met, {_AUTOMATED} AS automated "
    "FROM incident_facts FINAL WHERE merged = 0 AND detected_at >= {since:DateTime64(3)} AND {domain} "
    "{extra} ORDER BY detected_at DESC LIMIT {lim:UInt32}"
)
DRILL_ALERT = (
    "SELECT alert_id AS id, title, severity, status, domain, first_seen AS at, incident_id IS NOT NULL AS escalated "
    "FROM alert_facts FINAL WHERE first_seen >= {since:DateTime64(3)} AND {domain} {extra} "
    "ORDER BY first_seen DESC LIMIT {lim:UInt32}"
)
DRILL_FILTER = {
    "incidents_opened": "",
    "open_incidents": "AND status NOT IN ('resolved', 'closed')",
    "mtta": "AND acknowledged_at IS NOT NULL",
    "mttr": "AND resolved_at IS NOT NULL",
    "ack_sla": f"AND {_ACK_DUE}",
    "resolve_sla": f"AND {_RES_DUE}",
    "automation_rate": "",
    "alert_volume": "",
    "noise_ratio": "",
}


@router.get("/analytics/kpis/{key}/records", response_model=Drill, **requires("analytics:read"))
async def kpi_records(
    key: KpiKey,
    services: Svc,
    p: P,
    domain: Domain = "all",
    period: Period = "7d",
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
) -> Drill:
    """The records behind a KPI's basis. ``counted`` marks the numerator (SLA met, automated,
    not escalated) where the KPI is a ratio; ``seconds`` carries the duration for MTTA/MTTR."""
    now = datetime.now(UTC)
    since = now - PERIODS[period]
    kind = META[key][2]
    template = DRILL_INCIDENT if kind == "incident" else DRILL_ALERT
    domains = INCIDENT_DOMAIN if kind == "incident" else ALERT_DOMAIN
    sql = template.replace("{domain}", domains[domain]).replace("{extra}", DRILL_FILTER[key])
    rows = await reader_query(
        await reader(services), p.tenant_id, sql, {"since": _naive(since), "now": _naive(now), "lim": limit}
    )
    items: list[DrillItem] = []
    for r in rows:
        at = r["at"] if r["at"].tzinfo else r["at"].replace(tzinfo=UTC)
        seconds = {"mtta": r.get("ack_s"), "mttr": r.get("res_s")}.get(key)
        counted = {
            "ack_sla": r.get("ack_met"),
            "resolve_sla": r.get("res_met"),
            "automation_rate": r.get("automated"),
            "noise_ratio": (not r["escalated"]) if "escalated" in r else None,
        }.get(key)
        items.append(
            DrillItem(
                id=r["id"],
                number=r.get("number"),
                title=r["title"],
                severity=r["severity"],
                status=r["status"],
                domain=r["domain"],
                at=at,
                seconds=float(seconds) if seconds is not None else None,
                counted=bool(counted) if counted is not None else None,
            )
        )
    counted_total = sum(1 for i in items if i.counted) if any(i.counted is not None for i in items) else None
    return Drill(key=key, records=kind, total=len(items), counted=counted_total, items=items)  # type: ignore[arg-type]


@router.get("/analytics/timeseries", response_model=list[SeriesPoint], **requires("analytics:read"))
async def timeseries(
    services: Svc,
    p: P,
    metric: Literal["alerts", "incidents"] = "alerts",
    interval: Literal["hour", "day"] = "day",
    period: Period = "7d",
    domain: Domain = "all",
    group_by: Literal["none", "severity", "domain"] = "severity",
) -> list[SeriesPoint]:
    now = datetime.now(UTC)
    since = now - PERIODS[period]
    if interval == "hour" and period == "90d":
        raise ProblemError(422, "analytics.too_many_buckets", "Too many buckets", "Use daily buckets for 90 days.")
    bucket = "toStartOfHour" if interval == "hour" else "toStartOfDay"
    group = "''" if group_by == "none" else group_by
    if metric == "alerts":
        sql = (
            f"SELECT {bucket}(first_seen) AS start, toString({group}) AS grp, count() AS c FROM alert_facts FINAL "  # nosec B608 - fixed fragments, bound values
            f"WHERE first_seen >= {{since:DateTime64(3)}} AND {ALERT_DOMAIN[domain]} GROUP BY start, grp ORDER BY "
            f"start, grp"
        )
    else:
        sql = (
            f"SELECT {bucket}(detected_at) AS start, toString({group}) AS grp, count() AS c FROM incident_facts FINAL "  # nosec B608 - fixed fragments, bound values
            f"WHERE merged = 0 AND detected_at >= {{since:DateTime64(3)}} AND {INCIDENT_DOMAIN[domain]} "
            "GROUP BY start, grp ORDER BY start, grp"
        )
    rows = await reader_query(await reader(services), p.tenant_id, sql, {"since": _naive(since)})  # nosec B608
    return [
        SeriesPoint(
            start=r["start"].replace(tzinfo=UTC) if r["start"].tzinfo is None else r["start"],
            group=r["grp"],
            count=r["c"],
        )
        for r in rows
    ]


# ------------------------------------------------------------------ command center
class OpenIncident(BaseModel):
    id: UUID
    number: str
    title: str
    domain: str
    severity: str
    priority: str
    status: str
    detected_at: datetime


class Overview(BaseModel):
    period: Period
    computed_at: datetime
    kpis: dict[str, list[Kpi]]
    open_incidents: list[OpenIncident]


@router.get("/command-center/overview", response_model=Overview, **requires("portal:command"))
async def overview(services: Svc, p: P, period: Period = "7d") -> Overview:
    """KPIs for all, NOC and SOC in one call, plus the open P1/P2 incidents (from Postgres)."""
    if not p.has("analytics:read"):
        raise ProblemError(403, "authz.forbidden", "Forbidden", "The command center also needs analytics:read.")
    sets: dict[str, list[Kpi]] = {}
    computed = datetime.now(UTC)
    for domain in ("all", "noc", "soc"):
        _since, computed, inc, al = await compute(services, p.tenant_id, domain, period)  # type: ignore[arg-type]
        sets[domain] = build_kpis(inc[0] if inc else {}, al[0] if al else {})
    open_rows: list[OpenIncident] = []
    if p.has("incident:read"):
        async with tenant_tx(services, p) as conn:
            rows = await conn.execute(
                text(
                    "SELECT id, number, title, domain, severity, priority, status, detected_at FROM incidents "
                    "WHERE status NOT IN ('resolved', 'closed') AND merged_into_id IS NULL AND priority IN ('P1', "
                    "'P2') "
                    "ORDER BY priority, detected_at DESC LIMIT 10"
                )
            )
            open_rows = [OpenIncident(**r._mapping) for r in rows]
    return Overview(period=period, computed_at=computed, kpis=sets, open_incidents=open_rows)


class CustomerKpis(BaseModel):
    tenant_id: UUID
    name: str
    slug: str
    kpis: list[Kpi]


@router.get(
    "/command-center/customers",
    response_model=list[CustomerKpis],
    **requires("portal:command", aggregate=True),
)
async def customers(services: Svc, p: P, period: Period = "7d", domain: Domain = "all") -> list[CustomerKpis]:
    """MSP "All customers" view: the same KPIs per delegated customer, read-only. The tenant list
    comes from the caller's live delegations (computed per request), never from the client."""
    if not p.has("analytics:read"):
        raise ProblemError(403, "authz.forbidden", "Forbidden", "The command center also needs analytics:read.")
    ids = list(p.aggregate_tenant_ids)
    if not ids:
        return []
    _since, _now, inc, al = await compute(services, ids, domain, period, by_tenant=True)
    inc_by = {UUID(str(r["tenant_id"])): r for r in inc}
    al_by = {UUID(str(r["tenant_id"])): r for r in al}
    async with services.app_db.aggregate(p.aggregate_tenant_ids, p.user_id) as conn:
        tenants = list(
            await conn.execute(
                text("SELECT id, name, slug::text AS slug FROM tenants WHERE id = ANY (app_tenant_ids()) ORDER BY name")
            )
        )
    return [
        CustomerKpis(
            tenant_id=t.id, name=t.name, slug=t.slug, kpis=build_kpis(inc_by.get(t.id, {}), al_by.get(t.id, {}))
        )
        for t in tenants
    ]
