"""Saved reports with CSV and PDF export (P6).

A report is a saved definition (kind, domain, period); every export is computed fresh:
- ``kpi_summary``: the Command Center KPIs (ClickHouse facts, same code as the KPI API);
- ``incident_register``: incidents detected in the period (Postgres);
- ``sla_report``: per-incident SLA outcomes plus the MTTA/MTTR/attainment summary (Postgres).

Exports are audited (``report.export``). CSV cells that a spreadsheet could treat as a formula
are prefixed with a quote (CSV injection), since alert and incident text comes from outside.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.core.tenancy.common import record, tenant_tx
from app.errors import ProblemError, not_found
from app.incidents.sla import compute_metrics, evaluate, merged_targets
from app.kpis import PERIODS, build_kpis, compute
from app.pdf import Document
from app.services import Services, get_services

router = APIRouter(tags=["reports"])
Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]

Kind = Literal["kpi_summary", "incident_register", "sla_report"]
KIND_LABEL = {
    "kpi_summary": "KPI summary",
    "incident_register": "Incident register",
    "sla_report": "SLA report",
}
DOMAIN_SQL = {"all": "TRUE", "noc": "domain IN ('noc', 'joint')", "soc": "domain IN ('soc', 'joint')"}


class ReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    kind: Kind
    domain: Literal["all", "noc", "soc"] = "all"
    period: Literal["24h", "7d", "30d", "90d"] = "7d"


class ReportOut(BaseModel):
    id: UUID
    name: str
    kind: Kind
    domain: str
    period: str
    created_at: datetime
    last_exported_at: datetime | None


def safe_cell(value: object) -> str:
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _fmt_seconds(value: float | None) -> str:
    if value is None:
        return "-"
    minutes = value / 60
    return f"{minutes:.0f} min" if minutes < 120 else f"{minutes / 60:.1f} h"


def _fmt_kpi(unit: str, value: float | None) -> str:
    if value is None:
        return "-"
    if unit == "ratio":
        return f"{value * 100:.1f}%"
    if unit == "seconds":
        return _fmt_seconds(value)
    return f"{value:.0f}"


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.1f}%"


def _ts(value: datetime | None) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if value else ""


@router.get("/reports", response_model=list[ReportOut], **requires("report:read"))
async def list_reports(services: Svc, p: P) -> list[ReportOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(
            text("SELECT id, name, kind, domain, period, created_at, last_exported_at FROM reports ORDER BY name")
        )
        return [ReportOut(**r._mapping) for r in rows]


@router.post("/reports", response_model=ReportOut, status_code=status.HTTP_201_CREATED, **requires("report:create"))
async def create_report(body: ReportIn, services: Svc, p: P) -> ReportOut:
    async with tenant_tx(services, p) as conn:
        if (await conn.execute(text("SELECT 1 FROM reports WHERE name = :n"), {"n": body.name})).first():
            raise ProblemError(409, "report.name_taken", "Name in use", "Another report has this name.")
        row = (
            await conn.execute(
                text(
                    "INSERT INTO reports (tenant_id, name, kind, domain, period, created_by) VALUES (app_tenant(), :n, "
                    ":k, :d, :p, :u) RETURNING id, name, kind, domain, period, created_at, last_exported_at"
                ),
                {"n": body.name, "k": body.kind, "d": body.domain, "p": body.period, "u": p.user_id},
            )
        ).one()
        await record(conn, p, "report.create", target_type="report", target_id=row.id, details=body.model_dump())
    return ReportOut(**row._mapping)


@router.delete("/reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT, **requires("report:create"))
async def delete_report(report_id: UUID, services: Svc, p: P) -> Response:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(text("DELETE FROM reports WHERE id = :i RETURNING name"), {"i": report_id})
        ).one_or_none()
        if row is None:
            raise not_found("Report")
        await record(conn, p, "report.delete", target_type="report", target_id=report_id, details={"name": row.name})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _table(
    services: Services, p: Principal, kind: str, domain: str, period: str
) -> tuple[list[str], list[list[str]], list[str]]:
    """(header, rows, summary lines) for one export."""
    if kind == "kpi_summary":
        if not p.has("analytics:read"):
            raise ProblemError(403, "authz.forbidden", "Forbidden", "KPI reports also need analytics:read.")
        _since, _now, inc, al = await compute(services, p.tenant_id, domain, period)  # type: ignore[arg-type]
        kpis = build_kpis(inc[0] if inc else {}, al[0] if al else {})
        rows = [
            [
                k.label,
                _fmt_kpi(k.unit, k.value),
                "" if k.numerator is None else str(k.numerator),
                str(k.basis),
                k.description,
            ]
            for k in kpis
        ]
        return ["KPI", "Value", "Numerator", "Basis", "Definition"], rows, []
    if not p.has("incident:read"):
        raise ProblemError(403, "authz.forbidden", "Forbidden", "Incident reports also need incident:read.")
    since = datetime.now(UTC) - PERIODS[period]
    async with tenant_tx(services, p) as conn:
        incidents = list(
            await conn.execute(
                text(
                    "SELECT number, title, domain, severity, priority, status, detected_at, acknowledged_at, "
                    "resolved_at "
                    f"FROM incidents WHERE merged_into_id IS NULL AND detected_at >= :s AND {DOMAIN_SQL[domain]} "
                    f""  # nosec B608
                    "ORDER BY detected_at DESC LIMIT 5000"
                ),
                {"s": since},
            )
        )
        custom = (await conn.execute(text("SELECT targets FROM sla_policies"))).scalar_one_or_none()
    targets = merged_targets(custom)
    now = datetime.now(UTC)
    if kind == "incident_register":
        header = ["Number", "Title", "Domain", "Severity", "Priority", "Status", "Detected", "Acknowledged", "Resolved"]
        rows = [
            [
                i.number,
                i.title,
                i.domain.upper(),
                i.severity,
                i.priority,
                i.status,
                _ts(i.detected_at),
                _ts(i.acknowledged_at),
                _ts(i.resolved_at),
            ]
            for i in incidents
        ]
        return header, rows, [f"{len(rows)} incident(s)."]
    header = ["Number", "Priority", "Status", "Ack due", "Ack met", "Resolve due", "Resolve met"]
    rows = []
    for i in incidents:
        s = evaluate(i.priority, i.detected_at, i.acknowledged_at, i.resolved_at, now, targets)
        ack_known = i.acknowledged_at is not None or now > s.ack_due_at
        res_known = i.resolved_at is not None or now > s.resolve_due_at
        rows.append(
            [
                i.number,
                i.priority,
                i.status,
                _ts(s.ack_due_at),
                ("no" if s.ack_breached else "yes") if ack_known else "pending",
                _ts(s.resolve_due_at),
                ("no" if s.resolve_breached else "yes") if res_known else "pending",
            ]
        )
    m = compute_metrics(incidents, targets, now)
    summary = [
        f"Incidents: {m['total']} (open {m['open']}, resolved {m['resolved']}).",
        f"MTTA {_fmt_seconds(m['mtta_seconds'])}, MTTR {_fmt_seconds(m['mttr_seconds'])}.",
        f"Acknowledge SLA met {_pct(m['ack_sla_attainment'])}, resolve SLA met {_pct(m['resolve_sla_attainment'])}.",
    ]
    return header, rows, summary


@router.get("/reports/{report_id}/export", **requires("report:read"))
async def export_report(
    report_id: UUID,
    services: Svc,
    p: P,
    format: Literal["csv", "pdf"] = "csv",
) -> Response:
    async with tenant_tx(services, p) as conn:
        rep = (
            await conn.execute(text("SELECT name, kind, domain, period FROM reports WHERE id = :i"), {"i": report_id})
        ).one_or_none()
    if rep is None:
        raise not_found("Report")
    header, rows, summary = await _table(services, p, rep.kind, rep.domain, rep.period)
    generated = datetime.now(UTC)
    async with tenant_tx(services, p) as conn:
        await conn.execute(text("UPDATE reports SET last_exported_at = now() WHERE id = :i"), {"i": report_id})
        await record(
            conn,
            p,
            "report.export",
            target_type="report",
            target_id=report_id,
            details={"format": format, "rows": len(rows)},
        )
    slug = "".join(c if c.isalnum() else "-" for c in rep.name.lower()).strip("-")[:60] or "report"
    filename = f"{slug}-{generated:%Y%m%d-%H%M}.{format}"
    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow([safe_cell(h) for h in header])
        for r in rows:
            w.writerow([safe_cell(c) for c in r])
        content = buf.getvalue().encode("utf-8-sig")
        media = "text/csv; charset=utf-8"
    else:
        doc = Document(rep.name, landscape=True)
        doc.text(
            f"{KIND_LABEL[rep.kind]} · domain {rep.domain.upper()} · last {rep.period} · generated {_ts(generated)}",
            9,
        )
        doc.text("Sandbox data: built from simulated connector data and DEMO seed content, not production systems.", 9)
        for line in summary:
            doc.text(line)
        doc.heading("Details")
        widths = {
            "kpi_summary": [22, 10, 9, 6, 70],
            "incident_register": [10, 32, 6, 8, 8, 13, 20, 20, 20],
            "sla_report": [10, 8, 13, 20, 7, 20, 11],
        }[rep.kind]
        doc.table(header, rows, widths)
        content = doc.render()
        media = "application/pdf"
    return Response(
        content=content,
        media_type=media,
        headers={"content-disposition": f'attachment; filename="{filename}"', "cache-control": "no-store"},
    )
