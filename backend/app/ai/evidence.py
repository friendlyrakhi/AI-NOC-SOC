"""Evidence assembly (docs/02 §5.3, threat model T11).

All reads go through the caller's tenant transaction (RLS), so evidence can only come from the
caller's tenant. Each item gets a ref (E1, E2, ...) that claims must cite. Text is clipped, the
total is bounded, and every item is checked for instruction-like content.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.ai import knowledge
from app.ai.injection import is_suspicious
from app.errors import not_found
from app.services import Services

MAX_ITEMS = 50
TITLE_CHARS = 300
TEXT_CHARS = 1500


@dataclass
class EvidenceSet:
    subject: dict[str, Any]
    items: list[dict[str, Any]] = field(default_factory=list)
    connectors: set[str] = field(default_factory=set)

    def add(
        self,
        type_: str,
        id_: Any,
        title: str,
        body: str = "",
        *,
        severity: str | None = None,
        at: Any = None,
        **attributes: Any,
    ) -> str | None:
        if len(self.items) >= MAX_ITEMS:
            return None
        ref = f"E{len(self.items) + 1}"
        title = (title or "")[:TITLE_CHARS]
        body = (body or "")[:TEXT_CHARS]
        self.items.append(
            {
                "ref": ref,
                "type": type_,
                "id": str(id_),
                "title": title,
                "text": body,
                "severity": severity,
                "at": at.isoformat() if hasattr(at, "isoformat") else at,
                "attributes": {k: v for k, v in attributes.items() if v not in (None, "", [])},
                "suspicious": is_suspicious(title) or is_suspicious(body),
            }
        )
        return ref

    @property
    def refs(self) -> set[str]:
        return {i["ref"] for i in self.items}

    @property
    def suspicious(self) -> int:
        return sum(1 for i in self.items if i["suspicious"])


_ALERT_COLS = (
    "a.id, a.title, a.description, a.severity, a.status, a.domain, a.connector_id, a.last_seen, a.occurrence_count, "
    "a.mitre_techniques, a.asset_id, s.name AS asset_name, sv.name AS service_name "
    "FROM alerts a LEFT JOIN assets s ON s.id = a.asset_id LEFT JOIN services sv ON sv.id = a.service_id"
)


def _add_alert(ev: EvidenceSet, a: Any) -> None:
    ev.connectors.add(a.connector_id)
    ev.add(
        "alert",
        a.id,
        a.title,
        a.description,
        severity=a.severity,
        at=a.last_seen,
        asset=a.asset_name,
        connector=a.connector_id,
        domain=a.domain,
        status=a.status,
        occurrences=a.occurrence_count,
        service=a.service_name,
        mitre=list(a.mitre_techniques or []),
    )


async def _add_runbooks(services: Services, conn: AsyncConnection, ev: EvidenceSet, query: str) -> None:
    for hit in await knowledge.retrieve(services, conn, query, k=3):
        ev.add("runbook", hit["id"], hit["title"], hit["text"], kind=hit["kind"])


async def for_alert(services: Services, conn: AsyncConnection, alert_id: UUID) -> EvidenceSet:
    a = (await conn.execute(text(f"SELECT {_ALERT_COLS} WHERE a.id = :i"), {"i": alert_id})).one_or_none()  # nosec B608
    if a is None:
        raise not_found("Alert")
    ev = EvidenceSet(subject={"type": "alert", "id": str(alert_id)})
    _add_alert(ev, a)
    inc = (
        await conn.execute(
            text(
                "SELECT i.id, i.number, i.title, i.status, i.priority, i.domain FROM incident_alerts ia "
                "JOIN incidents i ON i.id = ia.incident_id WHERE ia.alert_id = :i"
            ),
            {"i": alert_id},
        )
    ).one_or_none()
    if inc is not None:
        ev.add(
            "incident",
            inc.id,
            f"{inc.number} {inc.title}",
            number=inc.number,
            status=inc.status,
            priority=inc.priority,
            domain=inc.domain,
        )
    if a.asset_id is not None:
        related = await conn.execute(
            text(
                f"SELECT {_ALERT_COLS} WHERE a.asset_id = :s AND a.id <> :i "  # nosec B608
                "AND a.last_seen >= now() - interval '24 hours' ORDER BY severity_rank(a.severity), a.last_seen DESC "
                "LIMIT 10"
            ),
            {"s": a.asset_id, "i": alert_id},
        )
        for r in related:
            _add_alert(ev, r)
    await _add_runbooks(services, conn, ev, f"{a.title}\n{a.description or ''}\n{a.service_name or ''}")
    return ev


async def for_incident(services: Services, conn: AsyncConnection, incident_id: UUID) -> EvidenceSet:
    inc = (
        await conn.execute(
            text(
                "SELECT i.*, coalesce((SELECT array_agg(s.name ORDER BY s.tier) FROM services s "
                "WHERE s.id = ANY(i.impacted_service_ids)), '{}') AS service_names FROM incidents i WHERE i.id = :i"
            ),
            {"i": incident_id},
        )
    ).one_or_none()
    if inc is None:
        raise not_found("Incident")
    ev = EvidenceSet(subject={"type": "incident", "id": str(incident_id), "number": inc.number})
    ev.add(
        "incident",
        inc.id,
        f"{inc.number} {inc.title}",
        inc.summary,
        severity=inc.severity,
        at=inc.detected_at,
        number=inc.number,
        status=inc.status,
        priority=inc.priority,
        domain=inc.domain,
        services=list(inc.service_names),
        acknowledged_at=str(inc.acknowledged_at or ""),
        resolved_at=str(inc.resolved_at or ""),
    )
    alerts = await conn.execute(
        text(
            f"SELECT {_ALERT_COLS} JOIN incident_alerts ia ON ia.alert_id = a.id "  # nosec B608
            "WHERE ia.incident_id = :i ORDER BY severity_rank(a.severity), a.last_seen LIMIT 25"
        ),
        {"i": incident_id},
    )
    alert_titles = []
    for a in alerts:
        _add_alert(ev, a)
        alert_titles.append(a.title)
    services_rows = await conn.execute(
        text(
            "SELECT s.id, s.name, s.tier, "
            "coalesce(array_agg(x.name) FILTER (WHERE sa.role = 'dependency'), '{}') AS deps, "
            "coalesce(array_agg(x.name) FILTER (WHERE sa.role = 'member'), '{}') AS members "
            "FROM services s LEFT JOIN service_assets sa ON sa.service_id = s.id LEFT JOIN assets x ON x.id = "
            "sa.asset_id "
            "WHERE s.id = ANY(:ids) GROUP BY s.id"
        ),
        {"ids": list(inc.impacted_service_ids)},
    )
    for s in services_rows:
        ev.add("service", s.id, s.name, tier=s.tier, dependencies=list(s.deps), members=list(s.members))
    entries = await conn.execute(
        text(
            "SELECT id, kind, body, at FROM timeline_entries WHERE incident_id = :i "
            "AND kind IN ('comment', 'state_change', 'escalation', 'merge', 'external_sync') ORDER BY id DESC LIMIT 15"
        ),
        {"i": incident_id},
    )
    for t in reversed(list(entries)):
        b = t.body or {}
        summary = str(b.get("text") or b.get("reason") or "")
        title = {"comment": "Analyst comment", "state_change": f"Status {b.get('from', '')} -> {b.get('to', '')}"}.get(
            t.kind, t.kind.replace("_", " ")
        )
        ev.add("timeline", t.id, title, summary, at=t.at, kind=t.kind)
    await _add_runbooks(services, conn, ev, f"{inc.title}\n" + "\n".join(alert_titles[:8]))
    return ev


async def for_briefing(services: Services, conn: AsyncConnection, tenant_id: UUID | None) -> EvidenceSet:
    """Daily briefing (P6): the last 24 hours' KPIs (ClickHouse facts, when available), the open
    P1/P2 incidents and notable alerts not yet in an incident. Postgres reads use the caller's
    RLS transaction; the KPI read carries the same tenant to the analytics row policies."""
    from app.errors import ProblemError
    from app.kpis import build_kpis, compute

    ev = EvidenceSet(subject={"type": "none", "briefing": "24h"})
    try:
        _since, _now, inc, al = await compute(services, tenant_id, "all", "24h")  # type: ignore[arg-type]
        for k in build_kpis(inc[0] if inc else {}, al[0] if al else {}):
            ev.add(
                "kpi",
                k.key,
                f"{k.label} (last 24 h)",
                k.description,
                key=k.key,
                label=k.label,
                value=k.value,
                unit=k.unit,
                basis=k.basis,
                numerator=k.numerator,
                period="24h",
            )
    except ProblemError:
        pass  # analytics not running: the briefing says so in its gaps
    incidents = await conn.execute(
        text(
            "SELECT id, number, title, summary, severity, priority, status, domain, detected_at FROM incidents "
            "WHERE status NOT IN ('resolved', 'closed') AND merged_into_id IS NULL AND priority IN ('P1', 'P2') "
            "ORDER BY priority, detected_at DESC LIMIT 10"
        )
    )
    for i in incidents:
        ev.add(
            "incident",
            i.id,
            f"{i.number} {i.title}",
            i.summary,
            severity=i.severity,
            at=i.detected_at,
            number=i.number,
            priority=i.priority,
            status=i.status,
            domain=i.domain,
        )
    alerts = await conn.execute(
        text(
            f"SELECT {_ALERT_COLS} WHERE a.severity IN ('critical', 'high') "  # nosec B608
            "AND a.status NOT IN ('resolved', 'closed', 'suppressed') AND a.last_seen > now() - interval '24 hours' "
            "AND NOT EXISTS (SELECT 1 FROM incident_alerts ia WHERE ia.alert_id = a.id) "
            "ORDER BY severity_rank(a.severity), a.last_seen DESC LIMIT 10"
        )
    )
    for a in alerts:
        _add_alert(ev, a)
    return ev
