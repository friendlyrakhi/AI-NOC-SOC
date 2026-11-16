"""Database side of correlation, run by the ingest worker inside its tenant transaction.

For each alert that the pipeline inserts (not de-duplicated repeats):
1. maintenance windows and suppression rules may mark it ``suppressed`` (no incident);
2. otherwise the pure engine (``correlation.decide``) links it to an open incident, escalates
   that incident to joint, or opens a new incident.

Also here: CMDB topology sync (``ServiceV1``) and inbound ITSM ticket sync with echo detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.incidents import store
from app.incidents.correlation import (
    AlertFacts,
    Candidate,
    absorb,
    decide,
    effective_rules,
    max_priority,
    max_severity,
    observable_keys,
    priority_for,
)
from nocsoc_connector_sdk import ServiceV1, TicketV1

# ServiceNow incident states that close the loop on our side (docs/05 §4).
ITSM_TO_INCIDENT = {"in_progress": "investigating", "resolved": "resolved", "closed": "closed"}
INCIDENT_TO_ITSM = {"investigating": "2", "contained": "2", "mitigated": "2", "resolved": "6", "closed": "7"}
ITSM_STATE_NAMES = {"1": "new", "2": "in_progress", "3": "on_hold", "6": "resolved", "7": "closed", "8": "canceled"}


@dataclass
class Changes:
    """What a transaction did, for live updates (SSE) after commit."""

    incidents: set[str] = field(default_factory=set)
    suppressed: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- topology
async def sync_service(conn: AsyncConnection, svc: ServiceV1, instance_id: UUID, resolve: Any) -> UUID:
    """Upserts a CMDB service and replaces its member/dependency links. ``resolve`` maps asset
    refs to an asset id (creating the asset if needed)."""
    service_id = (
        await conn.execute(
            text(
                "INSERT INTO services (tenant_id, name, tier, owner_team, aliases, external_ref, source_instance_id) "
                "VALUES (app_tenant(), :n, :t, :o, CAST(:a AS text[]), :x, :i) "
                "ON CONFLICT (tenant_id, name) DO UPDATE SET tier = EXCLUDED.tier, owner_team = EXCLUDED.owner_team, "
                "aliases = EXCLUDED.aliases, external_ref = EXCLUDED.external_ref, "
                "source_instance_id = EXCLUDED.source_instance_id, updated_at = now(), version = services.version + 1 "
                "RETURNING id"
            ),
            {
                "n": svc.name,
                "t": svc.tier,
                "o": svc.owner_team,
                "a": svc.aliases,
                "x": svc.external_id,
                "i": instance_id,
            },
        )
    ).scalar_one()
    await conn.execute(text("DELETE FROM service_assets WHERE service_id = :s"), {"s": service_id})
    for role, refs in (("member", svc.members), ("dependency", svc.depends_on)):
        for ref in refs:
            asset_id = await resolve([ref])
            if asset_id is not None:
                await conn.execute(
                    text(
                        "INSERT INTO service_assets (tenant_id, service_id, asset_id, role) "
                        "VALUES (app_tenant(), :s, :a, :r) ON CONFLICT DO NOTHING"
                    ),
                    {"s": service_id, "a": asset_id, "r": role},
                )
    return service_id  # type: ignore[no-any-return]


async def _alert_services(conn: AsyncConnection, asset_id: UUID | None, service_hint: str | None) -> list[Any]:
    rows = await conn.execute(
        text(
            "SELECT DISTINCT s.id, s.name, s.tier, sa.role FROM services s "
            "JOIN service_assets sa ON sa.service_id = s.id WHERE sa.asset_id = :a "
            "UNION SELECT s.id, s.name, s.tier, 'member' FROM services s "
            "WHERE CAST(:h AS text) IS NOT NULL AND :h = ANY(s.aliases)"
        ),
        {"a": asset_id, "h": service_hint},
    )
    return list(rows)


# ---------------------------------------------------------------- maintenance and suppression
def _rule_matches(match: dict[str, Any], alert: Any) -> bool:
    checks = []
    if "connector" in match:
        checks.append(alert.connector_id == match["connector"])
    if "domain" in match:
        checks.append(alert.domain == match["domain"])
    if "severity" in match:
        checks.append(alert.severity in match["severity"])
    if "asset_id" in match:
        checks.append(str(alert.asset_id) == str(match["asset_id"]))
    if "title_contains" in match:
        checks.append(str(match["title_contains"]).lower() in alert.title.lower())
    return bool(checks) and all(checks)


async def _suppression(conn: AsyncConnection, alert: Any, service_ids: list[UUID], now: datetime) -> str | None:
    window = (
        await conn.execute(
            text(
                "SELECT title FROM maintenance_windows WHERE cancelled_at IS NULL "
                "AND starts_at <= :now AND ends_at > :now "
                "AND (:a = ANY(asset_ids) OR service_ids && CAST(:s AS uuid[])) ORDER BY starts_at LIMIT 1"
            ),
            {"now": now, "a": alert.asset_id, "s": [str(s) for s in service_ids]},
        )
    ).scalar_one_or_none()
    if window is not None:
        return f"Maintenance window: {window}"
    rules = await conn.execute(
        text("SELECT id, name, match FROM suppression_rules WHERE enabled AND expires_at > :now ORDER BY created_at"),
        {"now": now},
    )
    for rule in rules:
        if _rule_matches(rule.match or {}, alert):
            await conn.execute(text("UPDATE suppression_rules SET hits = hits + 1 WHERE id = :i"), {"i": rule.id})
            return f"Suppression rule: {rule.name}"
    return None


# ---------------------------------------------------------------- correlation
async def _candidates(conn: AsyncConnection, since: datetime) -> list[Candidate]:
    rows = await conn.execute(
        text(
            "SELECT i.id, i.domain, i.impacted_service_ids, i.detected_at, i.created_by_type, "
            "max(a.last_seen) AS last_at, array_remove(array_agg(DISTINCT a.asset_id), NULL) AS assets, "
            "coalesce(jsonb_agg(a.observables), '[]'::jsonb) AS obs "
            "FROM incidents i JOIN incident_alerts ia ON ia.incident_id = i.id JOIN alerts a ON a.id = ia.alert_id "
            "WHERE i.status NOT IN ('resolved', 'closed') AND i.merged_into_id IS NULL "
            "GROUP BY i.id HAVING max(a.last_seen) >= :since"
        ),
        {"since": since},
    )
    out = []
    for r in rows:
        observables: set[str] = set()
        for group in r.obs or []:
            observables |= observable_keys(group or [])
        out.append(
            Candidate(
                id=str(r.id),
                domain=r.domain,
                last_alert_at=r.last_at,
                assets={str(a) for a in r.assets},
                services={str(s) for s in r.impacted_service_ids},
                observables=observables,
                opened_at=r.detected_at,
                auto=r.created_by_type == "correlation",
            )
        )
    return out


_ALERT_COLS = (
    "a.id, a.domain, a.severity, a.status, a.title, a.asset_id, a.service_hint, a.service_id, "
    "a.connector_id, a.last_seen, a.observables, a.sandbox, s.name AS asset_name "
    "FROM alerts a LEFT JOIN assets s ON s.id = a.asset_id"
)


@dataclass
class _Alert:
    row: Any
    facts: AlertFacts
    services: list[Any]

    @property
    def best_tier(self) -> int | None:
        return min((s.tier for s in self.services), default=None)


async def _describe(conn: AsyncConnection, row: Any) -> _Alert:
    services = await _alert_services(conn, row.asset_id, row.service_hint)
    facts = AlertFacts(
        id=str(row.id),
        domain=row.domain,
        severity=row.severity,
        observed_at=row.last_seen,
        asset_id=str(row.asset_id) if row.asset_id else None,
        asset_name=row.asset_name,
        services=frozenset(str(s.id) for s in services),
        observables=observable_keys(row.observables or []),
        title=row.title,
    )
    return _Alert(row, facts, services)


async def _pending(conn: AsyncConnection, since: datetime, exclude: UUID) -> list[_Alert]:
    """Recent open alerts that are in no incident (e.g. medium alerts that arrived first)."""
    rows = await conn.execute(
        text(
            f"SELECT {_ALERT_COLS} WHERE a.status NOT IN ('resolved', 'closed', 'suppressed') "  # nosec B608
            "AND a.last_seen >= :since AND a.id <> :x "
            "AND NOT EXISTS (SELECT 1 FROM incident_alerts ia WHERE ia.alert_id = a.id) "
            "ORDER BY a.last_seen LIMIT 500"
        ),
        {"since": since, "x": exclude},
    )
    return [await _describe(conn, r) for r in rows]


async def _grow(conn: AsyncConnection, incident_id: str, alert: _Alert, rule: str | None, reason: str) -> None:
    """Links an alert to an incident and updates services, severity, priority and domain."""
    inc = (
        await conn.execute(
            text("SELECT domain, severity, priority, impacted_service_ids FROM incidents WHERE id = :i"),
            {"i": incident_id},
        )
    ).one()
    await store.link_alert(conn, incident_id, alert.row.id, added_by="correlation", rule_key=rule, reason=reason)
    services = sorted({*map(str, inc.impacted_service_ids), *(str(s.id) for s in alert.services)})
    domain = "joint" if inc.domain != "joint" and alert.row.domain != inc.domain else inc.domain
    await conn.execute(
        text(
            "UPDATE incidents SET impacted_service_ids = CAST(:svc AS uuid[]), severity = :sev, priority = :p, "
            "domain = :d, updated_at = now(), version = version + 1 WHERE id = :i"
        ),
        {
            "svc": services,
            "sev": max_severity(inc.severity, alert.row.severity),
            "p": max_priority(inc.priority, priority_for(alert.row.severity, alert.best_tier)),
            "d": domain,
            "i": incident_id,
        },
    )
    if domain != inc.domain:
        await store.timeline(
            conn,
            incident_id,
            "escalation",
            {"from": inc.domain, "to": "joint", "reason": f"{alert.row.domain.upper()} alert joined: {reason}"},
        )


async def _merge(conn: AsyncConnection, keep_id: str, gone_id: str, reason: str) -> None:
    """Moves every alert of ``gone_id`` into ``keep_id`` and closes ``gone_id`` as merged."""
    keep = (
        await conn.execute(
            text("SELECT number, domain, severity, priority, impacted_service_ids FROM incidents WHERE id = :i"),
            {"i": keep_id},
        )
    ).one()
    gone = (
        await conn.execute(
            text(
                "SELECT number, domain, severity, priority, impacted_service_ids, status FROM incidents WHERE id = :i"
            ),
            {"i": gone_id},
        )
    ).one()
    moved = (
        await conn.execute(
            text("UPDATE incident_alerts SET incident_id = :k WHERE incident_id = :g RETURNING alert_id"),
            {"k": keep_id, "g": gone_id},
        )
    ).all()
    domain = keep.domain if keep.domain == gone.domain else "joint"
    await conn.execute(
        text(
            "UPDATE incidents SET impacted_service_ids = CAST(:svc AS uuid[]), severity = :sev, priority = :p, "
            "domain = :d, updated_at = now(), version = version + 1 WHERE id = :i"
        ),
        {
            "svc": sorted({*map(str, keep.impacted_service_ids), *map(str, gone.impacted_service_ids)}),
            "sev": max_severity(keep.severity, gone.severity),
            "p": max_priority(keep.priority, gone.priority),
            "d": domain,
            "i": keep_id,
        },
    )
    await conn.execute(
        text(
            "UPDATE incidents SET status = 'closed', closed_at = now(), merged_into_id = :k, updated_at = now(), "
            "version = version + 1 WHERE id = :g"
        ),
        {"k": keep_id, "g": gone_id},
    )
    await store.timeline(conn, keep_id, "merge", {"merged": gone.number, "alerts": len(moved), "reason": reason})
    await store.timeline(conn, gone_id, "merge", {"into": keep.number, "from_status": gone.status, "reason": reason})
    if domain != keep.domain:
        await store.timeline(
            conn, keep_id, "escalation", {"from": keep.domain, "to": "joint", "reason": f"Merged {gone.number}"}
        )


async def after_alert(conn: AsyncConnection, alert_id: str, *, inserted: bool, changes: Changes) -> None:
    row = (await conn.execute(text(f"SELECT {_ALERT_COLS} WHERE a.id = :id"), {"id": alert_id})).one()
    if row.status in ("resolved", "closed", "suppressed"):
        return
    alert = await _describe(conn, row)
    service_ids = [s.id for s in alert.services]
    if alert.services and row.service_id is None:
        primary = min(alert.services, key=lambda s: (s.role != "member", s.tier, s.name))
        await conn.execute(text("UPDATE alerts SET service_id = :s WHERE id = :a"), {"s": primary.id, "a": row.id})

    if inserted:
        reason = await _suppression(conn, row, service_ids, row.last_seen)
        if reason:
            await conn.execute(
                text(
                    "UPDATE alerts SET status = 'suppressed', suppression_reason = :r, updated_at = now() WHERE id = :a"
                ),
                {"r": reason, "a": row.id},
            )
            changes.suppressed.append(str(row.id))
            return

    await store.lock_tenant_incidents(conn)
    if (await conn.execute(text("SELECT 1 FROM incident_alerts WHERE alert_id = :a"), {"a": row.id})).first():
        return
    overrides = {
        r.rule_key: (r.enabled, r.window_minutes)
        for r in await conn.execute(text("SELECT rule_key, enabled, window_minutes FROM correlation_overrides"))
    }
    rules = effective_rules(overrides)
    since = row.last_seen - timedelta(minutes=max((r.window_minutes for r in rules if r.enabled), default=60))
    decision = decide(alert.facts, await _candidates(conn, since), rules)
    if decision.action == "none":
        return
    if decision.action == "create":
        title = row.title if not row.asset_name or row.asset_name in row.title else f"{row.title} on {row.asset_name}"
        new_id, _ = await store.create_incident(
            conn,
            domain=row.domain,
            title=title,
            severity=row.severity,
            priority=priority_for(row.severity, alert.best_tier),
            detected_at=row.last_seen,
            services=service_ids,
            created_by_type="correlation",
            correlation_key=f"alert:{row.id}",
            sandbox=row.sandbox,
        )
        incident_id = str(new_id)
        await store.link_alert(conn, incident_id, row.id, added_by="correlation", rule_key=None, reason=decision.reason)
    else:
        incident_id = decision.incident_id or ""
        await _grow(conn, incident_id, alert, decision.rule, decision.reason)
        for other in decision.merge_ids:
            await _merge(conn, incident_id, other, decision.reason)
            changes.incidents.add(other)

    # Earlier alerts that only now relate to this incident (arrival order must not matter).
    current = next((c for c in await _candidates(conn, since) if c.id == incident_id), None)
    if current is not None:
        pending = {p.facts.id: p for p in await _pending(conn, since, row.id)}
        for facts, rule, reason in absorb(current, [p.facts for p in pending.values()], rules):
            await _grow(conn, incident_id, pending[facts.id], rule, reason)
    changes.incidents.add(incident_id)


# ---------------------------------------------------------------- inbound ITSM sync
async def apply_ticket(conn: AsyncConnection, ticket: TicketV1, instance_id: UUID, changes: Changes) -> None:
    """A ServiceNow update for a linked ticket. Our own pushes come back as echoes (same state
    we last pushed) and are ignored, which is what stops the sync loop."""
    link = (
        await conn.execute(
            text(
                "SELECT t.id, t.incident_id, t.last_pushed_state, t.external_state, i.status "
                "FROM external_tickets t JOIN incidents i ON i.id = t.incident_id "
                "WHERE t.system = 'servicenow' AND t.external_id = :x"
            ),
            {"x": ticket.external_id},
        )
    ).one_or_none()
    if link is None:
        return
    state = ticket.state
    if state == link.external_state:
        return
    echo = link.last_pushed_state is not None and ITSM_STATE_NAMES.get(link.last_pushed_state) == state
    await conn.execute(
        text(
            "UPDATE external_tickets SET external_state = :s, last_synced_at = now(), "
            "last_sync_origin = CASE WHEN :echo THEN last_sync_origin ELSE 'external' END WHERE id = :i"
        ),
        {"s": state, "echo": echo, "i": link.id},
    )
    if echo:
        return
    target = ITSM_TO_INCIDENT.get(state)
    await store.timeline(
        conn,
        link.incident_id,
        "external_sync",
        {"system": "servicenow", "number": ticket.number, "state": state, "applied": bool(target)},
        actor_type="connector",
    )
    if target and target != link.status and target in store.STATUS_TRANSITIONS.get(link.status, set()):
        await store.change_status(
            conn,
            link.incident_id,
            link.status,
            target,
            actor_type="connector",
            actor_id=None,
            reason=f"ServiceNow {ticket.number} moved to {state}",
        )
    changes.incidents.add(str(link.incident_id))
