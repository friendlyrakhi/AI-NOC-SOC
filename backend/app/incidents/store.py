"""Incident persistence shared by correlation (worker role) and the API (app role).

All functions run inside a tenant transaction (``app_tenant()`` set), so RLS scopes every
statement. Timeline entries are only ever inserted.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

TERMINAL = ("resolved", "closed")

# Allowed status moves. "investigating" from "open" is the acknowledgement (sets MTTA).
STATUS_TRANSITIONS: dict[str, set[str]] = {
    "open": {"investigating", "contained", "mitigated", "resolved"},
    "investigating": {"contained", "mitigated", "resolved"},
    "contained": {"investigating", "mitigated", "resolved"},
    "mitigated": {"investigating", "resolved"},
    "resolved": {"closed", "investigating"},
    "closed": set(),
}


async def lock_tenant_incidents(conn: AsyncConnection) -> None:
    """Serializes incident creation and correlation per tenant (no duplicate incidents when
    several workers see related alerts at the same moment)."""
    await conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended('incidents:' || app_tenant()::text, 0))"))


async def next_number(conn: AsyncConnection) -> str:
    n = (
        await conn.execute(
            text(
                "INSERT INTO incident_counters (tenant_id, next) VALUES (app_tenant(), 2) "
                "ON CONFLICT (tenant_id) DO UPDATE SET next = incident_counters.next + 1 RETURNING next - 1"
            )
        )
    ).scalar_one()
    return f"INC-{int(n):06d}"


async def timeline(
    conn: AsyncConnection,
    incident_id: UUID | str,
    kind: str,
    body: dict[str, Any],
    *,
    actor_type: str = "system",
    actor_id: UUID | None = None,
    at: datetime | None = None,
) -> None:
    await conn.execute(
        text(
            "INSERT INTO timeline_entries (tenant_id, incident_id, kind, actor_type, actor_id, body, at) "
            "VALUES (app_tenant(), :i, :k, :t, :a, CAST(:b AS jsonb), coalesce(CAST(:at AS timestamptz), now()))"
        ),
        {"i": incident_id, "k": kind, "t": actor_type, "a": actor_id, "b": json.dumps(body, default=str), "at": at},
    )


async def create_incident(
    conn: AsyncConnection,
    *,
    domain: str,
    title: str,
    severity: str,
    priority: str,
    detected_at: datetime,
    services: list[UUID] | list[str],
    created_by_type: str,
    created_by: UUID | None = None,
    summary: str = "",
    correlation_key: str | None = None,
    sandbox: bool = True,
) -> tuple[UUID, str]:
    number = await next_number(conn)
    incident_id = (
        await conn.execute(
            text(
                "INSERT INTO incidents (tenant_id, number, domain, title, summary, severity, priority, detected_at, "
                "impacted_service_ids, created_by_type, created_by, correlation_key, sandbox) "
                "VALUES (app_tenant(), :n, :d, :t, :s, :sev, :p, :at, CAST(:svc AS uuid[]), :cbt, :cb, :ck, :sb) "
                "RETURNING id"
            ),
            {
                "n": number,
                "d": domain,
                "t": title[:300],
                "s": summary,
                "sev": severity,
                "p": priority,
                "at": detected_at,
                "svc": [str(s) for s in services],
                "cbt": created_by_type,
                "cb": created_by,
                "ck": correlation_key,
                "sb": sandbox,
            },
        )
    ).scalar_one()
    await timeline(
        conn,
        incident_id,
        "created",
        {"number": number, "domain": domain, "severity": severity, "priority": priority, "by": created_by_type},
        actor_type="user" if created_by_type == "user" else "system",
        actor_id=created_by,
    )
    return incident_id, number


async def link_alert(
    conn: AsyncConnection,
    incident_id: UUID | str,
    alert_id: UUID | str,
    *,
    added_by: str,
    rule_key: str | None,
    reason: str,
    actor_id: UUID | None = None,
) -> bool:
    """Links an alert (at most one incident per alert). False if it was already linked."""
    row = (
        await conn.execute(
            text(
                "INSERT INTO incident_alerts (alert_id, tenant_id, incident_id, added_by, rule_key, reason) "
                "VALUES (:a, app_tenant(), :i, :by, :r, :why) ON CONFLICT (alert_id) DO NOTHING RETURNING 1"
            ),
            {"a": alert_id, "i": incident_id, "by": added_by, "r": rule_key, "why": reason[:500]},
        )
    ).scalar_one_or_none()
    if row is None:
        return False
    alert = (
        await conn.execute(
            text("SELECT title, severity, domain, connector_id FROM alerts WHERE id = :a"), {"a": alert_id}
        )
    ).one()
    await timeline(
        conn,
        incident_id,
        "alert_added",
        {
            "alert_id": str(alert_id),
            "title": alert.title,
            "severity": alert.severity,
            "domain": alert.domain,
            "connector": alert.connector_id,
            "rule": rule_key,
            "reason": reason,
        },
        actor_type="user" if added_by == "user" else "system",
        actor_id=actor_id,
    )
    return True


async def change_status(
    conn: AsyncConnection,
    incident_id: UUID | str,
    current: str,
    to: str,
    *,
    actor_type: str,
    actor_id: UUID | None,
    reason: str | None,
    at: datetime | None = None,
    version: int | None = None,
) -> bool:
    """Applies a status change with its timestamps. False on a stale ``version``."""
    params: dict[str, Any] = {"id": incident_id, "to": to, "at": at, "v": version}
    result = await conn.execute(
        text(
            "UPDATE incidents SET status = :to, "
            "acknowledged_at = CASE WHEN acknowledged_at IS NULL AND :to <> 'open' "
            "                       THEN coalesce(CAST(:at AS timestamptz), now()) ELSE acknowledged_at END, "
            "resolved_at = CASE WHEN :to = 'resolved' THEN coalesce(CAST(:at AS timestamptz), now()) "
            "                   WHEN :to = 'investigating' THEN NULL ELSE resolved_at END, "
            "closed_at = CASE WHEN :to = 'closed' THEN coalesce(CAST(:at AS timestamptz), now()) ELSE closed_at END, "
            "updated_at = now(), version = version + 1 "
            "WHERE id = :id AND (CAST(:v AS integer) IS NULL OR version = :v)"
        ),
        params,
    )
    if result.rowcount == 0:
        return False
    await timeline(
        conn,
        incident_id,
        "state_change",
        {"from": current, "to": to, "reason": reason},
        actor_type=actor_type,
        actor_id=actor_id,
        at=at,
    )
    return True
