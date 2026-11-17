"""Analytics projector (P6): Postgres state -> ClickHouse facts and the OpenSearch entity index.

Postgres stays authoritative. The projector runs in the ingest worker as ``nocsoc_worker``:
it learns which tenants exist from ``projection_tenants()`` and then reads each tenant only
inside that tenant's RLS context, so it cannot mix tenants even by mistake.

Change capture uses ``updated_at`` (maintained by triggers, migration 0006) with a per-tenant
watermark per stream. Each pass re-reads a short overlap window, and a periodic resync re-reads
the last day, so rows committed late by long transactions are still picked up. Sinks are
idempotent (ReplacingMergeTree keyed by id and version; OpenSearch documents keyed by id), so
re-projecting is harmless. Each sink (facts, search) keeps its own watermark, which only moves
after that sink accepted the batch, so one store being down never stalls or rewinds the other.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import text

from app.db.engines import AppDatabase
from app.incidents.sla import evaluate, merged_targets
from app.searchstore import SearchStore, entity_document

logger = logging.getLogger("app.projector")

BATCH = 1000
OVERLAP = timedelta(seconds=10)
RESYNC_EVERY_SECONDS = 900
RESYNC_WINDOW = timedelta(days=1)
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

ALERT_FACT_COLUMNS = [
    "tenant_id",
    "alert_id",
    "domain",
    "severity",
    "status",
    "connector",
    "title",
    "asset",
    "incident_id",
    "first_seen",
    "last_seen",
    "occurrence_count",
    "updated_at",
    "version",
]
INCIDENT_FACT_COLUMNS = [
    "tenant_id",
    "incident_id",
    "number",
    "title",
    "domain",
    "severity",
    "priority",
    "status",
    "created_by_type",
    "detected_at",
    "acknowledged_at",
    "resolved_at",
    "ack_due_at",
    "resolve_due_at",
    "merged",
    "updated_at",
    "version",
]
ACTION_FACT_COLUMNS = [
    "tenant_id",
    "request_id",
    "incident_id",
    "action_key",
    "tier",
    "decision",
    "status",
    "execution_mode",
    "requested_by_type",
    "created_at",
    "executed_at",
    "updated_at",
    "version",
]

QUERIES = {
    "alerts": (
        "SELECT a.id, a.domain, a.severity, a.status, a.connector_id, a.title, a.description, a.source_alert_id, "
        "coalesce(s.name, '') AS asset, ia.incident_id, a.first_seen, a.last_seen, a.occurrence_count, a.updated_at "
        "FROM alerts a LEFT JOIN assets s ON s.id = a.asset_id LEFT JOIN incident_alerts ia ON ia.alert_id = a.id "
        "WHERE a.updated_at > :since ORDER BY a.updated_at LIMIT :n"
    ),
    "incidents": (
        "SELECT id, number, title, summary, domain, severity, priority, status, created_by_type, detected_at, "
        "acknowledged_at, resolved_at, merged_into_id IS NOT NULL AS merged, updated_at FROM incidents "
        "WHERE updated_at > :since ORDER BY updated_at LIMIT :n"
    ),
    "actions": (
        "SELECT id, incident_id, action_key, tier, coalesce(policy_decision->>'decision', '') AS decision, status, "
        "execution_mode, requested_by_type, created_at, executed_at, updated_at FROM action_requests "
        "WHERE updated_at > :since ORDER BY updated_at LIMIT :n"
    ),
    "assets": (
        "SELECT id, name, type, environment, criticality, last_seen, updated_at FROM assets "
        "WHERE updated_at > :since ORDER BY updated_at LIMIT :n"
    ),
}
FACT_STREAMS = ("alerts", "incidents", "actions")
SEARCH_STREAMS = ("alerts", "incidents", "assets")


def _version(ts: datetime) -> int:
    return int(ts.timestamp() * 1_000_000)


@dataclass
class Batch:
    facts: list[list[Any]]
    docs: list[tuple[str, str, dict[str, Any]]]
    newest: datetime | None
    size: int


class Projector:
    def __init__(
        self,
        db: AppDatabase,
        analytics: Any | None,
        search: SearchStore | None,
        database: str = "nocsoc",
    ) -> None:
        self.db = db
        self.analytics = analytics
        self.search = search
        self.database = database
        self.stats = {"projected": 0, "failed": 0}

    # ------------------------------------------------------------------ public
    async def run_once(self, *, resync: bool = False) -> int:
        """One pass over every tenant and stream. Returns rows projected."""
        if self.analytics is None and self.search is None:
            return 0
        async with self.db.engine.connect() as conn:
            tenants = [r[0] for r in await conn.execute(text("SELECT projection_tenants()"))]
        total = 0
        for tenant in tenants:
            for stream, sink in self._targets():
                try:
                    total += await self._project(tenant, stream, sink, resync=resync)
                except Exception as exc:  # one tenant or sink must not stop the others
                    self.stats["failed"] += 1
                    logger.warning("projection failed (stream=%s sink=%s): %s", stream, sink, type(exc).__name__)
        self.stats["projected"] += total
        return total

    def _targets(self) -> list[tuple[str, str]]:
        """(stream, sink) pairs. Each sink keeps its own watermark, so an unavailable search
        store never holds back the analytics facts, and vice versa."""
        out: list[tuple[str, str]] = []
        if self.analytics is not None:
            out += [(s, "facts") for s in FACT_STREAMS]
        if self.search is not None:
            out += [(s, "search") for s in SEARCH_STREAMS]
        return out

    async def loop(self, stopping: asyncio.Event, interval: float) -> None:
        next_resync = time.monotonic() + RESYNC_EVERY_SECONDS
        while not stopping.is_set():
            resync = time.monotonic() >= next_resync
            if resync:
                next_resync = time.monotonic() + RESYNC_EVERY_SECONDS
            try:
                await self.run_once(resync=resync)
            except Exception as exc:
                logger.warning("projector pass failed: %s", type(exc).__name__)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stopping.wait(), timeout=interval)

    # ------------------------------------------------------------------ one stream of one tenant
    async def _project(self, tenant: UUID, stream: str, sink: str, *, resync: bool) -> int:
        projected = 0
        async with self.db.tenant(tenant) as conn:
            mark = (
                await conn.execute(
                    text("SELECT watermark FROM projection_state WHERE stream = :s AND sink = :k"),
                    {"s": stream, "k": sink},
                )
            ).scalar_one_or_none()
        since = (mark - OVERLAP) if mark else EPOCH
        if resync:
            since = min(since, datetime.now(UTC) - RESYNC_WINDOW)
        while True:
            batch = await self._read(tenant, stream, since)
            if not batch.size:
                break
            await self._write(stream, sink, batch)
            projected += batch.size
            newest = batch.newest
            if newest is None:
                break
            if not resync and (mark is None or newest > mark):
                async with self.db.tenant(tenant) as conn:
                    await conn.execute(
                        text(
                            "INSERT INTO projection_state (tenant_id, stream, sink, watermark) VALUES (app_tenant(), "
                            ":s, :k, :w) ON CONFLICT (tenant_id, stream, sink) DO UPDATE SET watermark = GREATEST("
                            "projection_state.watermark, EXCLUDED.watermark), updated_at = now()"
                        ),
                        {"s": stream, "k": sink, "w": newest},
                    )
                mark = newest
            # Continue only on a full batch that moved forward (no endless loop on equal timestamps).
            if batch.size < BATCH or newest <= since:
                break
            since = newest
        return projected

    async def _read(self, tenant: UUID, stream: str, since: datetime) -> Batch:
        async with self.db.tenant(tenant) as conn:
            rows = list(await conn.execute(text(QUERIES[stream]), {"since": since, "n": BATCH}))
            targets = None
            if stream == "incidents" and rows:
                custom = (await conn.execute(text("SELECT targets FROM sla_policies"))).scalar_one_or_none()
                targets = merged_targets(custom)
        facts: list[list[Any]] = []
        docs: list[tuple[str, str, dict[str, Any]]] = []
        for r in rows:
            if stream == "alerts":
                facts.append(
                    [
                        tenant,
                        r.id,
                        r.domain,
                        r.severity,
                        r.status,
                        r.connector_id,
                        r.title,
                        r.asset,
                        r.incident_id,
                        r.first_seen,
                        r.last_seen,
                        r.occurrence_count,
                        r.updated_at,
                        _version(r.updated_at),
                    ]
                )
                docs.append(
                    entity_document(
                        tenant,
                        "alert",
                        r.id,
                        title=r.title,
                        subtitle=f"{r.connector_id} · {r.status}",
                        text=f"{r.description or ''} {r.source_alert_id} {r.asset}"[:4000],
                        severity=r.severity,
                        status=r.status,
                        domain=r.domain,
                        at=r.last_seen,
                    )
                )
            elif stream == "incidents":
                sla = evaluate(r.priority, r.detected_at, r.acknowledged_at, r.resolved_at, r.detected_at, targets)
                facts.append(
                    [
                        tenant,
                        r.id,
                        r.number,
                        r.title,
                        r.domain,
                        r.severity,
                        r.priority,
                        r.status,
                        r.created_by_type,
                        r.detected_at,
                        r.acknowledged_at,
                        r.resolved_at,
                        sla.ack_due_at,
                        sla.resolve_due_at,
                        int(r.merged),
                        r.updated_at,
                        _version(r.updated_at),
                    ]
                )
                docs.append(
                    entity_document(
                        tenant,
                        "incident",
                        r.id,
                        number=r.number,
                        title=r.title,
                        subtitle=f"{r.domain} · {r.status}",
                        text=(r.summary or "")[:4000],
                        severity=r.severity,
                        status=r.status,
                        domain=r.domain,
                        at=r.detected_at,
                    )
                )
            elif stream == "actions":
                facts.append(
                    [
                        tenant,
                        r.id,
                        r.incident_id,
                        r.action_key,
                        r.tier,
                        r.decision,
                        r.status,
                        r.execution_mode,
                        r.requested_by_type,
                        r.created_at,
                        r.executed_at,
                        r.updated_at,
                        _version(r.updated_at),
                    ]
                )
            else:  # assets
                docs.append(
                    entity_document(
                        tenant,
                        "asset",
                        r.id,
                        title=r.name,
                        subtitle=f"{r.type} · {r.environment}",
                        text=f"{r.name} {r.type} criticality {r.criticality}",
                        at=r.last_seen,
                    )
                )
        newest = max((r.updated_at for r in rows), default=None)
        return Batch(facts=facts, docs=docs, newest=newest, size=len(rows))

    async def _write(self, stream: str, sink: str, batch: Batch) -> None:
        if sink == "facts":
            table, columns = {
                "alerts": ("alert_facts", ALERT_FACT_COLUMNS),
                "incidents": ("incident_facts", INCIDENT_FACT_COLUMNS),
                "actions": ("action_facts", ACTION_FACT_COLUMNS),
            }[stream]
            if self.analytics is not None and batch.facts:
                await self.analytics.insert(f"{self.database}.{table}", batch.facts, column_names=columns)
        elif self.search is not None and batch.docs:
            failed = await self.search.bulk(batch.docs)
            if failed:
                raise RuntimeError(f"{failed} search documents failed")
