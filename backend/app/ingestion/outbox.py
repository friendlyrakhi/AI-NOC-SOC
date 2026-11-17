"""Telemetry outbox: at-least-once delivery of ClickHouse rows and OpenSearch event documents.

Before P7, telemetry was written after the Postgres commit on a best-effort basis, so an outage of
either store lost those rows (P2/P6 residual). Now the ingest transaction also inserts one outbox
row holding that message's telemetry and the sinks it still has to reach. After the commit the
ingestor delivers it immediately (the normal, low-latency path) and deletes the row. Whatever could not
be delivered stays in the outbox, and the relay in the ingest worker retries it per tenant and per
sink. One store being down never holds back the other.

Delivery is at-least-once:
- OpenSearch documents have deterministic ids, so a retry overwrites them.
- A ClickHouse insert that succeeded just before a crash may be inserted again. Telemetry tables are
  append-only facts for charts and hunting, so a rare duplicate is accepted (documented).

Rows older than ``telemetry_outbox_max_age_hours`` are dropped with a warning so a long outage
cannot grow the outbox without bound. The raw records stay replayable from the bus for 24 hours.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app import telemetry
from app.db.engines import AppDatabase

logger = logging.getLogger(__name__)

ANALYTICS = "analytics"
SEARCH = "search"
RETRY_AFTER_SECONDS = 10  # leave fresh rows to the immediate delivery path
BATCH = 200


# ---------------------------------------------------------------- typed JSON for telemetry rows
def _enc(v: Any) -> Any:
    if isinstance(v, datetime):
        return {"$dt": v.isoformat()}
    if isinstance(v, UUID):
        return {"$uuid": str(v)}
    if isinstance(v, list | tuple):
        return [_enc(x) for x in v]
    return v


def _dec(v: Any) -> Any:
    if isinstance(v, dict):
        if "$dt" in v:
            return datetime.fromisoformat(v["$dt"])
        if "$uuid" in v:
            return UUID(v["$uuid"])
        return v
    if isinstance(v, list):
        return [_dec(x) for x in v]
    return v


def encode(rows: dict[str, list[list[Any]]]) -> str:
    return json.dumps({table: [[_enc(c) for c in row] for row in data] for table, data in rows.items() if data})


def decode(payload: Any) -> dict[str, list[list[Any]]]:
    data = json.loads(payload) if isinstance(payload, str) else payload
    return {table: [[_dec(c) for c in row] for row in rows] for table, rows in data.items()}


# ---------------------------------------------------------------- delivery
class TelemetryWriter:
    """Writes telemetry rows to the configured sinks; reports which sinks failed."""

    def __init__(self, analytics: Any | None, database: str, columns: dict[str, list[str]], search: Any | None):
        self.analytics = analytics
        self.database = database
        self.columns = columns
        self.search = search

    @property
    def sinks(self) -> list[str]:
        return [s for s, client in ((ANALYTICS, self.analytics), (SEARCH, self.search)) if client is not None]

    async def deliver(self, rows: dict[str, list[list[Any]]], sinks: Sequence[str]) -> set[str]:
        failed: set[str] = set()
        if ANALYTICS in sinks and self.analytics is not None:
            for table, data in rows.items():
                if not data or table not in self.columns:
                    continue
                try:
                    await self.analytics.insert(f"{self.database}.{table}", data, column_names=self.columns[table])
                except Exception as exc:
                    logger.warning("telemetry insert failed (table=%s): %s", table, type(exc).__name__)
                    failed.add(ANALYTICS)
                    break
        events = rows.get("events") or []
        if SEARCH in sinks and self.search is not None and events:
            from app.searchstore import event_document

            try:
                rejected = await self.search.bulk([event_document(r, self.columns["events"]) for r in events])
                if rejected:  # per-document mapping errors: retrying cannot help, so do not block
                    logger.warning("search rejected %d event document(s)", rejected)
            except Exception as exc:
                logger.warning("search indexing failed: %s", type(exc).__name__)
                failed.add(SEARCH)
        return failed


async def add(conn: AsyncConnection, sinks: Sequence[str], rows: dict[str, list[list[Any]]]) -> int | None:
    """Inside the ingest transaction (tenant context set): records the telemetry to deliver."""
    if not sinks or not any(rows.values()):
        return None
    return int(
        (
            await conn.execute(
                text(
                    "INSERT INTO telemetry_outbox (tenant_id, sinks, rows) "
                    "VALUES (app_tenant(), :s, CAST(:r AS jsonb)) RETURNING id"
                ),
                {"s": list(sinks), "r": encode(rows)},
            )
        ).scalar_one()
    )


async def settle(conn: AsyncConnection, outbox_id: int, failed: set[str]) -> None:
    """After a delivery attempt: delete the row, or keep only the sinks that still need it."""
    if failed:
        await conn.execute(
            text("UPDATE telemetry_outbox SET sinks = :s, attempts = attempts + 1 WHERE id = :id"),
            {"s": sorted(failed), "id": outbox_id},
        )
    else:
        await conn.execute(text("DELETE FROM telemetry_outbox WHERE id = :id"), {"id": outbox_id})


class OutboxRelay:
    """Retries undelivered telemetry, per tenant (inside its RLS context) and per sink."""

    def __init__(self, db: AppDatabase, writer: TelemetryWriter, max_age_hours: int = 72) -> None:
        self.db = db
        self.writer = writer
        self.max_age_hours = max_age_hours

    async def run_once(
        self, tenants: Iterable[UUID] | None = None, *, retry_after: int = RETRY_AFTER_SECONDS, batch: int = BATCH
    ) -> dict[str, int]:
        """One pass. ``tenants``/``retry_after=0``: the ingest worker's flush after each poll batch
        (P7 tuning: one write per table and sink for the whole batch instead of one per message)."""
        stats = {"delivered": 0, "pending": 0, "expired": 0}
        explicit = tenants is not None
        if tenants is None:
            async with self.db.engine.begin() as conn:
                tenants = [r[0] for r in await conn.execute(text("SELECT projection_tenants()"))]
        for tenant in tenants:
            async with self.db.tenant(tenant) as conn:
                expired = (
                    await conn.execute(
                        text(
                            "DELETE FROM telemetry_outbox "
                            "WHERE created_at < now() - make_interval(hours => :h) RETURNING 1"
                        ),
                        {"h": self.max_age_hours},
                    )
                ).all()
                if expired:
                    stats["expired"] += len(expired)
                    logger.warning(
                        "dropped %d telemetry outbox row(s) older than %dh", len(expired), self.max_age_hours
                    )
                rows = (
                    await conn.execute(
                        text(
                            "SELECT id, sinks, rows FROM telemetry_outbox "
                            "WHERE created_at < now() - make_interval(secs => :retry) "
                            "ORDER BY id LIMIT :n FOR UPDATE SKIP LOCKED"
                        ),
                        {"retry": retry_after, "n": batch},
                    )
                ).all()
                if not rows:
                    continue
                # One write per sink for the whole batch; a sink that fails keeps every row pending.
                failed_by_sink: dict[str, bool] = {}
                for sink in {s for r in rows for s in r.sinks}:
                    merged: dict[str, list[list[Any]]] = {}
                    for r in rows:
                        if sink in r.sinks:
                            for table, data in decode(r.rows).items():
                                merged.setdefault(table, []).extend(data)
                    # A sink this worker is not configured for stays pending (until it returns or expires).
                    failed_by_sink[sink] = sink not in self.writer.sinks or sink in await self.writer.deliver(
                        merged, [sink]
                    )
                for r in rows:
                    still = {s for s in r.sinks if failed_by_sink.get(s, True)}
                    await settle(conn, r.id, still)
                    stats["pending" if still else "delivered"] += 1
        if not explicit:
            telemetry.OUTBOX_PENDING.set(stats["pending"])
        if stats["delivered"] or stats["pending"]:
            logger.info("telemetry outbox relay %s", stats)
        return stats
