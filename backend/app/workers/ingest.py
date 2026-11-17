"""Ingest worker: ``python -m app.workers.ingest``.

Consumes ``raw.*`` topics with manual commits (at-least-once). The idempotency ledger makes a
redelivery harmless, so offsets are committed only after a batch is fully processed.
Transient failures are retried; a message that keeps failing goes to the dead-letter table
instead of blocking its partition.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from aiokafka import AIOKafkaConsumer
from opentelemetry.trace import SpanKind
from sqlalchemy import text

from app import live, telemetry
from app.analytics import ingest_client
from app.config import Settings, get_settings
from app.db.engines import AppDatabase
from app.ingestion import outbox
from app.ingestion.outbox import OutboxRelay
from app.ingestion.pipeline import DeadLetterError, Ingestor, Outcome, Prepared
from app.logging_setup import configure_logging
from app.projector import Projector
from app.searchstore import SearchStore
from app.services import valkey_client
from app.streaming import ALERTS_UPSERTED, MAX_MESSAGE_BYTES, Publisher

logger = logging.getLogger("app.workers.ingest")

GROUP_ID = "nocsoc-ingest"
TOPIC_PATTERN = r"^raw\..*"
# Telemetry topics (P7 throughput): their own consumer group and loop, so batched telemetry never
# waits for correlation on the ordered topics.
TELEMETRY_GROUP_ID = "nocsoc-ingest-telemetry"
TELEMETRY_TOPIC_PATTERN = r"^rawt\..*"
MAX_ATTEMPTS = 3
# The idempotency ledger only has to outlive possible redelivery: raw topics keep 24 h.
LEDGER_RETENTION_DAYS = 7
LEDGER_PRUNE_SECONDS = 3600
# P7 tuning (NFR-2): the partitions of a poll batch are processed concurrently, each in order.
# Messages are keyed by tenant and connector instance, so one instance's records stay ordered,
# exactly as with several worker processes in the consumer group.
PARTITION_CONCURRENCY = 12  # = RAW_PARTITIONS


class Worker:
    def __init__(self, settings: Settings) -> None:
        if not settings.kafka_bootstrap:
            raise SystemExit("NOCSOC_KAFKA_BOOTSTRAP is required")
        if settings.worker_database_password is None:
            raise SystemExit("worker database password secret is required")
        self.settings = settings
        # Partitions are processed concurrently (PARTITION_CONCURRENCY), plus the projector and relay.
        self.db = AppDatabase(settings, url=settings.worker_database_url(), pool_size=PARTITION_CONCURRENCY + 4)
        self.analytics: Any = None
        self.search: SearchStore | None = None
        self.publisher = Publisher(settings.kafka_bootstrap)
        self.valkey = valkey_client(settings)
        self.consumer = self._consumer(settings, GROUP_ID)
        self.telemetry_consumer = self._consumer(settings, TELEMETRY_GROUP_ID)
        self.stopping = asyncio.Event()
        self._delivery: asyncio.Task[None] | None = None
        self.stats = {"stored": 0, "duplicate": 0, "dead_letter": 0, "failed": 0}

    async def start(self) -> None:
        if self.settings.clickhouse_host and self.settings.clickhouse_ingest_password:
            self.analytics = await ingest_client(self.settings)
        if self.settings.opensearch_url and self.settings.opensearch_indexer_password:
            self.search = SearchStore(
                self.settings.opensearch_url,
                "nocsoc_indexer",
                self.settings.opensearch_indexer_password.get_secret_value(),
                verify=self.settings.tls_ca_file or True,
            )
        self.ingestor = Ingestor(
            self.db,
            self.analytics,
            self.settings.clickhouse_database,
            quota=self.within_quota,
            search=self.search,
            deliver_immediately=False,  # flushed per poll batch (flush_telemetry)
        )
        self.touched: set[UUID] = set()
        # Fast-path batches committed but not yet delivered: (tenant, outbox id, rows), kept in memory.
        self.pending: list[tuple[UUID, int, dict[str, list[list[Any]]]]] = []
        self.projector = Projector(self.db, self.analytics, self.search, self.settings.clickhouse_database)
        self.relay = OutboxRelay(self.db, self.ingestor.writer, self.settings.telemetry_outbox_max_age_hours)
        await self.publisher.start()
        self.consumer.subscribe(pattern=TOPIC_PATTERN)
        await self.consumer.start()
        self.telemetry_consumer.subscribe(pattern=TELEMETRY_TOPIC_PATTERN)
        await self.telemetry_consumer.start()
        logger.info(
            "ingest worker started (analytics=%s, search=%s)", self.analytics is not None, self.search is not None
        )

    @staticmethod
    def _consumer(settings: Settings, group: str) -> AIOKafkaConsumer:
        return AIOKafkaConsumer(
            bootstrap_servers=settings.kafka_bootstrap,
            group_id=group,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
            max_poll_records=1000,
            fetch_max_bytes=8 * MAX_MESSAGE_BYTES,
            metadata_max_age_ms=30_000,  # pick up new raw topics quickly
        )

    async def consume(self, consumer: AIOKafkaConsumer, max_records: int) -> None:
        """Poll, store (durable in Postgres, outbox included), commit, then deliver the telemetry
        while the next batch is processed. One delivery in flight per loop."""
        delivery: asyncio.Task[None] | None = None
        try:
            while not self.stopping.is_set():
                batches = await consumer.getmany(timeout_ms=1000, max_records=max_records)
                await self.process_batches(batches)
                if batches:
                    await consumer.commit()
                    if delivery is not None:
                        await delivery
                    delivery = asyncio.create_task(self.flush_telemetry())
        finally:
            if delivery is not None:
                with contextlib.suppress(Exception):
                    await delivery

    async def _consume_once(self, consumer: AIOKafkaConsumer, max_records: int) -> None:
        """One poll of the ordered topics (same commit-then-deliver pipeline as ``consume``)."""
        batches = await consumer.getmany(timeout_ms=1000, max_records=max_records)
        await self.process_batches(batches)
        if batches:
            await consumer.commit()
            if self._delivery is not None:
                await self._delivery
            self._delivery = asyncio.create_task(self.flush_telemetry())

    async def stop(self) -> None:
        await self.telemetry_consumer.stop()
        await self.consumer.stop()
        await self.publisher.stop()
        if self.analytics is not None:
            await self.analytics.close()
        if self.search is not None:
            await self.search.close()
        await self.valkey.aclose()
        await self.db.dispose()
        logger.info("ingest worker stopped %s", self.stats)

    async def handle(
        self, value: bytes, headers: list[tuple[str, bytes]] | None = None, prepared: Prepared | None = None
    ) -> str:
        """One raw message, in a span that continues the producer's trace (Kafka headers)."""
        started = time.monotonic()
        with telemetry.tracer.start_as_current_span(
            "ingest.process", context=telemetry.context_from_headers(headers), kind=SpanKind.CONSUMER
        ) as span:
            result = await self._handle(value, prepared)
            span.set_attribute("nocsoc.ingest.result", result)
        telemetry.INGEST_MESSAGES.add(1, {"result": result})
        telemetry.INGEST_DURATION.record(time.monotonic() - started, {"result": result})
        return result

    async def process_batches(self, batches: dict[Any, list[Any]]) -> None:
        """One poll batch, in two phases.

        1. Prepare every message (parse, ownership, normalization), each partition in order.
        2. At the same time: telemetry-only messages (security events, metrics) are stored per tenant
           in one transaction each (``store_telemetry_batch``), while the remaining messages (alerts,
           assets, findings, tickets) go through the per-message path with correlation, each
           partition in order. Slow correlation no longer holds back telemetry (P7 throughput).
        Offsets are committed by the caller after both phases (at-least-once).
        """
        gate = asyncio.Semaphore(PARTITION_CONCURRENCY)
        fast: dict[UUID, list[tuple[Prepared, bytes]]] = {}
        ordered: list[list[tuple[Any, Prepared | None]]] = []

        async def prepare(messages: list[Any]) -> None:
            queue: list[tuple[Any, Prepared | None]] = []
            async with gate:
                for msg in messages:
                    if msg.value is None:
                        continue
                    try:
                        # Quota: per batch for telemetry, per message for the ordered path.
                        prepared = await self.ingestor.prepare(msg.value, check_quota=False)
                    except Exception:  # e.g. database hiccup: the per-message path retries
                        queue.append((msg, None))
                        continue
                    if isinstance(prepared, Outcome):  # dead-lettered while preparing
                        self.stats[prepared.result] += 1
                        telemetry.INGEST_MESSAGES.add(1, {"result": prepared.result})
                    elif Ingestor.is_telemetry(prepared.records):
                        fast.setdefault(prepared.owner, []).append((prepared, msg.value))
                    else:
                        queue.append((msg, prepared))
            if queue:
                ordered.append(queue)

        async def partition(queue: list[tuple[Any, Prepared | None]]) -> None:
            async with gate:
                for msg, prepared in queue:
                    headers = list(msg.headers or [])
                    if prepared is None:
                        await self.handle(msg.value, headers)
                    elif not await self.within_quota(prepared.owner):
                        await self._over_quota(prepared, msg.value)
                    else:
                        await self.handle(msg.value, headers, prepared)

        await asyncio.gather(*(prepare(m) for m in batches.values()))
        await asyncio.gather(
            *(partition(q) for q in ordered),
            *(self._store_telemetry(tenant, items) for tenant, items in fast.items()),
        )

    async def _over_quota(self, prepared: Prepared, value: bytes) -> None:
        dl = DeadLetterError("quota_exceeded", "tenant ingest quota exceeded for this minute")
        await self.ingestor.dead_letter(prepared.owner, prepared.env.instanceid, dl, value)
        self.stats["dead_letter"] += 1
        telemetry.INGEST_MESSAGES.add(1, {"result": "dead_letter"})

    async def quota_allowance(self, tenant: UUID, n: int) -> int:
        """How many of ``n`` messages fit this minute's quota (one Valkey round trip per batch)."""
        key = f"t:{tenant}:ingest:{int(time.time() // 60)}"
        try:
            async with self.valkey.pipeline(transaction=True) as pipe:
                pipe.incrby(key, n)
                pipe.expire(key, 120, nx=True)
                count, _ = await pipe.execute()
        except Exception as exc:
            logger.warning("ingest quota check failed open: %s", type(exc).__name__)
            return n
        before = int(count) - n
        return max(0, min(n, self.settings.tenant_ingest_records_per_minute - before))

    async def _store_telemetry(self, tenant: UUID, items: list[tuple[Prepared, bytes]]) -> None:
        allowed = await self.quota_allowance(tenant, len(items))
        for prepared, value in items[allowed:]:
            await self._over_quota(prepared, value)
        items = items[:allowed]
        if not items:
            return
        started = time.monotonic()
        try:
            with telemetry.tracer.start_as_current_span("ingest.telemetry_batch") as span:
                span.set_attribute("nocsoc.ingest.messages", len(items))
                outcomes, outbox_id, rows = await self.ingestor.store_telemetry_batch(tenant, [p for p, _ in items])
        except Exception as exc:  # fall back to one message at a time (with retries)
            logger.warning("telemetry batch failed, retrying per message: %s", type(exc).__name__)
            for prepared, value in items:
                await self.handle(value, None, prepared)
            return
        elapsed = (time.monotonic() - started) / max(1, len(items))
        now = datetime.now(UTC)
        for outcome in outcomes:
            self.stats[outcome.result] += 1
            telemetry.INGEST_MESSAGES.add(1, {"result": outcome.result})
            telemetry.INGEST_DURATION.record(elapsed, {"result": outcome.result})
            if outcome.result == "stored" and outcome.emitted_at is not None:
                emitted = outcome.emitted_at if outcome.emitted_at.tzinfo else outcome.emitted_at.replace(tzinfo=UTC)
                telemetry.INGEST_LATENCY.record(max(0.0, (now - emitted).total_seconds()))
        if outbox_id is not None:
            self.pending.append((tenant, outbox_id, rows))

    async def flush_telemetry(self) -> None:
        """Delivers the telemetry of every message stored since the last flush: one write per table
        and sink for the whole poll batch. Failures stay in the outbox for the relay."""
        pending, self.pending = self.pending, []
        writer = self.ingestor.writer
        for tenant, outbox_id, rows in pending:  # fast path: straight from memory
            try:
                failed = await writer.deliver(rows, writer.sinks)
                async with self.db.tenant(tenant) as conn:
                    await outbox.settle(conn, outbox_id, failed)
            except Exception as exc:  # the row stays in the outbox; the relay retries
                logger.warning("telemetry delivery failed: %s", type(exc).__name__)
        tenants, self.touched = self.touched, set()
        if not tenants or not writer.sinks:
            return
        try:
            await self.relay.run_once(tenants, retry_after=0, batch=1000)
        except Exception as exc:  # the background relay retries
            logger.warning("telemetry flush failed: %s", type(exc).__name__)

    async def _handle(self, value: bytes, prepared: Prepared | None = None) -> str:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                if prepared is not None:
                    outcome = await self.ingestor.store_prepared(prepared)
                else:
                    outcome = await self.ingestor.process(value)
                self.stats[outcome.result] += 1
                if outcome.result == "stored" and outcome.tenant is not None:
                    self.touched.add(outcome.tenant)
                if outcome.result == "stored" and outcome.emitted_at is not None:
                    emitted = outcome.emitted_at
                    if emitted.tzinfo is None:
                        emitted = emitted.replace(tzinfo=UTC)
                    telemetry.INGEST_LATENCY.record(max(0.0, (datetime.now(UTC) - emitted).total_seconds()))
                for alert_id in outcome.alerts:
                    await self.publisher.publish_json(ALERTS_UPSERTED, alert_id, {"alert_id": alert_id})
                await self.notify(outcome)
                return outcome.result
            except Exception as exc:
                logger.warning("processing failed (attempt %d/%d): %s", attempt, MAX_ATTEMPTS, type(exc).__name__)
                if attempt == MAX_ATTEMPTS:
                    self.stats["failed"] += 1
                    await self.ingestor.dead_letter(
                        None, None, DeadLetterError("processing_error", type(exc).__name__), value
                    )
                    return "failed"
                await asyncio.sleep(0.5 * attempt)
        return "failed"

    async def within_quota(self, tenant: UUID) -> bool:
        """Fixed one-minute window per tenant. Fails open if Valkey is unavailable: the quota
        protects fairness, and losing it briefly is better than stopping all ingestion."""
        key = f"t:{tenant}:ingest:{int(time.time() // 60)}"
        try:
            async with self.valkey.pipeline(transaction=True) as pipe:
                pipe.incr(key)
                pipe.expire(key, 120, nx=True)
                count, _ = await pipe.execute()
        except Exception as exc:
            logger.warning("ingest quota check failed open: %s", type(exc).__name__)
            return True
        return int(count) <= self.settings.tenant_ingest_records_per_minute

    async def notify(self, outcome: Outcome) -> None:
        """Live updates after commit (SSE). One event per alert/incident, capped per message."""
        if outcome.tenant is None:
            return
        for alert_id in outcome.alerts[:20]:
            await live.publish(self.valkey, outcome.tenant, {"type": "alert.upserted", "id": alert_id})
        for incident_id in outcome.incidents[:20]:
            await live.publish(self.valkey, outcome.tenant, {"type": "incident.changed", "id": incident_id})

    async def prune_ledger(self) -> int:
        async with self.db.engine.begin() as conn:
            removed = int(
                (await conn.execute(text("SELECT ingest_seen_cleanup(:d)"), {"d": LEDGER_RETENTION_DAYS})).scalar_one()
            )
        if removed:
            logger.info("pruned %d idempotency ledger entries", removed)
        return removed

    async def relay_loop(self) -> None:
        """Retries telemetry that could not be delivered right after its commit (at-least-once)."""
        while not self.stopping.is_set():
            try:
                await self.relay.run_once()
            except Exception as exc:  # a store outage must not stop the relay
                logger.warning("telemetry outbox relay failed: %s", type(exc).__name__)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.stopping.wait(), self.settings.telemetry_outbox_interval_seconds)

    async def run(self) -> None:
        await self.start()
        next_prune = 0.0
        projector = asyncio.create_task(
            self.projector.loop(self.stopping, self.settings.projector_interval_seconds), name="projector"
        )
        relay = asyncio.create_task(self.relay_loop(), name="outbox-relay")
        telemetry_loop = asyncio.create_task(self.consume(self.telemetry_consumer, 2000), name="telemetry")
        try:
            while not self.stopping.is_set():
                if time.monotonic() >= next_prune:
                    next_prune = time.monotonic() + LEDGER_PRUNE_SECONDS
                    try:
                        await self.prune_ledger()
                    except Exception as exc:  # housekeeping must never stop ingestion
                        logger.warning("ledger prune failed: %s", type(exc).__name__)
                await self._consume_once(self.consumer, 500)
                if telemetry_loop.done():  # surface a crash of the telemetry loop
                    telemetry_loop.result()
        finally:
            self.stopping.set()
            with contextlib.suppress(Exception):
                await telemetry_loop
            if self._delivery is not None:
                with contextlib.suppress(Exception):
                    await self._delivery
            with contextlib.suppress(Exception):
                await projector
            with contextlib.suppress(Exception):
                await relay
            await self.stop()


async def main(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    telemetry.setup("nocsoc-ingest-worker", settings)
    worker = Worker(settings)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # Windows dev shells
            loop.add_signal_handler(sig, worker.stopping.set)
    try:
        await worker.run()
    finally:
        telemetry.shutdown()


if __name__ == "__main__":
    configure_logging(settings=get_settings())
    asyncio.run(main())
