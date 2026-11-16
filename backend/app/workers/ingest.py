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
from typing import Any

from aiokafka import AIOKafkaConsumer
from sqlalchemy import text

from app.analytics import ingest_client
from app.config import Settings, get_settings
from app.db.engines import AppDatabase
from app.ingestion.pipeline import DeadLetterError, Ingestor
from app.logging_setup import configure_logging
from app.streaming import ALERTS_UPSERTED, MAX_MESSAGE_BYTES, Publisher

logger = logging.getLogger("app.workers.ingest")

GROUP_ID = "nocsoc-ingest"
TOPIC_PATTERN = r"^raw\..*"
MAX_ATTEMPTS = 3
# The idempotency ledger only has to outlive possible redelivery: raw topics keep 24 h.
LEDGER_RETENTION_DAYS = 7
LEDGER_PRUNE_SECONDS = 3600


class Worker:
    def __init__(self, settings: Settings) -> None:
        if not settings.kafka_bootstrap:
            raise SystemExit("NOCSOC_KAFKA_BOOTSTRAP is required")
        if settings.worker_database_password is None:
            raise SystemExit("worker database password secret is required")
        self.settings = settings
        self.db = AppDatabase(settings, url=settings.worker_database_url())
        self.analytics: Any = None
        self.publisher = Publisher(settings.kafka_bootstrap)
        self.consumer = AIOKafkaConsumer(
            bootstrap_servers=settings.kafka_bootstrap,
            group_id=GROUP_ID,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
            max_poll_records=200,
            fetch_max_bytes=8 * MAX_MESSAGE_BYTES,
            metadata_max_age_ms=30_000,  # pick up new raw topics quickly
        )
        self.stopping = asyncio.Event()
        self.stats = {"stored": 0, "duplicate": 0, "dead_letter": 0, "failed": 0}

    async def start(self) -> None:
        if self.settings.clickhouse_host and self.settings.clickhouse_ingest_password:
            self.analytics = await ingest_client(self.settings)
        self.ingestor = Ingestor(self.db, self.analytics, self.settings.clickhouse_database)
        await self.publisher.start()
        self.consumer.subscribe(pattern=TOPIC_PATTERN)
        await self.consumer.start()
        logger.info("ingest worker started (analytics=%s)", self.analytics is not None)

    async def stop(self) -> None:
        await self.consumer.stop()
        await self.publisher.stop()
        if self.analytics is not None:
            await self.analytics.close()
        await self.db.dispose()
        logger.info("ingest worker stopped %s", self.stats)

    async def handle(self, value: bytes) -> None:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                outcome = await self.ingestor.process(value)
                self.stats[outcome.result] += 1
                for alert_id in outcome.alerts:
                    await self.publisher.publish_json(ALERTS_UPSERTED, alert_id, {"alert_id": alert_id})
                return
            except Exception as exc:
                logger.warning("processing failed (attempt %d/%d): %s", attempt, MAX_ATTEMPTS, type(exc).__name__)
                if attempt == MAX_ATTEMPTS:
                    self.stats["failed"] += 1
                    await self.ingestor.dead_letter(
                        None, None, DeadLetterError("processing_error", type(exc).__name__), value
                    )
                    return
                await asyncio.sleep(0.5 * attempt)

    async def prune_ledger(self) -> int:
        async with self.db.engine.begin() as conn:
            removed = int(
                (await conn.execute(text("SELECT ingest_seen_cleanup(:d)"), {"d": LEDGER_RETENTION_DAYS})).scalar_one()
            )
        if removed:
            logger.info("pruned %d idempotency ledger entries", removed)
        return removed

    async def run(self) -> None:
        await self.start()
        next_prune = 0.0
        try:
            while not self.stopping.is_set():
                if time.monotonic() >= next_prune:
                    next_prune = time.monotonic() + LEDGER_PRUNE_SECONDS
                    try:
                        await self.prune_ledger()
                    except Exception as exc:  # housekeeping must never stop ingestion
                        logger.warning("ledger prune failed: %s", type(exc).__name__)
                batches = await self.consumer.getmany(timeout_ms=1000, max_records=200)
                for _tp, messages in batches.items():
                    for msg in messages:
                        if msg.value is not None:
                            await self.handle(msg.value)
                if batches:
                    await self.consumer.commit()
        finally:
            await self.stop()


async def main(settings: Settings | None = None) -> None:
    worker = Worker(settings or get_settings())
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # Windows dev shells
            loop.add_signal_handler(sig, worker.stopping.set)
    await worker.run()


if __name__ == "__main__":
    configure_logging(settings=get_settings())
    asyncio.run(main())
