"""Stream and analytics setup: ``python -m app.db.migrate_stream``.

Creates ClickHouse tables, users and row policies, and the Kafka topics (idempotent). Runs
as a one-shot container in the ``stream`` and ``analytics`` compose profiles.
"""

import asyncio
import logging

import clickhouse_connect
from aiokafka.admin import AIOKafkaAdminClient, NewPartitions, NewTopic

from app.analytics import schema, tls_options, users_and_policies
from app.config import Settings, get_settings
from app.streaming import ALERTS_UPSERTED, DEAD_LETTER, raw_topic

logger = logging.getLogger("app.db.migrate_stream")

HOUR_MS = 3_600_000


# P7 throughput (NFR-2): enough partitions for several ingest workers per connector.
RAW_PARTITIONS = 12


def topics(connector_ids: list[str]) -> list[NewTopic]:
    raw = [
        NewTopic(
            raw_topic(c),
            num_partitions=RAW_PARTITIONS,
            replication_factor=1,
            topic_configs={"retention.ms": str(24 * HOUR_MS)},
        )
        for c in connector_ids
    ]
    telemetry = [
        NewTopic(
            raw_topic(c, telemetry=True),
            num_partitions=RAW_PARTITIONS,
            replication_factor=1,
            topic_configs={"retention.ms": str(24 * HOUR_MS)},
        )
        for c in connector_ids
    ]
    return [
        *raw,
        *telemetry,
        NewTopic(
            ALERTS_UPSERTED, num_partitions=3, replication_factor=1, topic_configs={"retention.ms": str(72 * HOUR_MS)}
        ),
        NewTopic(
            DEAD_LETTER, num_partitions=1, replication_factor=1, topic_configs={"retention.ms": str(7 * 24 * HOUR_MS)}
        ),
    ]


async def setup_kafka(settings: Settings) -> None:
    from nocsoc_connectors import REGISTRY

    admin = AIOKafkaAdminClient(bootstrap_servers=settings.kafka_bootstrap)
    for attempt in range(30):
        try:
            await admin.start()
            break
        except Exception:  # broker still starting
            await asyncio.sleep(2)
            if attempt == 29:
                raise
    try:
        existing = set(await admin.list_topics())
        missing = [t for t in topics(sorted(REGISTRY)) if t.name not in existing]
        if missing:
            await admin.create_topics(missing)
        # Existing raw topics from before P7 have 3 partitions: grow them (partitions only ever grow).
        raw = [t.name for t in topics(sorted(REGISTRY)) if t.name.startswith("raw.") and t.name in existing]
        described = await admin.describe_topics(raw) if raw else []
        grow = {
            d["topic"]: NewPartitions(RAW_PARTITIONS)
            for d in described
            if len(d.get("partitions", [])) < RAW_PARTITIONS
        }
        if grow:
            await admin.create_partitions(grow)
        logger.info("kafka topics ready (%d created, %d grown)", len(missing), len(grow))
    finally:
        await admin.close()


def setup_clickhouse(settings: Settings) -> None:
    if not (
        settings.clickhouse_admin_password
        and settings.clickhouse_ingest_password
        and settings.clickhouse_reader_password
    ):
        raise SystemExit("missing ClickHouse secrets")
    for attempt in range(30):
        try:
            client = clickhouse_connect.get_client(
                host=settings.clickhouse_host,
                port=settings.clickhouse_port,
                username=settings.clickhouse_admin_user,
                password=settings.clickhouse_admin_password.get_secret_value(),
                **tls_options(settings),
            )
            break
        except Exception:
            import time

            time.sleep(2)
            if attempt == 29:
                raise
    db = settings.clickhouse_database
    for stmt in schema(db) + users_and_policies(
        db,
        settings.clickhouse_ingest_password.get_secret_value(),
        settings.clickhouse_reader_password.get_secret_value(),
    ):
        client.command(stmt)
    client.close()
    logger.info("clickhouse schema, users and row policies ready")


def main(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if settings.clickhouse_host:
        setup_clickhouse(settings)
    if settings.kafka_bootstrap:
        asyncio.run(setup_kafka(settings))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    main()
