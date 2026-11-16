"""ClickHouse telemetry store (docs/03 §3, threat model T8).

Tenant isolation: every table leads its ORDER BY with tenant_id, and the reader user is bound
by row policies on ``getSetting('SQL_tenant_id')``. A query without that setting fails rather
than returning other tenants' rows. The app sets it per query via ``reader_query``.
"""

from __future__ import annotations

import uuid
from typing import Any

import clickhouse_connect
from clickhouse_connect.driver.asyncclient import AsyncClient

from app.config import Settings

TABLES = ("raw_events", "security_events", "metrics", "events")


def schema(db: str) -> list[str]:
    from app.events import EVENTS_TABLE

    return [
        f"CREATE DATABASE IF NOT EXISTS {db}",
        EVENTS_TABLE.format(db=db),
        f"""CREATE TABLE IF NOT EXISTS {db}.raw_events (
            tenant_id UUID, instance_id UUID, connector LowCardinality(String), stream LowCardinality(String),
            event_id String, source_id String, trigger LowCardinality(String), schema LowCardinality(String),
            observed_at DateTime64(3, 'UTC'), ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
            payload String CODEC(ZSTD(3))
        ) ENGINE = MergeTree ORDER BY (tenant_id, connector, observed_at, event_id)
          TTL toDateTime(observed_at) + INTERVAL 7 DAY""",
        f"""CREATE TABLE IF NOT EXISTS {db}.security_events (
            tenant_id UUID, instance_id UUID, connector LowCardinality(String), class_uid UInt16,
            activity String, severity LowCardinality(String), observed_at DateTime64(3, 'UTC'), message String,
            actor_user String, device_hostname String, src_ip String, dst_ip String,
            outcome LowCardinality(String), mitre Array(String)
        ) ENGINE = MergeTree ORDER BY (tenant_id, class_uid, observed_at)
          TTL toDateTime(observed_at) + INTERVAL 30 DAY""",
        f"""CREATE TABLE IF NOT EXISTS {db}.metrics (
            tenant_id UUID, instance_id UUID, connector LowCardinality(String), name LowCardinality(String),
            value Float64, unit LowCardinality(String), asset_kind LowCardinality(String), asset_value String,
            observed_at DateTime64(3, 'UTC')
        ) ENGINE = MergeTree ORDER BY (tenant_id, name, asset_value, observed_at)
          TTL toDateTime(observed_at) + INTERVAL 14 DAY""",
    ]


def users_and_policies(db: str, ingest_pw: str, reader_pw: str) -> list[str]:
    def q(s: str) -> str:
        return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"

    stmts = [
        f"CREATE USER IF NOT EXISTS nocsoc_ingest IDENTIFIED WITH sha256_password BY {q(ingest_pw)}",
        f"ALTER USER nocsoc_ingest IDENTIFIED WITH sha256_password BY {q(ingest_pw)}",
        f"CREATE USER IF NOT EXISTS nocsoc_reader IDENTIFIED WITH sha256_password BY {q(reader_pw)}",
        f"ALTER USER nocsoc_reader IDENTIFIED WITH sha256_password BY {q(reader_pw)}",
        f"GRANT INSERT ON {db}.* TO nocsoc_ingest",
        f"GRANT SELECT ON {db}.* TO nocsoc_reader",
    ]
    for table in TABLES:
        stmts.append(
            f"CREATE ROW POLICY IF NOT EXISTS tenant_isolation ON {db}.{table} FOR SELECT "
            f"USING tenant_id = toUUID(getSetting('SQL_tenant_id')) TO nocsoc_reader"
        )
    return stmts


async def _client(settings: Settings, user: str, password: str | None) -> AsyncClient:
    return await clickhouse_connect.get_async_client(
        host=settings.clickhouse_host,
        port=settings.clickhouse_port,
        username=user,
        password=password or "",
        database=settings.clickhouse_database,
        connect_timeout=5,
        send_receive_timeout=30,
    )


async def ingest_client(settings: Settings) -> AsyncClient:
    pw = settings.clickhouse_ingest_password.get_secret_value() if settings.clickhouse_ingest_password else None
    return await _client(settings, "nocsoc_ingest", pw)


async def reader_client(settings: Settings) -> AsyncClient:
    pw = settings.clickhouse_reader_password.get_secret_value() if settings.clickhouse_reader_password else None
    return await _client(settings, "nocsoc_reader", pw)


async def reader_query(
    client: AsyncClient, tenant_id: uuid.UUID | None, sql: str, parameters: dict[str, Any]
) -> list[dict[str, Any]]:
    """Every read carries the tenant setting the row policies require. No tenant, no query."""
    if tenant_id is None:
        raise ValueError("analytics reads require a tenant")
    result = await client.query(sql, parameters=parameters, settings={"SQL_tenant_id": str(tenant_id)})
    return [dict(zip(result.column_names, row, strict=True)) for row in result.result_rows]
