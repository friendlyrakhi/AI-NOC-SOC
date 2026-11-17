"""ClickHouse telemetry and analytics store (docs/03 §3, threat model T8).

Tenant isolation: every table leads its ORDER BY with tenant_id, and the reader user is bound
by row policies on ``getSetting('SQL_tenant_id')``: a comma-separated list of tenant ids (one
tenant, or the delegated customers of an MSP aggregate view). A query without that setting
fails rather than returning other tenants' rows; an empty list matches nothing. The app sets it
per query via ``reader_query``, from the authenticated principal only.

Fact tables (P6) are ReplacingMergeTree projections of Postgres state written by the analytics
projector; Postgres stays authoritative. Read them with ``FINAL``.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

import clickhouse_connect
from clickhouse_connect.driver.asyncclient import AsyncClient

from app.config import Settings

TABLES = ("raw_events", "security_events", "metrics", "events", "alert_facts", "incident_facts", "action_facts")


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
        f"""CREATE TABLE IF NOT EXISTS {db}.alert_facts (
            tenant_id UUID, alert_id UUID, domain LowCardinality(String), severity LowCardinality(String),
            status LowCardinality(String), connector LowCardinality(String), title String, asset String,
            incident_id Nullable(UUID), first_seen DateTime64(3, 'UTC'), last_seen DateTime64(3, 'UTC'),
            occurrence_count UInt32, updated_at DateTime64(6, 'UTC'), version UInt64
        ) ENGINE = ReplacingMergeTree(version) ORDER BY (tenant_id, alert_id)
          TTL toDateTime(first_seen) + INTERVAL 400 DAY""",
        f"""CREATE TABLE IF NOT EXISTS {db}.incident_facts (
            tenant_id UUID, incident_id UUID, number String, title String, domain LowCardinality(String),
            severity LowCardinality(String), priority LowCardinality(String), status LowCardinality(String),
            created_by_type LowCardinality(String), detected_at DateTime64(3, 'UTC'),
            acknowledged_at Nullable(DateTime64(3, 'UTC')), resolved_at Nullable(DateTime64(3, 'UTC')),
            ack_due_at DateTime64(3, 'UTC'), resolve_due_at DateTime64(3, 'UTC'), merged UInt8,
            updated_at DateTime64(6, 'UTC'), version UInt64
        ) ENGINE = ReplacingMergeTree(version) ORDER BY (tenant_id, incident_id)
          TTL toDateTime(detected_at) + INTERVAL 400 DAY""",
        f"""CREATE TABLE IF NOT EXISTS {db}.action_facts (
            tenant_id UUID, request_id UUID, incident_id Nullable(UUID), action_key LowCardinality(String),
            tier LowCardinality(String), decision LowCardinality(String), status LowCardinality(String),
            execution_mode LowCardinality(String), requested_by_type LowCardinality(String),
            created_at DateTime64(3, 'UTC'), executed_at Nullable(DateTime64(3, 'UTC')),
            updated_at DateTime64(6, 'UTC'), version UInt64
        ) ENGINE = ReplacingMergeTree(version) ORDER BY (tenant_id, request_id)
          TTL toDateTime(created_at) + INTERVAL 400 DAY""",
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
        # OR REPLACE: P2 created a single-tenant policy; P6 accepts a list (MSP aggregate views).
        stmts.append(
            f"CREATE ROW POLICY OR REPLACE tenant_isolation ON {db}.{table} FOR SELECT "
            f"USING has(splitByChar(',', toString(getSetting('SQL_tenant_id'))), toString(tenant_id)) "
            f"TO nocsoc_reader"
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
        **tls_options(settings),
    )


def tls_options(settings: Settings) -> dict[str, Any]:
    """HTTPS with certificate verification in the hardened profile."""
    if not settings.clickhouse_secure:
        return {}
    return {"secure": True, "verify": True, "ca_cert": settings.tls_ca_file}


async def ingest_client(settings: Settings) -> AsyncClient:
    pw = settings.clickhouse_ingest_password.get_secret_value() if settings.clickhouse_ingest_password else None
    return await _client(settings, "nocsoc_ingest", pw)


async def reader_client(settings: Settings) -> AsyncClient:
    pw = settings.clickhouse_reader_password.get_secret_value() if settings.clickhouse_reader_password else None
    return await _client(settings, "nocsoc_reader", pw)


def tenant_setting(tenants: uuid.UUID | Sequence[uuid.UUID] | None) -> str:
    """The row-policy setting for one tenant or a list. Only ever built from the principal."""
    if tenants is None:
        raise ValueError("analytics reads require a tenant")
    ids = [tenants] if isinstance(tenants, uuid.UUID) else list(tenants)
    if not ids:
        raise ValueError("analytics reads require a tenant")
    return ",".join(str(uuid.UUID(str(t))) for t in ids)


async def reader_query(
    client: AsyncClient,
    tenant_id: uuid.UUID | Sequence[uuid.UUID] | None,
    sql: str,
    parameters: dict[str, Any],
) -> list[dict[str, Any]]:
    """Every read carries the tenant setting the row policies require. No tenant, no query."""
    result = await client.query(sql, parameters=parameters, settings={"SQL_tenant_id": tenant_setting(tenant_id)})
    return [dict(zip(result.column_names, row, strict=True)) for row in result.result_rows]
