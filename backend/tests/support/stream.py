"""Stream-enabled integration environment: Redpanda + ClickHouse containers on top of ``env``.

Started once per session, only by tests that request ``stream`` (ingestion, webhooks, telemetry).
"""

from __future__ import annotations

import asyncio
import dataclasses
import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from testcontainers.community.clickhouse import ClickHouseContainer
from testcontainers.community.kafka import RedpandaContainer

from app.config import Settings
from app.db.migrate_stream import main as migrate_stream
from app.mail import MemoryMailer
from app.main import create_app
from app.workers.ingest import Worker
from support.integration import Api, Env, attach_gateway

REDPANDA_IMAGE = "redpandadata/redpanda:v25.2.9"
CLICKHOUSE_IMAGE = "clickhouse/clickhouse-server:25.8"


@dataclass
class StreamEnv:
    env: Env
    api: Api
    settings: Settings

    def drain(self, *, minimum: int = 1, idle_seconds: float = 3.0, timeout: float = 60.0) -> dict[str, int]:
        """Run the real ingest worker until at least ``minimum`` messages were handled and the
        bus has been idle for ``idle_seconds``. Returns the worker's counters."""
        return asyncio.run(_drain(self.settings, minimum, idle_seconds, timeout))


async def _drain(settings: Settings, minimum: int, idle_seconds: float, max_seconds: float) -> dict[str, int]:
    worker = Worker(settings)
    await worker.start()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max_seconds
    last_activity = loop.time()
    try:
        while loop.time() < deadline:
            batches = await worker.consumer.getmany(timeout_ms=500, max_records=200)
            for _tp, messages in batches.items():
                for msg in messages:
                    if msg.value is not None:
                        await worker.handle(msg.value)
            if batches:
                await worker.consumer.commit()
                last_activity = loop.time()
            handled = sum(worker.stats.values())
            if handled >= minimum and loop.time() - last_activity >= idle_seconds:
                break
    finally:
        await worker.stop()
    return dict(worker.stats)


@pytest.fixture(scope="session")
def stream(env: Env) -> Iterator[StreamEnv]:
    ch_admin = secrets.token_hex(16)
    with (
        RedpandaContainer(REDPANDA_IMAGE) as rp,
        ClickHouseContainer(CLICKHOUSE_IMAGE, username="nocsoc_admin", password=ch_admin, dbname="default")
        .with_env("CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT", "1")
        .with_exposed_ports(8123) as ch,
    ):
        extra: dict[str, Any] = {
            "kafka_bootstrap": rp.get_bootstrap_server(),
            "clickhouse_host": ch.get_container_host_ip(),
            "clickhouse_port": int(ch.get_exposed_port(8123)),
            "clickhouse_admin_user": "nocsoc_admin",
            "clickhouse_admin_password": SecretStr(ch_admin),
            "clickhouse_ingest_password": SecretStr(secrets.token_hex(16)),
            "clickhouse_reader_password": SecretStr(secrets.token_hex(16)),
        }
        settings = env.settings.model_copy(update=extra)
        migrate_stream(settings)
        stream_env = dataclasses.replace(env, settings=settings)
        app = create_app(settings, mailer=MemoryMailer())
        with TestClient(app, base_url="http://api.example") as client:
            attach_gateway(app, settings)
            yield StreamEnv(env=stream_env, api=Api(stream_env, client), settings=settings)
