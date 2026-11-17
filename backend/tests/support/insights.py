"""P6 integration environment: OpenSearch (security plugin on) on top of the stream environment.

Starts once per session, only for tests that request ``insights``. The API is a fresh app with
search configured (reader user); the ingest worker and the projector run as in production (the
indexer user and the worker database role).
"""

from __future__ import annotations

import asyncio
import dataclasses
import secrets
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

from app.analytics import ingest_client
from app.config import Settings
from app.db.engines import AppDatabase
from app.db.migrate_search import run as migrate_search
from app.mail import MemoryMailer
from app.main import create_app
from app.projector import Projector
from app.searchstore import SearchStore
from support.integration import Api, Env, attach_gateway
from support.stream import StreamEnv, _drain

OPENSEARCH_IMAGE = "opensearchproject/opensearch:3.8.0"


def os_password() -> str:
    # OpenSearch requires upper, lower, digit and special characters; the randomness is the hex.
    return "Os-9" + secrets.token_hex(24)


@dataclass
class InsightsEnv:
    env: Env
    api: Api
    settings: Settings
    admin_password: str

    def drain(self, *, minimum: int = 1, idle_seconds: float = 3.0, timeout: float = 60.0) -> dict[str, int]:
        return asyncio.run(_drain(self.settings, minimum, idle_seconds, timeout))

    def project(self, *, resync: bool = False) -> int:
        """One projector pass (Postgres -> ClickHouse facts and OpenSearch entities), then refresh
        the indices so search sees the documents immediately."""
        return asyncio.run(self._project(resync))

    async def _project(self, resync: bool) -> int:
        db = AppDatabase(self.settings, url=self.settings.worker_database_url())
        ch = await ingest_client(self.settings)
        assert self.settings.opensearch_url and self.settings.opensearch_indexer_password
        os_ = SearchStore(
            self.settings.opensearch_url, "nocsoc_indexer", self.settings.opensearch_indexer_password.get_secret_value()
        )
        try:
            n = await Projector(db, ch, os_, self.settings.clickhouse_database).run_once(resync=resync)
        finally:
            await os_.close()
            await ch.close()
            await db.dispose()
        await self.refresh()
        return n

    async def refresh(self) -> None:
        assert self.settings.opensearch_url
        admin = SearchStore(self.settings.opensearch_url, "admin", self.admin_password)
        try:
            await admin.client.post("/t-*/_refresh")
        finally:
            await admin.close()

    def refresh_now(self) -> None:
        asyncio.run(self.refresh())


@pytest.fixture(scope="session")
def insights(stream: StreamEnv) -> Iterator[InsightsEnv]:
    admin = os_password()
    container = (
        DockerContainer(OPENSEARCH_IMAGE)
        .with_env("discovery.type", "single-node")
        .with_env("OPENSEARCH_JAVA_OPTS", "-Xms512m -Xmx512m")
        .with_env("plugins.security.ssl.http.enabled", "false")
        .with_env("DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI", "true")
        .with_env("OPENSEARCH_INITIAL_ADMIN_PASSWORD", admin)
        .with_exposed_ports(9200)
        .waiting_for(LogMessageWaitStrategy("started"))
    )
    with container as os_:
        url = f"http://{os_.get_container_host_ip()}:{os_.get_exposed_port(9200)}"
        settings = stream.settings.model_copy(
            update={
                "opensearch_url": url,
                "opensearch_admin_password": SecretStr(admin),
                "opensearch_reader_password": SecretStr(os_password()),
                "opensearch_indexer_password": SecretStr(os_password()),
            }
        )
        asyncio.run(migrate_search(settings))
        env = dataclasses.replace(stream.env, settings=settings)
        app = create_app(settings, mailer=MemoryMailer())
        with TestClient(app, base_url="http://api.example") as client:
            attach_gateway(app, settings)
            yield InsightsEnv(env=env, api=Api(env, client), settings=settings, admin_password=admin)
