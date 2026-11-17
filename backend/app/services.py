"""Process-wide services, created in the app lifespan and stored on ``app.state.services``."""

import asyncio
from dataclasses import dataclass, field
from typing import Any

import redis.asyncio as redis
from fastapi import Request

from app.config import Settings
from app.core.identity.authdb import AuthDatabase
from app.core.secrets import LocalEnvelopeProvider, SecretsProvider
from app.db.engines import AppDatabase
from app.mail import Mailer, SmtpMailer
from app.ratelimit import RateLimiter
from app.streaming import Publisher


@dataclass
class Services:
    settings: Settings
    app_db: AppDatabase
    auth_db: AuthDatabase
    valkey: redis.Redis
    limiter: RateLimiter
    secrets: SecretsProvider
    mailer: Mailer
    _publisher: Publisher | None = field(default=None, repr=False)
    _publisher_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    _reader: Any = field(default=None, repr=False)
    # httpx transport for the AI gateway client; tests inject an in-process gateway here.
    ai_transport: Any = field(default=None, repr=False)
    _temporal: Any = field(default=None, repr=False)
    _search: Any = field(default=None, repr=False)
    _temporal_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    async def temporal(self) -> Any:
        """Temporal client, connected on first use. None when automation is not configured."""
        if not self.settings.temporal_address:
            return None
        async with self._temporal_lock:
            if self._temporal is None:
                from temporalio.client import Client

                self._temporal = await Client.connect(
                    self.settings.temporal_address, namespace=self.settings.temporal_namespace
                )
        return self._temporal

    def search_reader(self) -> Any:
        """OpenSearch client as ``nocsoc_reader``. None when search is not configured."""
        if not self.settings.opensearch_url or self.settings.opensearch_reader_password is None:
            return None
        if self._search is None:
            from app.searchstore import SearchStore

            self._search = SearchStore(
                self.settings.opensearch_url,
                "nocsoc_reader",
                self.settings.opensearch_reader_password.get_secret_value(),
            )
        return self._search

    async def analytics_reader(self) -> Any:
        """ClickHouse client as ``nocsoc_reader`` (row policies). None when not configured."""
        if not self.settings.clickhouse_host or self.settings.clickhouse_reader_password is None:
            return None
        if self._reader is None:
            from app.analytics import reader_client

            self._reader = await reader_client(self.settings)
        return self._reader

    async def publisher(self) -> Publisher | None:
        """Kafka producer, started on first use. None when streaming is not configured."""
        if not self.settings.kafka_bootstrap:
            return None
        async with self._publisher_lock:
            if self._publisher is None:
                pub = Publisher(self.settings.kafka_bootstrap)
                await pub.start()
                self._publisher = pub
        return self._publisher

    async def close(self) -> None:
        if self._publisher is not None:
            await self._publisher.stop()
        if self._reader is not None:
            await self._reader.close()
        if self._search is not None:
            await self._search.close()
        await self.app_db.dispose()
        await self.auth_db.dispose()
        await self.valkey.aclose()


def build_services(settings: Settings, mailer: Mailer | None = None) -> Services:
    if settings.master_key is None:
        raise RuntimeError("master key secret (nocsoc_master_key) is required")
    valkey = redis.Redis(
        host=settings.valkey_host,
        port=settings.valkey_port,
        password=settings.valkey_password.get_secret_value() if settings.valkey_password else None,
        socket_timeout=2,
    )
    return Services(
        settings=settings,
        app_db=AppDatabase(settings),
        auth_db=AuthDatabase(settings),
        valkey=valkey,
        limiter=RateLimiter(valkey),
        secrets=LocalEnvelopeProvider(settings.master_key.get_secret_value()),
        mailer=mailer or SmtpMailer(settings),
    )


def get_services(request: Request) -> Services:
    services: Services = request.app.state.services
    return services
