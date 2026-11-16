"""Process-wide services, created in the app lifespan and stored on ``app.state.services``."""

from dataclasses import dataclass

import redis.asyncio as redis
from fastapi import Request

from app.config import Settings
from app.core.identity.authdb import AuthDatabase
from app.core.secrets import LocalEnvelopeProvider, SecretsProvider
from app.db.engines import AppDatabase
from app.mail import Mailer, SmtpMailer
from app.ratelimit import RateLimiter


@dataclass
class Services:
    settings: Settings
    app_db: AppDatabase
    auth_db: AuthDatabase
    valkey: redis.Redis
    limiter: RateLimiter
    secrets: SecretsProvider
    mailer: Mailer

    async def close(self) -> None:
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
