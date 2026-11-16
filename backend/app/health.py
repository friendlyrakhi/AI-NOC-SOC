"""Liveness and readiness probes (docs/05-api-specification.md §2.11).

Both are public, so responses carry no dependency details. Failures are logged instead.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Annotated

import psycopg
import redis.asyncio as redis
from fastapi import APIRouter, Depends, Response, status

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])

Check = Callable[[Settings], Awaitable[None]]


async def check_postgres(settings: Settings) -> None:
    password = settings.database_password.get_secret_value() if settings.database_password else None
    conn = await psycopg.AsyncConnection.connect(
        host=settings.database_host,
        port=settings.database_port,
        dbname=settings.database_name,
        user=settings.database_user,
        password=password,
        connect_timeout=max(1, int(settings.readiness_timeout_seconds)),
    )
    async with conn:
        await conn.execute("SELECT 1")


async def check_valkey(settings: Settings) -> None:
    password = settings.valkey_password.get_secret_value() if settings.valkey_password else None
    client = redis.Redis(
        host=settings.valkey_host,
        port=settings.valkey_port,
        password=password,
        socket_timeout=settings.readiness_timeout_seconds,
    )
    try:
        await client.ping()
    finally:
        await client.aclose()


def get_checks() -> dict[str, Check]:
    return {"postgres": check_postgres, "valkey": check_valkey}


@router.get("/live")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def ready(
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
    checks: Annotated[dict[str, Check], Depends(get_checks)],
) -> dict[str, str]:
    names = list(checks)
    results = await asyncio.gather(
        *(
            asyncio.wait_for(checks[n](settings), settings.readiness_timeout_seconds + 1)
            for n in names
        ),
        return_exceptions=True,
    )
    failed = [n for n, r in zip(names, results, strict=True) if isinstance(r, BaseException)]
    for name, result in zip(names, results, strict=True):
        if isinstance(result, BaseException):
            logger.warning("readiness check %s failed: %s", name, type(result).__name__)
    if failed:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready"}
    return {"status": "ready"}
