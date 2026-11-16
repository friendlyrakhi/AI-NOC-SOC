"""Liveness and readiness probes (docs/05-api-specification.md §2.11).

Both are public, so responses carry no dependency details. Failures are logged instead.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text

from app.core.authz.deps import public
from app.services import Services, get_services

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])

Check = Callable[[Services], Awaitable[None]]


async def check_postgres(services: Services) -> None:
    async with services.app_db.engine.connect() as conn:
        await conn.execute(text("SELECT 1"))


async def check_identity_db(services: Services) -> None:
    async with services.auth_db.engine.connect() as conn:
        await conn.execute(text("SELECT 1"))


async def check_valkey(services: Services) -> None:
    await services.valkey.ping()


def get_checks() -> dict[str, Check]:
    return {"postgres": check_postgres, "identity_db": check_identity_db, "valkey": check_valkey}


@router.get("/live", **public())
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready", **public())
async def ready(
    response: Response,
    services: Annotated[Services, Depends(get_services)],
    checks: Annotated[dict[str, Check], Depends(get_checks)],
) -> dict[str, str]:
    timeout = services.settings.readiness_timeout_seconds
    names = list(checks)
    results = await asyncio.gather(
        *(asyncio.wait_for(checks[n](services), timeout) for n in names),
        return_exceptions=True,
    )
    failed = False
    for name, result in zip(names, results, strict=True):
        if isinstance(result, BaseException):
            failed = True
            logger.warning("readiness check %s failed: %s", name, type(result).__name__)
    if failed:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready"}
    return {"status": "ready"}
