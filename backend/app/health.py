"""Liveness and readiness probes (docs/05-api-specification.md §2.11).

Both are public, so responses carry no dependency details. Failures are logged instead.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel
from sqlalchemy import text

from app.core.authz.deps import platform_admin, public
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


async def check_event_bus(services: Services) -> None:
    publisher = await services.publisher()
    if publisher is None:
        raise LookupError("not_configured")
    await publisher.ping()


async def check_analytics(services: Services) -> None:
    client = await services.analytics_reader()
    if client is None:
        raise LookupError("not_configured")
    await client.ping()


OPTIONAL_CHECKS: dict[str, Check] = {"event_bus": check_event_bus, "analytics": check_analytics}


class DependencyStatus(BaseModel):
    name: str
    required: bool
    status: Literal["up", "down", "not_configured"]


@router.get("/dependencies", response_model=list[DependencyStatus], **platform_admin())
async def dependencies(services: Annotated[Services, Depends(get_services)]) -> list[DependencyStatus]:
    """Per-dependency status for operators. Optional dependencies (event bus, analytics) do not
    affect readiness: without them the API serves everything except ingestion and event search."""
    timeout = services.settings.readiness_timeout_seconds
    checks = {**{n: (c, True) for n, c in get_checks().items()}, **{n: (c, False) for n, c in OPTIONAL_CHECKS.items()}}
    results = await asyncio.gather(
        *(asyncio.wait_for(c(services), timeout) for c, _ in checks.values()), return_exceptions=True
    )
    out = []
    for (name, (_, required)), result in zip(checks.items(), results, strict=True):
        if isinstance(result, LookupError):
            state = "not_configured"
        elif isinstance(result, BaseException):
            state = "down"
            logger.warning("dependency %s down: %s", name, type(result).__name__)
        else:
            state = "up"
        out.append(DependencyStatus(name=name, required=required, status=state))  # type: ignore[arg-type]
    return out


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
