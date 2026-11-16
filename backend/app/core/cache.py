"""Tenant-scoped Valkey cache and per-tenant request budgets.

Keys always start with ``t:{tenant_id}:`` (threat model T9), so one tenant's cached data can
never be served to another, and a tenant's cache can be dropped as a unit. Cached values are
derived, never authoritative: a Valkey outage degrades to a cache miss, not an error.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar
from uuid import UUID

from app.core.authz.principal import Principal
from app.errors import ProblemError
from app.services import Services

logger = logging.getLogger(__name__)
T = TypeVar("T")


def tenant_key(tenant_id: UUID | None, *parts: str) -> str:
    if tenant_id is None:
        raise ValueError("tenant-scoped key without a tenant")
    return ":".join(("t", str(tenant_id), *parts))


async def cached_json(services: Services, key: str, ttl_seconds: int, compute: Callable[[], Awaitable[Any]]) -> Any:
    try:
        hit = await services.valkey.get(key)
        if hit is not None:
            return json.loads(hit)
    except Exception:  # cache unavailable: compute directly
        logger.warning("cache read failed")
    value = await compute()
    try:
        await services.valkey.set(key, json.dumps(value, default=str), ex=ttl_seconds)
    except Exception:
        logger.warning("cache write failed")
    return value


async def invalidate(services: Services, *keys: str) -> None:
    try:
        if keys:
            await services.valkey.delete(*keys)
    except Exception:
        logger.warning("cache invalidation failed")


async def tenant_budget(services: Services, principal: Principal, name: str) -> None:
    """Fixed-window budget per tenant for expensive operations (429 when exceeded)."""
    key = tenant_key(principal.tenant_id, "budget", name)
    if await services.limiter.hit(key, 60) > services.settings.tenant_heavy_requests_per_minute:
        raise ProblemError(
            429, "rate_limited", "Too many requests", "This tenant is over its per-minute budget. Retry shortly."
        )
