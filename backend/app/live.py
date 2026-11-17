"""Live updates over Server-Sent Events (docs/05 §1 "Live updates").

Producers (ingest worker, API) publish small notifications to a per-tenant Valkey channel
``t:{tenant_id}:live``. The SSE endpoint subscribes only to the caller's tenant channel, so a
subscriber can never receive another tenant's events. Events carry ids and types only; clients
re-fetch through the normal, permission-checked endpoints.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Any
from uuid import UUID

import redis.asyncio as redis
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.errors import ProblemError
from app.services import Services, get_services

logger = logging.getLogger(__name__)

router = APIRouter(tags=["live"])

HEARTBEAT_SECONDS = 15
LEASE_SECONDS = 60  # a stream's slot lapses this long after its last heartbeat (crash-safe)
MAX_STREAM_SECONDS = 30 * 60  # clients reconnect; bounds a stale connection's lifetime
EVENT_TYPES = frozenset({"alert.upserted", "incident.changed"})


def channel(tenant_id: UUID | str) -> str:
    return f"t:{tenant_id}:live"


async def publish(client: redis.Redis, tenant_id: UUID | str | None, event: dict[str, Any]) -> None:
    """Best effort: a live-update failure never fails the write that caused it."""
    if tenant_id is None or event.get("type") not in EVENT_TYPES:
        return
    try:
        await client.publish(channel(tenant_id), json.dumps(event, separators=(",", ":")))
    except Exception as exc:
        logger.warning("live publish failed: %s", type(exc).__name__)


def _lease_keys(tenant_id: UUID, user: UUID | None) -> list[str]:
    keys = [f"t:{tenant_id}:sse:tenant"]
    if user is not None:
        keys.append(f"t:{tenant_id}:sse:user:{user}")
    return keys


async def acquire(client: redis.Redis, keys: list[str], limits: list[int], stream_id: str) -> bool:
    """Takes a slot in every lease set unless one is full. Expired leases are pruned first."""
    now = time.time()
    async with client.pipeline(transaction=True) as pipe:
        for key in keys:
            pipe.zremrangebyscore(key, "-inf", now)
            pipe.zcard(key)
        counts = (await pipe.execute())[1::2]
    if any(int(c) >= limit for c, limit in zip(counts, limits, strict=True)):
        return False
    await renew(client, keys, stream_id)
    return True


async def renew(client: redis.Redis, keys: list[str], stream_id: str) -> None:
    async with client.pipeline(transaction=True) as pipe:
        for key in keys:
            pipe.zadd(key, {stream_id: time.time() + LEASE_SECONDS})
            pipe.expire(key, LEASE_SECONDS * 2)
        await pipe.execute()


async def release(client: redis.Redis, keys: list[str], stream_id: str) -> None:
    try:
        async with client.pipeline(transaction=True) as pipe:
            for key in keys:
                pipe.zrem(key, stream_id)
            await pipe.execute()
    except Exception:  # the lease lapses on its own
        logger.debug("stream lease release failed", exc_info=True)


async def _events(
    request: Request, client: redis.Redis, tenant_id: UUID, lease: tuple[list[str], str] | None = None
) -> AsyncIterator[bytes]:
    pubsub = client.pubsub(ignore_subscribe_messages=True)
    await pubsub.subscribe(channel(tenant_id))
    started = last_beat = time.monotonic()
    try:
        yield b"retry: 3000\n: connected\n\n"
        while time.monotonic() - started < MAX_STREAM_SECONDS:
            if await request.is_disconnected():
                break
            try:
                message = await pubsub.get_message(timeout=1.0)
            except (TimeoutError, redis.TimeoutError):
                message = None
            if message and message.get("type") == "message":
                try:
                    event = json.loads(message["data"])
                except ValueError:
                    continue
                if event.get("type") in EVENT_TYPES:
                    yield f"event: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n".encode()
            if time.monotonic() - last_beat >= HEARTBEAT_SECONDS:
                last_beat = time.monotonic()
                if lease is not None:
                    try:
                        await renew(client, *lease)
                    except Exception:
                        logger.debug("stream lease renew failed", exc_info=True)
                yield b": ping\n\n"
            else:
                await asyncio.sleep(0)
    finally:
        if lease is not None:
            await release(client, *lease)
        try:
            await pubsub.unsubscribe()
            await pubsub.aclose()  # type: ignore[no-untyped-call]
        except Exception:  # connection already gone
            logger.debug("pubsub close failed", exc_info=True)


@router.get("/stream", **requires("alert:read"))
async def stream(
    request: Request,
    services: Annotated[Services, Depends(get_services)],
    p: Annotated[Principal, Depends(get_principal)],
) -> StreamingResponse:
    """``text/event-stream`` of ``alert.upserted`` and ``incident.changed`` for the caller's tenant.

    Concurrent streams are capped per tenant and per user (429 ``stream.limit``), so one tenant
    cannot exhaust the API's connections (P3 residual). Slots are leases renewed by the heartbeat.
    """
    tenant = p.tenant_id
    if tenant is None:  # requires() guarantees a tenant; keeps the type checker honest
        raise ProblemError(409, "tenant.none_selected", "No tenant selected", "Select a tenant first.")
    keys = _lease_keys(tenant, p.user_id or p.api_key_id)
    limits = [services.settings.sse_streams_per_tenant, services.settings.sse_streams_per_user][: len(keys)]
    stream_id = uuid.uuid4().hex
    try:
        granted = await acquire(services.valkey, keys, limits, stream_id)
    except Exception as exc:  # Valkey down: the stream itself cannot work either; let it try
        logger.warning("stream lease check failed: %s", type(exc).__name__)
        granted = True
    if not granted:
        raise ProblemError(
            429,
            "stream.limit",
            "Too many live connections",
            "Close other tabs with live updates, or retry in a minute.",
        )
    return StreamingResponse(
        _events(request, services.valkey, tenant, (keys, stream_id)),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
