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
from collections.abc import AsyncIterator
from typing import Annotated, Any
from uuid import UUID

import redis.asyncio as redis
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.services import Services, get_services

logger = logging.getLogger(__name__)

router = APIRouter(tags=["live"])

HEARTBEAT_SECONDS = 15
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


async def _events(request: Request, client: redis.Redis, tenant_id: UUID) -> AsyncIterator[bytes]:
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
                yield b": ping\n\n"
            else:
                await asyncio.sleep(0)
    finally:
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
    """``text/event-stream`` of ``alert.upserted`` and ``incident.changed`` for the caller's tenant."""
    return StreamingResponse(
        _events(request, services.valkey, p.tenant_id),  # type: ignore[arg-type]
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
