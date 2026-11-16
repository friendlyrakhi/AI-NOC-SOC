"""Polling scheduler: work list -> due streams -> fetch -> publish -> report.

The runner holds no tenant data between runs except the connector objects themselves (so a
sandbox simulator keeps its state). Checkpoints live in the platform database and are only
advanced past records that were published successfully.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from connector_runner.api import PlatformApi
from connector_runner.bus import Bus, envelope, publish
from connector_runner.health import InstanceHealth, TokenBucket, error_class, safe_detail
from nocsoc_connector_sdk import Checkpoint, Connector, ConnectorContext, SchemaDriftError
from nocsoc_connectors import REGISTRY

logger = logging.getLogger("connector_runner")


class BusError(Exception):
    """Publishing failed. Not the source's fault, so it does not change connector health."""


def _parse(ts: str | None) -> datetime | None:
    return datetime.fromisoformat(ts) if ts else None


@dataclass
class _Cached:
    fingerprint: str
    connector: Connector


class Scheduler:
    def __init__(self, api: PlatformApi, bus: Bus, *, max_pages: int = 10, concurrency: int = 8) -> None:
        self.api = api
        self.bus = bus
        self.max_pages = max_pages
        self.sem = asyncio.Semaphore(concurrency)
        # Breakers per (instance, stream); the instance reports the worst of its streams.
        self.health: dict[str, dict[str, InstanceHealth]] = {}
        self.buckets: dict[str, TokenBucket] = {}
        self._connectors: dict[str, _Cached] = {}
        self._inflight: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------ connector cache
    @staticmethod
    def _fingerprint(item: dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps([item["definition_id"], item["config"]], sort_keys=True).encode()).hexdigest()

    async def connector(self, item: dict[str, Any]) -> Connector:
        iid = str(item["instance_id"])
        fp = self._fingerprint(item)
        cached = self._connectors.get(iid)
        if cached is None or cached.fingerprint != fp:
            cls = REGISTRY[item["definition_id"]]
            if item.get("mode") != "sandbox":  # guardrail #1: live mode does not exist in this build
                raise RuntimeError("refusing non-sandbox instance")
            secrets = await self.api.credentials(iid)
            ctx = ConnectorContext(tenant_id=str(item["tenant_id"]), instance_id=iid, mode="sandbox")
            cached = _Cached(fp, cls(ctx, item["config"], secrets))
            self._connectors[iid] = cached
            self.buckets[iid] = TokenBucket(cls.manifest.rate_limit_per_minute)
        return cached.connector

    # ------------------------------------------------------------------ scheduling
    @staticmethod
    def due_streams(item: dict[str, Any], now: datetime) -> list[tuple[str, str]]:
        """[(stream, trigger)] that should run now."""
        cls = REGISTRY.get(item["definition_id"])
        if cls is None:
            return []
        last_runs: dict[str, str] = item.get("last_runs") or {}
        requested = _parse(item.get("sync_requested_at"))
        out = []
        for spec in cls.manifest.streams:
            if spec.name not in cls.streams:
                continue
            last = _parse(last_runs.get(spec.name))
            if requested is not None and (last is None or requested > last):
                out.append((spec.name, "manual"))
            elif last is None or (now - last).total_seconds() >= spec.default_interval_seconds:
                out.append((spec.name, "schedule"))
        return out

    async def tick(self, now: datetime | None = None) -> int:
        now = now or datetime.now(UTC)
        work = await self.api.work()
        tasks = []
        live_ids = set()
        for item in work:
            iid = str(item["instance_id"])
            live_ids.add(iid)
            cached = self._connectors.get(iid)
            if cached is not None and cached.fingerprint != self._fingerprint(item):
                self.health.pop(iid, None)  # new configuration: close the breaker, start fresh
            for stream, trigger in self.due_streams(item, now):
                if (iid, stream) in self._inflight:
                    continue
                self._inflight.add((iid, stream))
                tasks.append(self._guarded(item, stream, trigger))
        for gone in set(self._connectors) - live_ids:  # deleted or disabled instances
            self._connectors.pop(gone, None)
            self.health.pop(gone, None)
            self.buckets.pop(gone, None)
        if tasks:
            await asyncio.gather(*tasks)
        return len(tasks)

    async def _guarded(self, item: dict[str, Any], stream: str, trigger: str) -> None:
        iid = str(item["instance_id"])
        try:
            async with self.sem:
                await self.run_stream(item, stream, trigger)
        except Exception:
            logger.exception("run failed unexpectedly (instance=%s stream=%s)", iid, stream)
        finally:
            self._inflight.discard((iid, stream))

    # ------------------------------------------------------------------ one run
    async def run_stream(self, item: dict[str, Any], stream: str, trigger: str) -> None:
        iid = str(item["instance_id"])
        health = self.health.setdefault(iid, {}).setdefault(stream, InstanceHealth())
        if not health.allows() and trigger != "manual":
            return
        started = datetime.now(UTC)
        cursor = (item.get("checkpoints") or {}).get(stream)
        checkpoint = Checkpoint(cursor=cursor) if cursor else None
        saved: Checkpoint | None = None
        published = 0
        drifted = 0
        rate_limited = False
        try:
            connector = await self.connector(item)
            bucket = self.buckets[iid]
            for _ in range(self.max_pages):
                if not bucket.take():
                    rate_limited = True
                    break
                result = await connector.fetch(stream, checkpoint)
                # Pre-check with the pure normalizer so drift shows in health. Drifted records are
                # still published: the worker dead-letters them, keeping the evidence.
                for rec in result.records:
                    try:
                        type(connector).normalize(stream, rec)
                    except (SchemaDriftError, ValidationError):
                        drifted += 1
                try:
                    for rec in result.records:
                        await publish(
                            self.bus, envelope(str(item["tenant_id"]), iid, item["definition_id"], stream, trigger, rec)
                        )
                except Exception as exc:
                    raise BusError(type(exc).__name__) from exc
                published += len(result.records)
                checkpoint = saved = result.checkpoint
                if not result.has_more:
                    break
        except BusError as exc:
            # Keep whatever progress was published; leave health unchanged.
            logger.warning("bus unavailable (%s); instance %s stream %s will retry", exc, iid, stream)
            if saved is not None:
                await self._report(
                    iid,
                    stream,
                    trigger,
                    "failed",
                    published,
                    "BusError",
                    "event bus unavailable",
                    self.instance_health(iid),
                    saved,
                    started,
                )
            return
        except Exception as exc:
            health.failure(exc)
            state = self.instance_health(iid)
            logger.info("fetch failed: instance=%s stream=%s %s -> %s", iid, stream, error_class(exc), state)
            await self._report(
                iid, stream, trigger, "failed", published, error_class(exc), safe_detail(exc), state, saved, started
            )
            return
        health.success(rate_limited=rate_limited, drifted=drifted > 0)
        state = self.instance_health(iid)
        detail = f"{drifted} of {published} records did not match the expected schema" if drifted else None
        await self._report(
            iid,
            stream,
            trigger,
            "succeeded",
            published,
            "SchemaDriftError" if drifted else None,
            detail,
            state,
            saved,
            started,
        )

    def instance_health(self, iid: str) -> str:
        order = {"healthy": 0, "degraded": 1, "failing": 2}
        states = [h.health for h in self.health.get(iid, {}).values()] or ["healthy"]
        return max(states, key=order.__getitem__)

    async def _report(
        self,
        iid: str,
        stream: str,
        trigger: str,
        status: str,
        records: int,
        err_class: str | None,
        err_detail: str | None,
        health: str,
        checkpoint: Checkpoint | None,
        started: datetime,
    ) -> None:
        await self.api.report(
            iid,
            {
                "stream": stream,
                "trigger": trigger,
                "status": status,
                "records": records,
                "error_class": err_class,
                "error_detail": err_detail,
                "health": health,
                "cursor": checkpoint.cursor if checkpoint is not None else None,
                "started_at": started.isoformat(),
                "finished_at": datetime.now(UTC).isoformat(),
            },
        )
