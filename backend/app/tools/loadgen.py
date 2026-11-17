"""Synthetic ingest load (P7, NFR-2): ``python -m app.tools.loadgen ...``.

Produces realistic raw envelopes (the connectors' own sandbox scenario payloads, each with a fresh
envelope id) straight onto the bus at a target rate, then watches the ingest consumer group until
its lag is back to zero. It reports what was produced, how fast, and the sustained processing
rate of the real ingest worker(s). Run it through ``scripts/loadtest.py``, which creates the
sandbox instances and passes their ids. Sandbox data only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.admin import AIOKafkaAdminClient

from app.config import get_settings
from app.streaming import MAX_MESSAGE_BYTES, Envelope
from app.workers.ingest import GROUP_ID, TELEMETRY_GROUP_ID
from nocsoc_connector_sdk import ConnectorContext
from nocsoc_connectors import REGISTRY, SCENARIOS, bus_key, bus_topic

TELEMETRY = {"metric@1", "security_event@1"}
TELEMETRY_CONNECTORS = ("splunk", "prometheus", "datadog", "aws.cloudwatch")


async def telemetry_pool(tenant: str, instances: dict[str, str], pages: int) -> list[Envelope]:
    """Security events and metric points from the connectors' own simulators (their telemetry streams)."""
    pool: list[Envelope] = []
    for cid in TELEMETRY_CONNECTORS:
        if cid not in instances:
            continue
        cls = REGISTRY[cid]
        conn = cls(ConnectorContext(tenant_id=tenant, instance_id=instances[cid]), {})
        for stream in (s.name for s in cls.manifest.streams if s.output in TELEMETRY):
            cursor = None
            for _ in range(pages):
                page = await conn.fetch(stream, cursor)
                cursor = page.checkpoint
                for rec in page.records:
                    pool.append(
                        Envelope.for_record(
                            tenant_id=tenant,
                            instance_id=instances[cid],
                            connector=cid,
                            stream=stream,
                            trigger="scenario",
                            record=rec,
                        )
                    )
    if not pool:
        raise SystemExit(f"no telemetry connectors among {sorted(instances)}")
    return pool


def record_pool(tenant: str, instances: dict[str, str], scenario: str, variants: int) -> list[Envelope]:
    """Envelope templates: every scenario record of every listed connector, ``variants`` times."""
    pool: list[Envelope] = []
    for cid in SCENARIOS[scenario].connectors:
        if cid not in instances:
            continue
        conn = REGISTRY[cid](ConnectorContext(tenant_id=tenant, instance_id=instances[cid]), {})
        for v in range(variants):
            for stream, rec in conn.scenario_records(scenario, v):
                pool.append(
                    Envelope.for_record(
                        tenant_id=tenant,
                        instance_id=instances[cid],
                        connector=cid,
                        stream=stream,
                        trigger="scenario",
                        record=rec,
                    )
                )
    if not pool:
        raise SystemExit(f"no records: none of {sorted(instances)} is used by scenario {scenario}")
    return pool


async def lag(admin: AIOKafkaAdminClient, consumer_end: Any, topics: list[str]) -> int:
    committed = {
        **(await admin.list_consumer_group_offsets(GROUP_ID)),
        **(await admin.list_consumer_group_offsets(TELEMETRY_GROUP_ID)),
    }
    parts = [tp for tp in committed if tp.topic in topics]
    if not parts:
        return -1
    ends = await consumer_end(parts)
    return sum(max(0, ends[tp] - committed[tp].offset) for tp in parts)


async def run(args: argparse.Namespace) -> dict[str, Any]:
    settings = get_settings()
    if not settings.kafka_bootstrap:
        raise SystemExit("NOCSOC_KAFKA_BOOTSTRAP is required")
    instances = dict(pair.split("=", 1) for pair in args.instances.split(","))
    alerts = record_pool(args.tenant, instances, args.scenario, args.variants)
    events = await telemetry_pool(args.tenant, instances, 5) if args.mix == "realistic" else []
    topics = sorted({bus_topic(e.connector, e.stream) for e in alerts + events})
    producer = AIOKafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap,
        acks="all",
        enable_idempotence=True,
        max_request_size=MAX_MESSAGE_BYTES,
        linger_ms=20,
        max_batch_size=256 * 1024,
    )
    admin = AIOKafkaAdminClient(bootstrap_servers=settings.kafka_bootstrap)
    probe = AIOKafkaConsumer(bootstrap_servers=settings.kafka_bootstrap)
    await producer.start()
    await admin.start()
    await probe.start()
    total = int(args.rate * args.seconds)
    sent = 0
    rng = random.Random(7)  # noqa: S311  # nosec B311: load shape, not security
    started = time.monotonic()
    max_lag = 0
    try:
        tick = 0.1
        per_tick = max(1, round(args.rate * tick))
        next_tick = started
        futures = []
        while sent < total:
            for _ in range(min(per_tick, total - sent)):
                # realistic: 5 % alerts (correlation path), 95 % security events and metrics
                pool = alerts if not events or rng.random() < args.alert_share else events
                template = pool[rng.randrange(len(pool))]
                env = template.model_copy(update={"id": str(uuid.uuid4()), "time": datetime.now(UTC)})
                key = bus_key(str(env.tenantid), str(env.instanceid), env.connector, env.stream, env.id)
                futures.append(await producer.send(bus_topic(env.connector, env.stream), env.to_bytes(), key=key))
                sent += 1
            next_tick += tick
            delay = next_tick - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            if sent % (per_tick * 50) == 0:
                await producer.flush()
        await producer.flush()
        await asyncio.gather(*futures)
        produced_at = time.monotonic()
        # Drain: wait until the ingest group has caught up with everything produced.
        drained_at = None
        deadline = produced_at + args.drain_timeout
        while time.monotonic() < deadline:
            current = await lag(admin, probe.end_offsets, topics)
            max_lag = max(max_lag, current)
            if current == 0:
                drained_at = time.monotonic()
                break
            await asyncio.sleep(1)
    finally:
        await probe.stop()
        await admin.close()
        await producer.stop()
    produce_seconds = produced_at - started
    report: dict[str, Any] = {
        "scenario": args.scenario,
        "mix": args.mix if events else "alerts",
        "messages": sent,
        "target_rate": args.rate,
        "produce_seconds": round(produce_seconds, 1),
        "produced_rate": round(sent / produce_seconds, 1),
        "max_lag_after_produce": max_lag,
        "drained": drained_at is not None,
    }
    if drained_at is not None:
        report["drain_seconds_after_produce"] = round(drained_at - produced_at, 1)
        report["sustained_processing_rate"] = round(sent / (drained_at - started), 1)
    return report


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tenant", required=True)
    p.add_argument("--instances", required=True, help="connector_id=instance_id,... (sandbox instances)")
    p.add_argument("--scenario", default="phishing_credential_misuse")
    p.add_argument("--rate", type=float, default=1000)
    p.add_argument("--seconds", type=float, default=60)
    p.add_argument("--variants", type=int, default=20)
    p.add_argument("--drain-timeout", type=float, default=600)
    p.add_argument("--mix", choices=["realistic", "alerts"], default="realistic")
    p.add_argument("--alert-share", type=float, default=0.05)
    print(json.dumps(asyncio.run(run(p.parse_args())), indent=2))


if __name__ == "__main__":
    main()
