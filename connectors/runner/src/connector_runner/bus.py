"""Raw-record envelopes for the event bus.

Same shape as the platform's ``app.streaming.Envelope`` (a contract test in the backend checks
that every envelope built here validates there). Kept separate so the runner never imports the
API process's code.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from aiokafka import AIOKafkaProducer

from nocsoc_connector_sdk import RawRecord


def raw_topic(connector_id: str) -> str:
    return "raw." + connector_id.replace(".", "_")


def envelope(
    tenant_id: str, instance_id: str, connector: str, stream: str, trigger: str, record: RawRecord
) -> dict[str, Any]:
    data = record.model_dump(mode="json", by_alias=True)
    return {
        "specversion": "1.0",
        "id": str(uuid.uuid4()),
        "source": f"connector/{connector}/{instance_id}",
        "type": "nocsoc.raw.v1",
        "time": datetime.now(UTC).isoformat(),
        "tenantid": tenant_id,
        "instanceid": instance_id,
        "connector": connector,
        "stream": stream,
        "trigger": trigger,
        "dataschema": data.get("schema", ""),
        "data": data,
    }


class Bus(Protocol):
    async def send(self, topic: str, key: bytes, value: bytes) -> None: ...


class KafkaBus:
    def __init__(self, bootstrap: str) -> None:
        self._producer = AIOKafkaProducer(
            bootstrap_servers=bootstrap, acks="all", enable_idempotence=True, max_request_size=1_048_576, linger_ms=5
        )

    async def start(self) -> None:
        await self._producer.start()

    async def stop(self) -> None:
        await self._producer.stop()

    async def send(self, topic: str, key: bytes, value: bytes) -> None:
        await self._producer.send_and_wait(topic, value, key=key)


async def publish(bus: Bus, env: dict[str, Any]) -> None:
    await bus.send(
        raw_topic(env["connector"]), f"{env['tenantid']}:{env['instanceid']}".encode(), json.dumps(env).encode()
    )
