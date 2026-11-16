"""Event bus (Kafka API; Redpanda in dev). docs/03 §5.

Envelope: CloudEvents 1.0 shape. ``tenantid`` in an envelope is a *claim*; the ingest worker
re-derives ownership from the connector instance (threat model T10).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from aiokafka import AIOKafkaProducer
from pydantic import BaseModel, ConfigDict, Field

ALERTS_UPSERTED = "alerts.upserted"
DEAD_LETTER = "dlq.raw"
RAW_PREFIX = "raw."
MAX_MESSAGE_BYTES = 1_048_576


def raw_topic(connector_id: str) -> str:
    return RAW_PREFIX + connector_id.replace(".", "_")


Trigger = Literal["schedule", "manual", "scenario", "webhook"]


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    specversion: Literal["1.0"] = "1.0"
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str
    type: Literal["nocsoc.raw.v1"] = "nocsoc.raw.v1"
    time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tenantid: uuid.UUID
    instanceid: uuid.UUID
    connector: str = Field(max_length=64)
    stream: str = Field(max_length=64)
    trigger: Trigger
    dataschema: str = Field(max_length=120)
    data: dict[str, Any]

    @classmethod
    def for_record(
        cls, *, tenant_id: str, instance_id: str, connector: str, stream: str, trigger: Trigger, record: Any
    ) -> Envelope:
        data = record.model_dump(mode="json", by_alias=True)
        return cls(
            source=f"connector/{connector}/{instance_id}",
            tenantid=uuid.UUID(str(tenant_id)),
            instanceid=uuid.UUID(str(instance_id)),
            connector=connector,
            stream=stream,
            trigger=trigger,
            dataschema=str(data.get("schema", "")),
            data=data,
        )

    def to_bytes(self) -> bytes:
        return self.model_dump_json().encode()

    def key(self) -> bytes:
        return f"{self.tenantid}:{self.instanceid}".encode()


class Publisher:
    """Thin AIOKafkaProducer wrapper (idempotent producer, acks=all)."""

    def __init__(self, bootstrap: str) -> None:
        self._producer = AIOKafkaProducer(
            bootstrap_servers=bootstrap,
            acks="all",
            enable_idempotence=True,
            max_request_size=MAX_MESSAGE_BYTES,
            linger_ms=5,
        )
        self.started = False

    async def start(self) -> None:
        await self._producer.start()
        self.started = True

    async def stop(self) -> None:
        if self.started:
            await self._producer.stop()
            self.started = False

    async def ping(self) -> None:
        """Metadata round trip to the cluster."""
        await self._producer.client.fetch_all_metadata()

    async def publish(self, envelope: Envelope) -> None:
        await self._producer.send_and_wait(raw_topic(envelope.connector), envelope.to_bytes(), key=envelope.key())

    async def publish_json(self, topic: str, key: str, value: dict[str, Any]) -> None:
        await self._producer.send_and_wait(topic, json.dumps(value, default=str).encode(), key=key.encode())
