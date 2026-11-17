"""Shared helpers for the integration endpoints."""

from __future__ import annotations

import json
import secrets as pysecrets
from typing import Any
from uuid import UUID

from app.errors import ProblemError
from app.services import Services
from app.streaming import Envelope, Trigger
from nocsoc_connector_sdk import Connector, ConnectorContext, RawRecord
from nocsoc_connectors import REGISTRY, bus_key, is_telemetry_stream


# Envelope-encryption context strings bind a ciphertext to one instance, so a ciphertext
# copied to another row cannot be decrypted there (threat model T17).
def credential_aad(instance_id: UUID | str) -> str:
    return f"connector-credential:{instance_id}"


def webhook_aad(instance_id: UUID | str) -> str:
    return f"connector-webhook:{instance_id}"


def new_webhook_secret() -> str:
    return "whs_" + pysecrets.token_urlsafe(32)


def definition(definition_id: str) -> type[Connector]:
    cls = REGISTRY.get(definition_id)
    if cls is None:
        raise ProblemError(422, "connector.unknown_definition", "Unknown connector", f"No connector '{definition_id}'.")
    return cls


def build(
    definition_id: str,
    tenant_id: UUID | str,
    instance_id: UUID | str,
    config: dict[str, Any],
    secrets: dict[str, str] | None = None,
) -> Connector:
    """A sandbox connector instance. Live mode does not exist in this build (guardrail #1)."""
    cls = definition(definition_id)
    return cls(
        ConnectorContext(tenant_id=str(tenant_id), instance_id=str(instance_id), mode="sandbox"), config, secrets
    )


def decrypt_credentials(services: Services, instance_id: UUID | str, ciphertext: str | None) -> dict[str, str]:
    if not ciphertext:
        return {}
    data = json.loads(services.secrets.decrypt(ciphertext, credential_aad(instance_id)))
    return {str(k): str(v) for k, v in data.items()}


async def publish_records(
    services: Services,
    *,
    tenant_id: UUID | str,
    instance_id: UUID | str,
    connector_id: str,
    trigger: Trigger,
    records: list[tuple[str, RawRecord]],
) -> int:
    publisher = await require_publisher(services)
    for stream, record in records:
        env = Envelope.for_record(
            tenant_id=str(tenant_id),
            instance_id=str(instance_id),
            connector=connector_id,
            stream=stream,
            trigger=trigger,
            record=record,
        )
        await publisher.publish(
            env,
            bus_key(str(tenant_id), str(instance_id), connector_id, stream, env.id),
            telemetry_topic=is_telemetry_stream(connector_id, stream),
        )
    return len(records)


async def require_publisher(services: Services):  # type: ignore[no-untyped-def]
    try:
        publisher = await services.publisher()
    except Exception as exc:
        raise ProblemError(
            503, "stream.unavailable", "Event bus unavailable", "The event bus could not be reached."
        ) from exc
    if publisher is None:
        raise ProblemError(
            503, "stream.disabled", "Event bus not configured", "Start the 'stream' profile to ingest data."
        )
    return publisher
