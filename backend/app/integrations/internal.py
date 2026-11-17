"""Service endpoints: connector-runner work protocol and vendor webhook ingress.

Runner (``**internal()``): a shared token authenticates the runner. These endpoints use narrow
SECURITY DEFINER functions (migration 0002) rather than broad grants. The runner never
receives tenant data beyond what it needs to fetch: instance config, checkpoints and, per
instance, its decrypted sandbox credentials.

Webhooks (``**webhook_hmac()``): per-instance HMAC over ``ts.nonce.body``, +-300 s skew,
single-use nonce in Valkey, size and depth limits. The tenant comes from the instance
record, never from the request (threat model T10, T14).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.core.authz.deps import internal, webhook_hmac
from app.core.secrets import SecretDecryptionError
from app.core.types import IsoDatetime, StrictInt
from app.errors import ProblemError, not_found
from app.ingestion.limits import MAX_DEPTH, json_depth
from app.integrations.common import build, decrypt_credentials, publish_records, webhook_aad
from app.services import Services, get_services
from nocsoc_connector_sdk import ConfigError, SchemaDriftError
from nocsoc_connector_sdk.signing import verify

logger = logging.getLogger(__name__)

router = APIRouter(tags=["internal"])
Svc = Annotated[Services, Depends(get_services)]

NONCE_TTL_SECONDS = 600
WEBHOOK_RATE_PER_MINUTE = 600


# ============================================================ runner
class WorkItem(BaseModel):
    instance_id: UUID
    tenant_id: UUID
    definition_id: str
    mode: Literal["sandbox"]
    config: dict[str, Any]
    sync_requested_at: datetime | None
    checkpoints: dict[str, Any]
    last_runs: dict[str, datetime]


class RunnerCredentials(BaseModel):
    secrets: dict[str, str]


class RunReport(BaseModel):
    stream: str = Field(max_length=64)
    trigger: Literal["schedule", "manual"]
    status: Literal["succeeded", "failed"]
    records: StrictInt = Field(ge=0)
    error_class: str | None = Field(default=None, max_length=100)
    error_detail: str | None = Field(default=None, max_length=1000)
    health: Literal["healthy", "degraded", "failing"]
    cursor: dict[str, Any] | None = None
    started_at: IsoDatetime
    finished_at: IsoDatetime


@router.get("/internal/runner/work", response_model=list[WorkItem], **internal())
async def runner_work(services: Svc) -> list[WorkItem]:
    async with services.app_db.engine.begin() as conn:
        rows = await conn.execute(text("SELECT * FROM runner_work()"))
        return [WorkItem(**r._mapping) for r in rows]


@router.get("/internal/runner/instances/{instance_id}/credentials", response_model=RunnerCredentials, **internal())
async def runner_credentials(instance_id: UUID, services: Svc) -> RunnerCredentials:
    async with services.app_db.engine.begin() as conn:
        ciphertext = (await conn.execute(text("SELECT runner_secret(:i)"), {"i": instance_id})).scalar_one_or_none()
    try:
        return RunnerCredentials(secrets=decrypt_credentials(services, instance_id, ciphertext))
    except SecretDecryptionError as exc:
        raise ProblemError(
            409, "connector.credentials_unreadable", "Credentials unreadable", "Set them again."
        ) from exc


@router.post("/internal/runner/instances/{instance_id}/report", status_code=status.HTTP_204_NO_CONTENT, **internal())
async def runner_report(instance_id: UUID, body: RunReport, services: Svc) -> None:
    async with services.app_db.engine.begin() as conn:
        try:
            await conn.execute(
                text("SELECT runner_report(:i, :s, :t, :st, :n, :ec, :ed, :h, CAST(:c AS jsonb), :sa, :fa)"),
                {
                    "i": instance_id,
                    "s": body.stream,
                    "t": body.trigger,
                    "st": body.status,
                    "n": body.records,
                    "ec": body.error_class,
                    "ed": body.error_detail,
                    "h": body.health,
                    "c": json.dumps(body.cursor) if body.cursor is not None else None,
                    "sa": body.started_at,
                    "fa": body.finished_at,
                },
            )
        except Exception as exc:
            if "unknown instance" in str(exc):
                raise not_found("Connector instance") from exc
            raise


# ============================================================ webhooks
def _unauthorized() -> ProblemError:
    return ProblemError(401, "webhook.unauthorized", "Signature rejected", "Missing or invalid webhook signature.")


class WebhookAccepted(BaseModel):
    accepted: int


@router.post(
    "/ingest/webhooks/{instance_id}",
    response_model=WebhookAccepted,
    status_code=status.HTTP_202_ACCEPTED,
    **webhook_hmac(),
)
async def webhook_ingress(instance_id: UUID, request: Request, services: Svc) -> WebhookAccepted:
    limit = services.settings.webhook_max_bytes
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        raise ProblemError(
            413, "webhook.too_large", "Payload too large", f"Webhook bodies are limited to {limit} bytes."
        )
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise ProblemError(
                413, "webhook.too_large", "Payload too large", f"Webhook bodies are limited to {limit} bytes."
            )

    ts = request.headers.get("x-nocsoc-timestamp", "")
    nonce = request.headers.get("x-nocsoc-nonce", "")
    signature = request.headers.get("x-nocsoc-signature", "")
    if not (ts and nonce and signature):
        raise _unauthorized()

    rate_key = f"p:webhook:rate:{instance_id}"
    if await services.limiter.hit(rate_key, 60) > WEBHOOK_RATE_PER_MINUTE:
        raise ProblemError(429, "webhook.rate_limited", "Too many requests", "Slow down.")

    async with services.app_db.engine.begin() as conn:
        row = (await conn.execute(text("SELECT * FROM webhook_lookup(:i)"), {"i": instance_id})).one_or_none()
    # Unknown instance, disabled instance and bad signature look the same to the caller.
    if row is None or not row.enabled or not row.ciphertext:
        raise _unauthorized()
    try:
        secret = services.secrets.decrypt(row.ciphertext, webhook_aad(instance_id))
    except SecretDecryptionError:
        logger.error("webhook secret undecryptable for instance %s", instance_id)
        raise _unauthorized() from None
    if not verify(secret, ts, nonce, body, signature):
        raise _unauthorized()
    # Single use: a captured request cannot be replayed within the skew window.
    if not await services.valkey.set(f"p:webhook:nonce:{instance_id}:{nonce}", b"1", nx=True, ex=NONCE_TTL_SECONDS):
        raise ProblemError(409, "webhook.replayed", "Replayed request", "This nonce was already used.")

    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise ProblemError(400, "webhook.invalid_json", "Invalid JSON", "The body must be a JSON object.") from exc
    if not isinstance(payload, dict):
        raise ProblemError(400, "webhook.invalid_json", "Invalid JSON", "The body must be a JSON object.")
    if json_depth(payload) > MAX_DEPTH:
        raise ProblemError(422, "webhook.too_deep", "Payload too deep", f"Nesting is limited to {MAX_DEPTH} levels.")

    connector = build(row.definition_id, row.tenant_id, instance_id, row.config or {})
    try:
        records = connector.parse_webhook(payload)
    except (SchemaDriftError, ConfigError) as exc:
        raise ProblemError(422, "webhook.unrecognized", "Unrecognized payload", str(exc)[:300]) from exc
    accepted = await publish_records(
        services,
        tenant_id=row.tenant_id,
        instance_id=instance_id,
        connector_id=row.definition_id,
        trigger="webhook",
        records=records,
    )
    return WebhookAccepted(accepted=accepted)
