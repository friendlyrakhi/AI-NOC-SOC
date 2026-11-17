"""Integration administration (docs/05 §2.4, docs/06 §6).

- Instances are sandbox-only (database CHECK and guardrail #1). Nothing here reaches a vendor.
- Credentials are write-only: stored envelope-encrypted, never returned, audited by key name only.
- Health is owned by the connector-runner. The API never claims an instance is healthy;
  a new instance stays ``pending`` until the runner has reported a real run.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, Response, status
from jsonschema import Draft202012Validator
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.core.cache import tenant_budget
from app.core.tenancy.common import record, tenant_tx
from app.core.types import StrictBool, StrictInt
from app.errors import ProblemError, not_found
from app.integrations.common import (
    build,
    credential_aad,
    decrypt_credentials,
    definition,
    new_webhook_secret,
    publish_records,
    require_publisher,
    webhook_aad,
)
from app.services import Services, get_services
from nocsoc_connectors import REGISTRY, SCENARIOS

router = APIRouter(prefix="/connectors", tags=["integrations"])

Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]

MAX_CONFIG_BYTES = 16_384


# ============================================================ definitions
class StreamOut(BaseModel):
    name: str
    domain: str | None
    output: str
    default_interval_seconds: int


class ActionOut(BaseModel):
    key: str
    tier: str
    reversible: bool


class DefinitionOut(BaseModel):
    id: str
    name: str
    vendor: str
    category: str
    version: str
    certification: str
    auth_types: list[str]
    streams: list[StreamOut]
    webhook: bool
    actions: list[ActionOut]
    config_schema: dict[str, Any]
    secrets_schema: dict[str, Any]
    scenarios: list[str]
    docs_reference: str


def _definition_out(cid: str) -> DefinitionOut:
    m = REGISTRY[cid].manifest
    return DefinitionOut(
        id=m.id,
        name=m.name,
        vendor=m.vendor,
        category=m.category,
        version=m.version,
        certification=m.certification,
        auth_types=m.auth_types,
        streams=[StreamOut(**s.model_dump()) for s in m.streams],
        webhook=m.webhook,
        actions=[ActionOut(key=a.key, tier=a.tier, reversible=a.reversible) for a in m.actions],
        config_schema=m.config_schema,
        secrets_schema=m.secrets_schema,
        scenarios=[s.key for s in SCENARIOS.values() if m.id in s.connectors],
        docs_reference=m.docs_reference,
    )


@router.get("/definitions", response_model=list[DefinitionOut], **requires("connector:read"))
async def list_definitions() -> list[DefinitionOut]:
    return [_definition_out(cid) for cid in sorted(REGISTRY)]


# ============================================================ instances
InstanceStatus = Literal["pending", "healthy", "degraded", "failing", "disabled"]


class InstanceOut(BaseModel):
    id: UUID
    definition_id: str
    name: str
    mode: Literal["sandbox"]
    config: dict[str, Any]
    enabled: bool
    status: InstanceStatus
    status_detail: str | None
    has_credentials: bool
    webhook_enabled: bool
    sync_requested_at: datetime | None
    last_run_at: datetime | None
    last_success_at: datetime | None
    last_error_at: datetime | None
    created_at: datetime
    updated_at: datetime
    version: int


class InstanceCreated(InstanceOut):
    # Shown exactly once. Store it in the sender's webhook configuration.
    webhook_secret: str | None = None


class InstanceCreate(BaseModel):
    definition_id: str = Field(max_length=64)
    name: str = Field(min_length=1, max_length=100)
    config: dict[str, Any] = Field(default_factory=dict)


class InstancePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    config: dict[str, Any] | None = None
    enabled: StrictBool | None = None
    version: StrictInt = Field(ge=1, description="Current version (optimistic concurrency).")


class CredentialsIn(BaseModel):
    secrets: dict[str, str] = Field(max_length=20)


class ConnectionTestOut(BaseModel):
    ok: bool
    detail: str


class WebhookSecretOut(BaseModel):
    webhook_secret: str
    ingress_path: str


_INSTANCE_COLS = (
    "id, definition_id, name, mode, config, enabled, status, status_detail, secret_id IS NOT NULL AS has_credentials, "
    "webhook_secret_id IS NOT NULL AS webhook_enabled, sync_requested_at, last_run_at, last_success_at, last_error_at, "
    "created_at, updated_at, version"
)


def _check_config(definition_id: str, config: dict[str, Any]) -> None:
    if len(json.dumps(config)) > MAX_CONFIG_BYTES:
        raise ProblemError(
            422, "connector.config_too_large", "Configuration too large", "Keep configuration under 16 KB."
        )
    problems = build(definition_id, uuid4(), uuid4(), config).validate_config()
    faults = config.get("sandbox_faults")
    if faults is not None and not isinstance(faults, dict):
        problems.append("sandbox_faults: must be an object")
    if problems:
        raise ProblemError(422, "connector.invalid_config", "Invalid configuration", "; ".join(problems))


async def _get(conn: Any, instance_id: UUID) -> Any:
    sql = f"SELECT {_INSTANCE_COLS} FROM connector_instances WHERE id = :id"  # nosec B608 - constant columns
    row = (await conn.execute(text(sql), {"id": instance_id})).one_or_none()
    if row is None:
        raise not_found("Connector instance")
    return row


@router.get("/instances", response_model=list[InstanceOut], **requires("connector:read"))
async def list_instances(services: Svc, p: P) -> list[InstanceOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(text(f"SELECT {_INSTANCE_COLS} FROM connector_instances ORDER BY name"))  # nosec B608
        return [InstanceOut(**r._mapping) for r in rows]


@router.post(
    "/instances", response_model=InstanceCreated, status_code=status.HTTP_201_CREATED, **requires("connector:manage")
)
async def create_instance(body: InstanceCreate, services: Svc, p: P) -> InstanceCreated:
    cls = definition(body.definition_id)
    _check_config(body.definition_id, body.config)
    instance_id = uuid4()
    webhook_plain = new_webhook_secret() if cls.manifest.webhook else None
    async with tenant_tx(services, p) as conn:
        webhook_secret_id = None
        if webhook_plain:
            webhook_secret_id = (
                await conn.execute(
                    text(
                        "INSERT INTO secrets (tenant_id, kind, ciphertext, created_by) "
                        "VALUES (app_tenant(), 'webhook_hmac', :c, :u) RETURNING id"
                    ),
                    {"c": services.secrets.encrypt(webhook_plain, webhook_aad(instance_id)), "u": p.user_id},
                )
            ).scalar_one()
        try:
            await conn.execute(
                text(
                    "INSERT INTO connector_instances "
                    "(id, tenant_id, definition_id, name, config, webhook_secret_id, created_by) "
                    "VALUES (:id, app_tenant(), :d, :n, CAST(:c AS jsonb), :w, :u)"
                ),
                {
                    "id": instance_id,
                    "d": body.definition_id,
                    "n": body.name,
                    "c": json.dumps(body.config),
                    "w": webhook_secret_id,
                    "u": p.user_id,
                },
            )
        except IntegrityError as exc:
            raise ProblemError(
                409, "connector.name_taken", "Name in use", "Another integration has that name."
            ) from exc
        row = await _get(conn, instance_id)
        await record(
            conn,
            p,
            "connector.create",
            target_type="connector_instance",
            target_id=instance_id,
            details={"definition_id": body.definition_id, "name": body.name, "mode": "sandbox"},
        )
    return InstanceCreated(**row._mapping, webhook_secret=webhook_plain)


@router.get("/instances/{instance_id}", response_model=InstanceOut, **requires("connector:read"))
async def get_instance(instance_id: UUID, services: Svc, p: P) -> InstanceOut:
    async with tenant_tx(services, p) as conn:
        return InstanceOut(**(await _get(conn, instance_id))._mapping)


@router.patch("/instances/{instance_id}", response_model=InstanceOut, **requires("connector:manage"))
async def patch_instance(instance_id: UUID, body: InstancePatch, services: Svc, p: P) -> InstanceOut:
    async with tenant_tx(services, p) as conn:
        current = await _get(conn, instance_id)
        if body.config is not None:
            _check_config(current.definition_id, body.config)
        sets = ["updated_at = now()", "version = version + 1"]
        params: dict[str, Any] = {"id": instance_id, "v": body.version}
        if body.name is not None:
            sets.append("name = :n")
            params["n"] = body.name
        if body.config is not None:
            sets.append("config = CAST(:c AS jsonb)")
            params["c"] = json.dumps(body.config)
        if body.enabled is not None:
            sets.append("enabled = :e")
            # Re-enabling returns to "pending" until the runner reports a real run.
            sets.append("status = CASE WHEN :e THEN 'pending' ELSE 'disabled' END, status_detail = NULL")
            params["e"] = body.enabled
        try:
            result = await conn.execute(
                text(f"UPDATE connector_instances SET {', '.join(sets)} WHERE id = :id AND version = :v"),  # nosec B608
                params,
            )
        except IntegrityError as exc:
            raise ProblemError(
                409, "connector.name_taken", "Name in use", "Another integration has that name."
            ) from exc
        if result.rowcount == 0:
            raise ProblemError(409, "conflict.version", "Changed by someone else", "Reload and try again.")
        row = await _get(conn, instance_id)
        await record(
            conn,
            p,
            "connector.update",
            target_type="connector_instance",
            target_id=instance_id,
            details={k: v for k, v in body.model_dump(exclude_none=True).items() if k != "version"},
        )
    return InstanceOut(**row._mapping)


@router.delete(
    "/instances/{instance_id}", status_code=status.HTTP_204_NO_CONTENT, **requires("connector:manage", step_up=True)
)
async def delete_instance(instance_id: UUID, services: Svc, p: P) -> Response:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text("DELETE FROM connector_instances WHERE id = :id RETURNING secret_id, webhook_secret_id, name"),
                {"id": instance_id},
            )
        ).one_or_none()
        if row is None:
            raise not_found("Connector instance")
        ids = [i for i in (row.secret_id, row.webhook_secret_id) if i]
        if ids:
            await conn.execute(text("DELETE FROM secrets WHERE id = ANY(:ids)"), {"ids": ids})
        await record(
            conn,
            p,
            "connector.delete",
            target_type="connector_instance",
            target_id=instance_id,
            details={"name": row.name},
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put(
    "/instances/{instance_id}/credentials",
    status_code=status.HTTP_204_NO_CONTENT,
    **requires("connector:secret:write", step_up=True),
)
async def set_credentials(instance_id: UUID, body: CredentialsIn, services: Svc, p: P) -> Response:
    async with tenant_tx(services, p) as conn:
        current = await _get(conn, instance_id)
        schema = definition(current.definition_id).manifest.secrets_schema
        # jsonschema messages can quote the value, so report only the field and the rule (T17).
        problems = [
            e.message
            if e.validator in {"required", "additionalProperties"}
            else f"{'/'.join(map(str, e.path)) or 'secrets'}: fails '{e.validator}'"
            for e in Draft202012Validator(schema).iter_errors(body.secrets)
        ]
        if problems:
            raise ProblemError(422, "connector.invalid_credentials", "Invalid credentials", "; ".join(problems))
        ciphertext = services.secrets.encrypt(json.dumps(body.secrets), credential_aad(instance_id))
        existing = (
            await conn.execute(text("SELECT secret_id FROM connector_instances WHERE id = :id"), {"id": instance_id})
        ).scalar_one()
        if existing:
            await conn.execute(
                text("UPDATE secrets SET ciphertext = :c, rotated_at = now() WHERE id = :s"),
                {"c": ciphertext, "s": existing},
            )
        else:
            sid = (
                await conn.execute(
                    text(
                        "INSERT INTO secrets (tenant_id, kind, ciphertext, created_by) "
                        "VALUES (app_tenant(), 'connector_credential', :c, :u) RETURNING id"
                    ),
                    {"c": ciphertext, "u": p.user_id},
                )
            ).scalar_one()
            await conn.execute(
                text(
                    "UPDATE connector_instances SET secret_id = :s, updated_at = now(), version = version + 1 "
                    "WHERE id = :id"
                ),
                {"s": sid, "id": instance_id},
            )
        await record(
            conn,
            p,
            "connector.credentials.set",
            target_type="connector_instance",
            target_id=instance_id,
            details={"fields": sorted(body.secrets)},
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/instances/{instance_id}/webhook-secret",
    response_model=WebhookSecretOut,
    **requires("connector:secret:write", step_up=True),
)
async def rotate_webhook_secret(instance_id: UUID, services: Svc, p: P) -> WebhookSecretOut:
    plain = new_webhook_secret()
    async with tenant_tx(services, p) as conn:
        current = await _get(conn, instance_id)
        if not definition(current.definition_id).manifest.webhook:
            raise ProblemError(422, "connector.no_webhook", "No webhook", "This connector does not accept webhooks.")
        ciphertext = services.secrets.encrypt(plain, webhook_aad(instance_id))
        existing = (
            await conn.execute(
                text("SELECT webhook_secret_id FROM connector_instances WHERE id = :id"), {"id": instance_id}
            )
        ).scalar_one()
        if existing:
            await conn.execute(
                text("UPDATE secrets SET ciphertext = :c, rotated_at = now() WHERE id = :s"),
                {"c": ciphertext, "s": existing},
            )
        else:
            sid = (
                await conn.execute(
                    text(
                        "INSERT INTO secrets (tenant_id, kind, ciphertext, created_by) "
                        "VALUES (app_tenant(), 'webhook_hmac', :c, :u) RETURNING id"
                    ),
                    {"c": ciphertext, "u": p.user_id},
                )
            ).scalar_one()
            await conn.execute(
                text("UPDATE connector_instances SET webhook_secret_id = :s WHERE id = :id"),
                {"s": sid, "id": instance_id},
            )
        await record(
            conn, p, "connector.webhook_secret.rotate", target_type="connector_instance", target_id=instance_id
        )
    return WebhookSecretOut(webhook_secret=plain, ingress_path=f"/api/v1/ingest/webhooks/{instance_id}")


@router.post("/instances/{instance_id}/test", response_model=ConnectionTestOut, **requires("connector:manage"))
async def test_instance(instance_id: UUID, services: Svc, p: P) -> ConnectionTestOut:
    """Runs the connector's connection test against its sandbox simulator."""
    async with tenant_tx(services, p) as conn:
        current = await _get(conn, instance_id)
        ciphertext = (
            await conn.execute(
                text(
                    "SELECT s.ciphertext FROM connector_instances i "
                    "JOIN secrets s ON s.id = i.secret_id WHERE i.id = :id"
                ),
                {"id": instance_id},
            )
        ).scalar_one_or_none()
    connector = build(
        current.definition_id,
        p.tenant_id or "",
        instance_id,
        current.config,
        decrypt_credentials(services, instance_id, ciphertext),
    )
    result = await connector.test_connection()
    async with tenant_tx(services, p) as conn:
        await record(
            conn,
            p,
            "connector.test",
            target_type="connector_instance",
            target_id=instance_id,
            outcome="success" if result.ok else "failure",
        )
    return ConnectionTestOut(ok=result.ok, detail=result.detail)


@router.post("/instances/{instance_id}/sync", status_code=status.HTTP_202_ACCEPTED, **requires("connector:manage"))
async def request_sync(instance_id: UUID, services: Svc, p: P) -> dict[str, str]:
    async with tenant_tx(services, p) as conn:
        result = await conn.execute(
            text("UPDATE connector_instances SET sync_requested_at = now() WHERE id = :id AND enabled"),
            {"id": instance_id},
        )
        if result.rowcount == 0:
            await _get(conn, instance_id)  # 404 if invisible
            raise ProblemError(409, "connector.disabled", "Integration disabled", "Enable the integration first.")
        await record(conn, p, "connector.sync", target_type="connector_instance", target_id=instance_id)
    return {"status": "requested"}


# ============================================================ runs and dead letters
class RunOut(BaseModel):
    id: int
    stream: str
    trigger: str
    status: str
    records_out: int
    error_class: str | None
    error_detail: str | None
    started_at: datetime
    finished_at: datetime


@router.get("/instances/{instance_id}/runs", response_model=list[RunOut], **requires("connector:read"))
async def list_runs(
    instance_id: UUID, services: Svc, p: P, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[RunOut]:
    async with tenant_tx(services, p) as conn:
        await _get(conn, instance_id)
        rows = await conn.execute(
            text(
                "SELECT id, stream, trigger, status, records_out, error_class, error_detail, started_at, finished_at "
                "FROM connector_runs WHERE instance_id = :id ORDER BY id DESC LIMIT :l"
            ),
            {"id": instance_id, "l": limit},
        )
        return [RunOut(**r._mapping) for r in rows]


class DeadLetterOut(BaseModel):
    id: int
    instance_id: UUID | None
    reason: str
    detail: str
    at: datetime


@router.get("/dead-letters", response_model=list[DeadLetterOut], **requires("connector:read"))
async def list_dead_letters(
    services: Svc,
    p: P,
    instance_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[DeadLetterOut]:
    """Envelope bodies are not returned: they may hold attacker-controlled content."""
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(
            text(
                "SELECT id, instance_id, reason, detail, at FROM ingest_dead_letters "
                "WHERE (CAST(:i AS uuid) IS NULL OR instance_id = :i) ORDER BY id DESC LIMIT :l"
            ),
            {"i": instance_id, "l": limit},
        )
        return [DeadLetterOut(**r._mapping) for r in rows]


# ============================================================ scenarios (sandbox)
class ScenarioOut(BaseModel):
    key: str
    title: str
    description: str
    connectors: list[str]
    configured: list[str]
    missing: list[str]


class ReplayOut(BaseModel):
    scenario: str
    times: int
    published: int
    instances: list[UUID]
    missing: list[str]


async def _sandbox_instances(conn: Any) -> dict[str, list[Any]]:
    rows = await conn.execute(
        text(
            "SELECT id, definition_id, config FROM connector_instances "
            "WHERE enabled AND mode = 'sandbox' ORDER BY created_at"
        )
    )
    out: dict[str, list[Any]] = {}
    for r in rows:
        out.setdefault(r.definition_id, []).append(r)
    return out


@router.get("/scenarios", response_model=list[ScenarioOut], **requires("connector:read"))
async def list_scenarios(services: Svc, p: P) -> list[ScenarioOut]:
    async with tenant_tx(services, p) as conn:
        have = await _sandbox_instances(conn)
    return [
        ScenarioOut(
            key=s.key,
            title=s.title,
            description=s.description,
            connectors=list(s.connectors),
            configured=[c for c in s.connectors if c in have],
            missing=[c for c in s.connectors if c not in have],
        )
        for s in SCENARIOS.values()
    ]


@router.post("/scenarios/{key}/replay", response_model=ReplayOut, **requires("connector:manage"))
async def replay_scenario(key: str, services: Svc, p: P, times: Annotated[int, Query(ge=1, le=10)] = 1) -> ReplayOut:
    """Publishes the scenario's sandbox records through the real pipeline (runner -> bus -> worker).

    Uses the tenant's enabled sandbox instances; connectors without one are reported as missing.
    """
    scenario = SCENARIOS.get(key)
    if scenario is None:
        raise not_found("Scenario")
    await tenant_budget(services, p, "scenario-replay")
    await require_publisher(services)  # fail before doing anything if the bus is not there
    async with tenant_tx(services, p) as conn:
        have = await _sandbox_instances(conn)
    if not any(c in have for c in scenario.connectors):
        raise ProblemError(
            409,
            "scenario.no_instances",
            "No sandbox integrations",
            f"Add a sandbox instance of one of: {', '.join(scenario.connectors)}.",
        )
    published = 0
    used: list[UUID] = []
    for cid in scenario.connectors:
        for inst in have.get(cid, [])[:1]:
            connector = build(cid, p.tenant_id or "", inst.id, inst.config)
            for _ in range(times):
                published += await publish_records(
                    services,
                    tenant_id=p.tenant_id or "",
                    instance_id=inst.id,
                    connector_id=cid,
                    trigger="scenario",
                    records=connector.scenario_records(key, 0),
                )
            used.append(inst.id)
    missing = [c for c in scenario.connectors if c not in have]
    async with tenant_tx(services, p) as conn:
        await record(
            conn,
            p,
            "connector.scenario.replay",
            target_type="scenario",
            target_id=key,
            details={"times": times, "published": published, "missing": missing},
        )
    return ReplayOut(scenario=key, times=times, published=published, instances=used, missing=missing)
