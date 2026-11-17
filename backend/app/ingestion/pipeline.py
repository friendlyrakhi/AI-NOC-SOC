"""Raw envelope -> normalized records -> Postgres and ClickHouse (docs/03 §5, docs/06 §5).

Order of checks for every message:
1. Size and shape: envelope parses, ``data`` under 256 KB and 32 levels deep.
2. Ownership: the instance's real owner (from the database) must equal the claimed tenant and
   the claimed connector. Otherwise -> dead letter. The claim is never trusted (T10).
3. Normalize with the connector's pure ``normalize``; drift or invalid output -> dead letter.
4. Idempotency ledger: a redelivered message has no second effect.
5. Write: alerts (de-duplicated by fingerprint), assets (resolved by identifiers),
   vulnerability findings, then telemetry rows in ClickHouse.

All tenant writes run as ``nocsoc_worker`` inside a transaction whose tenant context is the
verified owner, so RLS still applies if this code has a bug.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Literal
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.db.engines import AppDatabase
from app.events import EVENT_COLUMNS, to_event_row
from app.incidents import engine
from app.ingestion.limits import MAX_DEPTH, MAX_RECORD_BYTES, json_depth
from app.streaming import Envelope
from nocsoc_connector_sdk import (
    AlertV1,
    AssetRef,
    AssetV1,
    MetricPointV1,
    RawRecord,
    SchemaDriftError,
    SecurityEventV1,
    ServiceV1,
    TicketV1,
    VulnFindingV1,
)
from nocsoc_connectors import REGISTRY

logger = logging.getLogger(__name__)

Result = Literal["stored", "duplicate", "dead_letter"]

ASSET_TYPE_BY_REF = {"hostname": "host", "fqdn": "host", "ip": "host", "cloud_id": "cloud_resource", "upn": "identity"}


@dataclass
class Outcome:
    result: Result
    reason: str = ""
    tenant: UUID | None = None
    alerts: list[str] = field(default_factory=list)
    incidents: list[str] = field(default_factory=list)
    suppressed: list[str] = field(default_factory=list)
    telemetry: dict[str, list[list[Any]]] = field(default_factory=dict)


class DeadLetterError(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def record_key(env: Envelope) -> str:
    """Pulled records are idempotent by content (a re-fetched page is the same record); pushed
    records (scenario, webhook) are distinct occurrences, idempotent by envelope id."""
    if env.trigger in ("schedule", "manual"):
        d = env.data
        basis = f"{env.instanceid}|{env.dataschema}|{d.get('source_id')}|{d.get('observed_at')}"
    else:
        basis = f"envelope|{env.id}"
    return hashlib.sha256(basis.encode()).hexdigest()


def fingerprint(connector_id: str, dedup_key: str) -> str:
    return hashlib.sha256(f"{connector_id}\x1f{dedup_key}".encode()).hexdigest()


def _ch_dt(value: datetime) -> datetime:
    return value.replace(tzinfo=None) if value.tzinfo is None else value


class Ingestor:
    def __init__(
        self,
        db: AppDatabase,
        analytics: Any | None = None,
        database: str = "nocsoc",
        quota: Callable[[UUID], Awaitable[bool]] | None = None,
        search: Any | None = None,
    ) -> None:
        self.quota = quota
        self.db = db
        self.analytics = analytics
        self.database = database
        # OpenSearch indexer (P6): canonical events become searchable per tenant.
        self.search = search

    # ------------------------------------------------------------------ entry point
    async def process(self, value: bytes) -> Outcome:
        try:
            env = self._parse(value)
        except DeadLetterError as dl:
            await self.dead_letter(None, None, dl, value)
            return Outcome("dead_letter", dl.reason)
        try:
            owner = await self._verify_owner(env)
            if self.quota is not None and not await self.quota(owner):
                raise DeadLetterError("quota_exceeded", "tenant ingest quota exceeded for this minute")
            records = self._normalize(env)
        except DeadLetterError as dl:
            tenant = env.tenantid if dl.reason != "ownership_mismatch" else None
            await self.dead_letter(tenant, env.instanceid, dl, value)
            return Outcome("dead_letter", dl.reason)

        outcome = await self._store(env, owner, records)
        outcome.tenant = owner
        if outcome.result == "stored":
            await self._write_telemetry(env, owner, outcome.telemetry)
        return outcome

    # ------------------------------------------------------------------ checks
    @staticmethod
    def _parse(value: bytes) -> Envelope:
        if len(value) > MAX_RECORD_BYTES + 16_384:
            raise DeadLetterError("too_large", f"{len(value)} bytes")
        try:
            raw = json.loads(value)
        except ValueError as exc:
            raise DeadLetterError("invalid_json", str(exc)[:200]) from exc
        envelope_limit = MAX_DEPTH + 2  # envelope + data wrap the vendor payload
        if json_depth(raw, envelope_limit) > envelope_limit:
            raise DeadLetterError("too_deep")
        try:
            env = Envelope.model_validate(raw)
        except ValidationError as exc:
            raise DeadLetterError("invalid_envelope", str(exc.errors(include_input=False))[:500]) from exc
        if len(json.dumps(env.data)) > MAX_RECORD_BYTES:
            raise DeadLetterError("too_large", "record over 256 KB")
        return env

    async def _verify_owner(self, env: Envelope) -> UUID:
        async with self.db.engine.begin() as conn:
            row = (
                await conn.execute(text("SELECT * FROM connector_instance_owner(:i)"), {"i": env.instanceid})
            ).one_or_none()
        if row is None:
            raise DeadLetterError("ownership_mismatch", "unknown instance")
        if row.tenant_id != env.tenantid or row.definition_id != env.connector:
            raise DeadLetterError("ownership_mismatch", "claimed tenant or connector does not match the instance")
        return row.tenant_id  # type: ignore[no-any-return]

    @staticmethod
    def _normalize(env: Envelope) -> list[Any]:
        cls = REGISTRY.get(env.connector)
        if cls is None:
            raise DeadLetterError("unknown_connector", env.connector)
        try:
            record = RawRecord.model_validate(env.data)
            return list(cls.normalize(env.stream, record))
        except SchemaDriftError as exc:
            raise DeadLetterError("schema_drift", str(exc)[:500]) from exc
        except ValidationError as exc:
            raise DeadLetterError("schema_drift", str(exc.errors(include_input=False))[:500]) from exc
        except (KeyError, TypeError, ValueError) as exc:  # connector bug on odd input: never crash the worker
            raise DeadLetterError("normalize_error", f"{type(exc).__name__}: {exc}"[:500]) from exc

    async def dead_letter(self, tenant: UUID | None, instance: UUID | None, dl: DeadLetterError, value: bytes) -> None:
        try:
            envelope: Any = json.loads(value) if len(value) <= MAX_RECORD_BYTES else None
            if not isinstance(envelope, dict):
                envelope = None
        except ValueError:
            envelope = None
        async with self.db.engine.begin() as conn:
            await conn.execute(
                text("SELECT record_dead_letter(:t, :i, :r, :d, CAST(:e AS jsonb))"),
                {
                    "t": tenant,
                    "i": instance,
                    "r": dl.reason,
                    "d": dl.detail,
                    "e": json.dumps(envelope) if envelope else None,
                },
            )
        logger.warning("dead letter: %s (instance=%s)", dl.reason, instance)

    # ------------------------------------------------------------------ writes
    async def _store(self, env: Envelope, tenant: UUID, records: Sequence[Any]) -> Outcome:
        outcome = Outcome("stored")
        async with self.db.tenant(tenant) as conn:
            inserted = (
                await conn.execute(
                    text(
                        "INSERT INTO ingest_seen (tenant_id, record_key) VALUES (app_tenant(), :k) "
                        "ON CONFLICT DO NOTHING RETURNING 1"
                    ),
                    {"k": record_key(env)},
                )
            ).scalar_one_or_none()
            if inserted is None:
                return Outcome("duplicate")
            changes = engine.Changes()
            source_id = str(env.data.get("source_id", ""))
            new_alerts: list[tuple[str, bool]] = []
            for index, rec in enumerate(records):
                event = to_event_row(
                    rec,
                    tenant=tenant,
                    instance=env.instanceid,
                    connector=env.connector,
                    event_id=env.id,
                    source_id=source_id,
                    index=index,
                )
                if event is not None:
                    outcome.telemetry.setdefault("events", []).append(event)
                if isinstance(rec, AlertV1):
                    upserted = await self._upsert_alert(conn, env, rec, source_id)
                    if upserted:
                        outcome.alerts.append(upserted[0])
                        new_alerts.append(upserted)
                elif isinstance(rec, ServiceV1):

                    async def resolve(refs: Sequence[AssetRef], _conn: AsyncConnection = conn) -> UUID | None:
                        return await self._resolve_asset(_conn, env, refs)

                    await engine.sync_service(conn, rec, env.instanceid, resolve)
                elif isinstance(rec, AssetV1):
                    await self._resolve_asset(
                        conn, env, rec.identifiers, rec.type, rec.name, rec.environment, rec.attributes
                    )
                elif isinstance(rec, VulnFindingV1):
                    await self._upsert_vuln(conn, env, rec)
                elif isinstance(rec, SecurityEventV1):
                    outcome.telemetry.setdefault("security_events", []).append(
                        [
                            tenant,
                            env.instanceid,
                            env.connector,
                            rec.class_uid,
                            rec.activity,
                            rec.severity,
                            _ch_dt(rec.observed_at),
                            rec.message,
                            rec.actor_user or "",
                            rec.device_hostname or "",
                            rec.src_ip or "",
                            rec.dst_ip or "",
                            rec.outcome,
                            list(rec.mitre_techniques),
                        ]
                    )
                elif isinstance(rec, MetricPointV1):
                    outcome.telemetry.setdefault("metrics", []).append(
                        [
                            tenant,
                            env.instanceid,
                            env.connector,
                            rec.name,
                            rec.value,
                            rec.unit,
                            rec.asset_ref.kind,
                            rec.asset_ref.value,
                            _ch_dt(rec.observed_at),
                        ]
                    )
                elif isinstance(rec, TicketV1):
                    await engine.apply_ticket(conn, rec, env.instanceid, changes)
            # Correlation after all records of the message are stored (topology first).
            for alert_id, inserted in new_alerts:
                await engine.after_alert(conn, alert_id, inserted=inserted, changes=changes)
            outcome.incidents = sorted(changes.incidents)
            outcome.suppressed = changes.suppressed
            observed = env.data.get("observed_at")
            outcome.telemetry.setdefault("raw_events", []).append(
                [
                    tenant,
                    env.instanceid,
                    env.connector,
                    env.stream,
                    env.id,
                    source_id,
                    env.trigger,
                    env.dataschema,
                    datetime.fromisoformat(observed) if isinstance(observed, str) else env.time,
                    json.dumps(env.data.get("payload", {}), separators=(",", ":")),
                ]
            )
        return outcome

    async def _resolve_asset(
        self,
        conn: AsyncConnection,
        env: Envelope,
        refs: Sequence[AssetRef],
        type_: str | None = None,
        name: str | None = None,
        environment: str = "unknown",
        attributes: dict[str, Any] | None = None,
    ) -> UUID | None:
        """Find the asset any identifier points at, or create it; then attach all identifiers.

        A transaction-scoped advisory lock per identifier serializes concurrent workers that
        see the same new asset at the same time.
        """
        if not refs:
            return None
        keys = sorted({(r.kind, r.value.lower()) for r in refs})
        for kind, value in keys:
            await conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(app_tenant()::text || :k || :v, 0))"),
                {"k": kind, "v": value},
            )
        row = (
            await conn.execute(
                text(
                    "SELECT asset_id FROM asset_identifiers WHERE (kind, value) IN "
                    "(SELECT * FROM unnest(CAST(:kinds AS text[]), CAST(:vals AS text[]))) LIMIT 1"
                ),
                {"kinds": [k for k, _ in keys], "vals": [v for _, v in keys]},
            )
        ).one_or_none()
        if row is not None:
            asset_id: UUID = row.asset_id
            await conn.execute(
                text(
                    "UPDATE assets SET last_seen = greatest(last_seen, now()), "
                    "sources = (SELECT array_agg(DISTINCT s) FROM unnest(sources || CAST(:src AS text[])) s), "
                    "type = CASE WHEN CAST(:t AS text) IS NOT NULL AND type = 'host' THEN :t ELSE type END, "
                    "environment = CASE WHEN environment = 'unknown' THEN :e ELSE environment END, "
                    "attributes = attributes || CAST(:a AS jsonb) WHERE id = :id"
                ),
                {
                    "src": [env.connector],
                    "t": type_,
                    "e": environment,
                    "a": json.dumps(attributes or {}),
                    "id": asset_id,
                },
            )
        else:
            first = refs[0]
            asset_id = (
                await conn.execute(
                    text(
                        "INSERT INTO assets (tenant_id, type, name, environment, attributes, sources) "
                        "VALUES (app_tenant(), :t, :n, :e, CAST(:a AS jsonb), CAST(:src AS text[])) RETURNING id"
                    ),
                    {
                        "t": type_ or ASSET_TYPE_BY_REF.get(first.kind, "host"),
                        "n": name or first.value,
                        "e": environment,
                        "a": json.dumps(attributes or {}),
                        "src": [env.connector],
                    },
                )
            ).scalar_one()
        for kind, value in keys:
            await conn.execute(
                text(
                    "INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, source_instance_id) "
                    "VALUES (app_tenant(), :a, :k, :v, :i) ON CONFLICT DO NOTHING"
                ),
                {"a": asset_id, "k": kind, "v": value, "i": env.instanceid},
            )
        return asset_id

    async def _upsert_alert(
        self, conn: AsyncConnection, env: Envelope, a: AlertV1, source_id: str
    ) -> tuple[str, bool] | None:
        """(alert id, newly inserted). A de-duplicated repeat returns inserted = False."""
        fp = fingerprint(env.connector, a.dedup_key)
        if a.status == "resolved":
            # A source-side resolve closes the open alert with that fingerprint, if any.
            row = (
                await conn.execute(
                    text(
                        "UPDATE alerts SET status = 'resolved', last_seen = greatest(last_seen, :o), "
                        "updated_at = now(), version = version + 1 WHERE tenant_id = app_tenant() AND fingerprint = :f "
                        "AND status NOT IN ('resolved', 'closed') RETURNING id"
                    ),
                    {"f": fp, "o": a.observed_at},
                )
            ).scalar_one_or_none()
            return (str(row), False) if row else None
        asset_id = await self._resolve_asset(conn, env, a.asset_refs)
        row = (
            await conn.execute(
                text(
                    """
INSERT INTO alerts (tenant_id, domain, source_instance_id, connector_id, source_alert_id, fingerprint, title,
                    description, severity, status, category, asset_id, service_hint, first_seen, last_seen,
                    mitre_techniques, observables, labels, raw_ref)
VALUES (app_tenant(), :domain, :inst, :conn, :sid, :fp, :title, :descr, :sev, 'new', :cat, :asset, :svc, :o, :o,
        CAST(:mitre AS text[]), CAST(:obs AS jsonb), CAST(:labels AS jsonb), :raw)
ON CONFLICT (tenant_id, fingerprint) WHERE status NOT IN ('resolved', 'closed') DO UPDATE SET
  occurrence_count = alerts.occurrence_count + 1,
  last_seen = greatest(alerts.last_seen, EXCLUDED.last_seen),
  first_seen = least(alerts.first_seen, EXCLUDED.first_seen),
  severity = CASE WHEN severity_rank(EXCLUDED.severity) < severity_rank(alerts.severity)
                  THEN EXCLUDED.severity ELSE alerts.severity END,
  title = EXCLUDED.title,
  asset_id = coalesce(alerts.asset_id, EXCLUDED.asset_id),
  raw_ref = EXCLUDED.raw_ref,
  updated_at = now(),
  version = alerts.version + 1
RETURNING id, (xmax = 0) AS inserted
"""
                ),
                {
                    "domain": a.domain,
                    "inst": env.instanceid,
                    "conn": env.connector,
                    "sid": a.source_alert_id,
                    "fp": fp,
                    "title": a.title,
                    "descr": a.description,
                    "sev": a.severity,
                    "cat": a.category,
                    "asset": asset_id,
                    "svc": a.service_hint,
                    "o": a.observed_at,
                    "mitre": list(a.mitre_techniques),
                    "obs": json.dumps([o.model_dump() for o in a.observables]),
                    "labels": json.dumps(a.labels),
                    "raw": source_id,
                },
            )
        ).one()
        return str(row.id), bool(row.inserted)

    async def _upsert_vuln(self, conn: AsyncConnection, env: Envelope, v: VulnFindingV1) -> None:
        asset_id = await self._resolve_asset(conn, env, v.asset_refs)
        await conn.execute(
            text(
                """
INSERT INTO vuln_findings (tenant_id, external_id, connector_id, source_instance_id, vuln_id, title, severity,
                           cvss, epss, kev, status, asset_id, first_found, last_found)
VALUES (app_tenant(), :x, :c, :i, :v, :t, :s, :cvss, :epss, :kev, :st, :a, :o, :o)
ON CONFLICT (tenant_id, external_id) DO UPDATE SET
  severity = EXCLUDED.severity, cvss = EXCLUDED.cvss, epss = EXCLUDED.epss, kev = EXCLUDED.kev,
  status = CASE WHEN vuln_findings.status = 'accepted' THEN 'accepted' ELSE EXCLUDED.status END,
  asset_id = coalesce(EXCLUDED.asset_id, vuln_findings.asset_id),
  last_found = greatest(vuln_findings.last_found, EXCLUDED.last_found)
"""
            ),
            {
                "x": f"{env.connector}:{v.external_id}",
                "c": env.connector,
                "i": env.instanceid,
                "v": v.vuln_id,
                "t": v.title,
                "s": v.severity,
                "cvss": v.cvss,
                "epss": v.epss,
                "kev": v.kev,
                "st": v.status,
                "a": asset_id,
                "o": v.observed_at,
            },
        )

    # ------------------------------------------------------------------ telemetry
    COLUMNS: ClassVar[dict[str, list[str]]] = {
        "raw_events": [
            "tenant_id",
            "instance_id",
            "connector",
            "stream",
            "event_id",
            "source_id",
            "trigger",
            "schema",
            "observed_at",
            "payload",
        ],
        "security_events": [
            "tenant_id",
            "instance_id",
            "connector",
            "class_uid",
            "activity",
            "severity",
            "observed_at",
            "message",
            "actor_user",
            "device_hostname",
            "src_ip",
            "dst_ip",
            "outcome",
            "mitre",
        ],
        "metrics": [
            "tenant_id",
            "instance_id",
            "connector",
            "name",
            "value",
            "unit",
            "asset_kind",
            "asset_value",
            "observed_at",
        ],
        "events": EVENT_COLUMNS,
    }

    async def _write_telemetry(self, env: Envelope, tenant: UUID, rows: dict[str, list[list[Any]]]) -> None:
        """Best effort after the Postgres commit: a telemetry outage must not block alerts.

        A failed insert is logged and those telemetry rows are not retried (the alert, asset and
        finding writes are already committed). Documented as a P2 residual risk; a transactional
        outbox for telemetry is still a residual risk (P7). The same applies to the OpenSearch copy of
        canonical events.
        """
        if self.analytics is not None:
            for table, data in rows.items():
                if not data:
                    continue
                try:
                    await self.analytics.insert(f"{self.database}.{table}", data, column_names=self.COLUMNS[table])
                except Exception:
                    logger.exception("telemetry insert failed (table=%s instance=%s)", table, env.instanceid)
        events = rows.get("events") or []
        if self.search is not None and events:
            from app.searchstore import event_document

            try:
                failed = await self.search.bulk([event_document(r, self.COLUMNS["events"]) for r in events])
                if failed:
                    logger.warning("search indexing failed for %d event(s) (instance=%s)", failed, env.instanceid)
            except Exception:
                logger.exception("search indexing failed (instance=%s)", env.instanceid)
