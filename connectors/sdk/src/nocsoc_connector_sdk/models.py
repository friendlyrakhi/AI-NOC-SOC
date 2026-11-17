"""Connector contract types (docs/06-connector-sdk.md §3-4).

Normalized records are versioned. Security events follow an OCSF-aligned subset; operational
records follow OTel-aligned naming. Every normalized record carries its source provenance.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Domain = Literal["noc", "soc"]
Category = Literal["observability", "cloud_monitoring", "siem", "edr", "vuln", "itsm", "generic"]
Tier = Literal["T0", "T1", "T2", "T3"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# ------------------------------------------------------------------ manifest
class StreamSpec(_Model):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,40}$")
    domain: Domain | None = None
    output: str
    default_interval_seconds: int = Field(default=60, ge=10, le=86_400)


class ActionSpec(_Model):
    key: str = Field(pattern=r"^[a-z0-9_]+\.[a-z0-9_]+$")
    tier: Tier
    reversible: bool = False
    params_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})


class Manifest(_Model):
    id: str = Field(pattern=r"^[a-z0-9_]+(\.[a-z0-9_]+)?$")
    name: str
    vendor: str
    category: Category
    version: str
    sdk: str
    certification: Literal["sandbox", "contract-tested", "live-verified"] = "sandbox"
    # P8 (ADR-0019): implements ``fetch_live`` against the vendor's real API (read-only).
    live_read: bool = False
    auth_types: list[str] = Field(default_factory=list)
    streams: list[StreamSpec] = Field(default_factory=list)
    webhook: bool = False
    actions: list[ActionSpec] = Field(default_factory=list)
    severity_map: dict[str, Severity] = Field(default_factory=dict)
    rate_limit_per_minute: int = Field(default=60, ge=1)
    config_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})
    secrets_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})
    docs_reference: str = ""

    def stream(self, name: str) -> StreamSpec:
        for s in self.streams:
            if s.name == name:
                return s
        raise KeyError(name)


# ------------------------------------------------------------------ fetching
class RawRecord(_Model):
    source_id: str = Field(min_length=1, max_length=256)
    observed_at: datetime
    schema_name: str = Field(alias="schema", min_length=1, max_length=120)
    payload: dict[str, Any]

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Checkpoint(_Model):
    cursor: dict[str, Any] = Field(default_factory=dict)


class FetchBudget(_Model):
    max_records: int = Field(default=500, ge=1, le=10_000)
    max_seconds: float = Field(default=20.0, gt=0, le=120)


class FetchResult(_Model):
    records: list[RawRecord]
    checkpoint: Checkpoint
    has_more: bool = False


class ConnectionResult(_Model):
    ok: bool
    detail: str


# ------------------------------------------------------------------ normalized output
class Observable(_Model):
    type: Literal["ip", "domain", "url", "sha256", "user", "hostname", "email", "process"]
    value: str = Field(max_length=2048)


class AssetRef(_Model):
    kind: Literal["hostname", "fqdn", "ip", "mac", "cloud_id", "agent_id", "serial", "upn"]
    value: str = Field(max_length=512)


class AlertV1(_Model):
    kind: Literal["alert"] = "alert"
    domain: Domain
    source_alert_id: str = Field(max_length=256)
    title: str = Field(min_length=1, max_length=500)
    description: str = Field(default="", max_length=8000)
    severity: Severity
    status: Literal["new", "acknowledged", "resolved"] = "new"
    category: str = Field(default="", max_length=100)
    observed_at: datetime
    asset_refs: list[AssetRef] = Field(default_factory=list, max_length=20)
    service_hint: str | None = Field(default=None, max_length=200)
    observables: list[Observable] = Field(default_factory=list, max_length=50)
    mitre_techniques: list[Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]] = Field(
        default_factory=list, max_length=20
    )
    labels: dict[str, str] = Field(default_factory=dict)
    # Stable identity for de-duplication: same key = same ongoing alert.
    dedup_key: str = Field(min_length=1, max_length=512)


class AssetV1(_Model):
    kind: Literal["asset"] = "asset"
    type: Literal[
        "host", "vm", "container", "network_device", "database", "application", "cloud_resource", "identity", "storage"
    ]
    name: str = Field(min_length=1, max_length=255)
    identifiers: list[AssetRef] = Field(min_length=1, max_length=20)
    environment: Literal["prod", "stage", "dev", "unknown"] = "unknown"
    attributes: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime


class VulnFindingV1(_Model):
    kind: Literal["vuln_finding"] = "vuln_finding"
    external_id: str = Field(max_length=256)
    vuln_id: str = Field(max_length=64)
    title: str = Field(max_length=500)
    severity: Severity
    cvss: float | None = Field(default=None, ge=0, le=10)
    epss: float | None = Field(default=None, ge=0, le=1)
    kev: bool = False
    status: Literal["open", "fixed"] = "open"
    asset_refs: list[AssetRef] = Field(min_length=1, max_length=20)
    observed_at: datetime


class SecurityEventV1(_Model):
    """OCSF-aligned subset: class_uid 2004 Detection Finding, 3002 Authentication,
    1007 Process Activity, 4001 Network Activity, 6003 API Activity."""

    kind: Literal["security_event"] = "security_event"
    class_uid: Literal[1007, 2004, 3002, 4001, 6003]
    activity: str = Field(max_length=100)
    severity: Severity
    observed_at: datetime
    message: str = Field(max_length=2000)
    actor_user: str | None = Field(default=None, max_length=256)
    device_hostname: str | None = Field(default=None, max_length=256)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    outcome: Literal["success", "failure", "unknown"] = "unknown"
    mitre_techniques: list[str] = Field(default_factory=list, max_length=20)


class MetricPointV1(_Model):
    kind: Literal["metric"] = "metric"
    name: str = Field(max_length=200)
    value: float
    unit: str = Field(default="", max_length=20)
    asset_ref: AssetRef
    observed_at: datetime


class TicketV1(_Model):
    kind: Literal["ticket"] = "ticket"
    external_id: str = Field(max_length=128)
    number: str = Field(max_length=64)
    state: str = Field(max_length=40)
    short_description: str = Field(max_length=500)
    observed_at: datetime


class ServiceV1(_Model):
    """A business service from a CMDB (SDK 1.1). ``members`` run the service; ``depends_on`` is
    infrastructure it needs (network, databases). ``aliases`` are application names that
    monitoring tools use as service hints."""

    kind: Literal["service"] = "service"
    external_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=200)
    tier: int = Field(default=3, ge=1, le=4)
    owner_team: str | None = Field(default=None, max_length=100)
    aliases: list[str] = Field(default_factory=list, max_length=20)
    members: list[AssetRef] = Field(default_factory=list, max_length=200)
    depends_on: list[AssetRef] = Field(default_factory=list, max_length=100)
    observed_at: datetime


NormalizedRecord = AlertV1 | AssetV1 | VulnFindingV1 | SecurityEventV1 | MetricPointV1 | TicketV1 | ServiceV1


# ------------------------------------------------------------------ actions
class ActionInvocation(_Model):
    key: str
    mode: Literal["dry_run", "simulate", "live"]
    target: dict[str, Any]
    params: dict[str, Any] = Field(default_factory=dict)


class ActionResult(_Model):
    status: Literal["succeeded", "failed"]
    mode: Literal["dry_run", "simulate", "live"]
    simulated: bool
    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)
    message: str = ""
