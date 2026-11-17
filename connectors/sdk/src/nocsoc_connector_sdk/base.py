"""Connector base class (docs/06 §4)."""

from __future__ import annotations

import hashlib
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar, Literal

import yaml
from jsonschema import Draft202012Validator

from nocsoc_connector_sdk.errors import ConfigError, SchemaDriftError
from nocsoc_connector_sdk.execution import Certification, ConnectorMode, ExecutionMode, assert_execution_allowed
from nocsoc_connector_sdk.models import (
    ActionInvocation,
    ActionResult,
    Checkpoint,
    ConnectionResult,
    FetchBudget,
    FetchResult,
    Manifest,
    NormalizedRecord,
    RawRecord,
)
from nocsoc_connector_sdk.sandbox import Simulator, iso, parse_ts
from nocsoc_connector_sdk.transport import FaultConfig, LiveHttp, SandboxTransport, Transport

DEFAULT_BACKFILL = timedelta(hours=1)


def dig(item: Any, path: str, *, required: bool = False) -> Any:
    """Reads a dotted path ("properties.essentials.severity") from nested dicts."""
    value = item
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            if required:
                raise KeyError(path)
            return None
        value = value[part]
    return value


def utcnow() -> datetime:
    return datetime.now(UTC)


def load_manifest(path: Path) -> Manifest:
    return Manifest.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


@dataclass(frozen=True)
class ConnectorContext:
    tenant_id: str
    instance_id: str
    mode: Literal["sandbox", "live"] = "sandbox"
    clock: Callable[[], datetime] = utcnow
    # Fixed to simulate in this build; the platform setting rejects "live".
    platform_execution_mode: ExecutionMode = ExecutionMode.SIMULATE


@dataclass(frozen=True)
class Paged:
    """A list endpoint using the platform pagination convention:
    GET path?since&until&limit&page_token -> {items_key: [...], next_page_token}."""

    path: str
    items_key: str
    id_field: str
    ts_field: str
    schema: str


@dataclass
class _State:
    faults: FaultConfig = field(default_factory=FaultConfig)


class _NoTransport:
    """Live connectors read through LiveHttp; the sandbox transport interface is closed."""

    async def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        raise ConfigError("live connectors use LiveHttp")

    async def post_json(self, path: str, body: dict[str, Any]) -> Any:
        raise ConfigError("live connectors cannot write (live actions are disabled)")


class Connector(ABC):
    manifest: ClassVar[Manifest]
    streams: ClassVar[dict[str, Paged]] = {}
    simulator_cls: ClassVar[type[Simulator]]

    def __init__(
        self,
        ctx: ConnectorContext,
        config: dict[str, Any] | None = None,
        secrets: dict[str, str] | None = None,
        transport: Transport | None = None,
        http: LiveHttp | None = None,
    ) -> None:
        self.ctx = ctx
        self.config = dict(config or {})
        self._secrets = dict(secrets or {})
        self.http = http
        if ctx.mode == "live":
            # P8 (ADR-0019): live reads only, through the runner's egress-checked LiveHttp.
            if not self.manifest.live_read:
                raise ConfigError(f"{self.manifest.id} does not support live reads")
            if http is None:
                raise ConfigError("live mode requires the runner's live HTTP client")
            self.transport = transport or _NoTransport()
            return
        if transport is None:
            if ctx.mode != "sandbox":
                raise ConfigError("live mode requires a transport supplied by the runner")
            self.simulator = self.simulator_cls(ctx.tenant_id, ctx.instance_id)
            transport = SandboxTransport(
                routes=self.simulator.routes(),
                faults=FaultConfig.from_config(self.config.get("sandbox_faults")),
            )
        self.transport = transport

    def __repr__(self) -> str:  # never include secrets
        return f"<{type(self).__name__} {self.manifest.id} instance={self.ctx.instance_id} mode={self.ctx.mode}>"

    # ------------------------------------------------------------- lifecycle
    def validate_config(self) -> list[str]:
        validator = Draft202012Validator(self.manifest.config_schema)
        cfg = {k: v for k, v in self.config.items() if k != "sandbox_faults"}
        return [f"{'/'.join(map(str, e.path)) or 'config'}: {e.message}" for e in validator.iter_errors(cfg)]

    async def test_connection(self) -> ConnectionResult:
        problems = self.validate_config()
        if problems:
            return ConnectionResult(ok=False, detail="; ".join(problems))
        try:
            await self.transport.get_json("/__sandbox/ping" if self.ctx.mode == "sandbox" else "/")
        except Exception as exc:  # report class only, never payloads
            return ConnectionResult(ok=False, detail=f"{type(exc).__name__}: {exc}")
        return ConnectionResult(ok=True, detail=f"{self.manifest.name} reachable ({self.ctx.mode})")

    # ------------------------------------------------------------- pull
    async def fetch(self, stream: str, checkpoint: Checkpoint | None, budget: FetchBudget | None = None) -> FetchResult:
        if self.ctx.mode == "live":
            return await self.fetch_live(stream, checkpoint, budget or FetchBudget())
        spec = self.streams[stream]
        budget = budget or FetchBudget()
        now = self.ctx.clock()
        cursor = dict(checkpoint.cursor) if checkpoint else {}
        since = cursor.get("since") or iso(now - DEFAULT_BACKFILL)
        until = cursor.get("until") or iso(now)
        token = cursor.get("page_token")
        records: list[RawRecord] = []
        deadline = time.monotonic() + budget.max_seconds
        while True:
            limit = min(200, budget.max_records - len(records))
            params: dict[str, Any] = {"since": since, "until": until, "limit": limit}
            if token:
                params["page_token"] = token
            data = await self.transport.get_json(spec.path, params)
            if not isinstance(data, dict) or not isinstance(data.get(spec.items_key), list):
                raise SchemaDriftError(f"{spec.path}: missing '{spec.items_key}' list")
            for item in data[spec.items_key]:
                records.append(self._raw(spec, item, now))
            token = data.get("next_page_token")
            if not token or len(records) >= budget.max_records or time.monotonic() > deadline:
                break
        if token:
            return FetchResult(
                records=records,
                checkpoint=Checkpoint(cursor={"since": since, "until": until, "page_token": token}),
                has_more=True,
            )
        return FetchResult(records=records, checkpoint=Checkpoint(cursor={"since": until}), has_more=False)

    @staticmethod
    def _raw(spec: Paged, item: dict[str, Any], now: datetime) -> RawRecord:
        source_id = dig(item, spec.id_field)
        if source_id in (None, ""):
            source_id = "drift-" + hashlib.sha256(repr(sorted(item.items())).encode()).hexdigest()[:16]
        try:
            observed = parse_ts(dig(item, spec.ts_field, required=True))
        except (KeyError, ValueError, TypeError):
            observed = now
        return RawRecord(source_id=str(source_id), observed_at=observed, schema=spec.schema, payload=item)

    async def fetch_live(self, stream: str, checkpoint: Checkpoint | None, budget: FetchBudget) -> FetchResult:
        """Live read against the vendor's real API (P8). Connectors with ``live_read: true`` override
        this; the base refuses."""
        raise ConfigError(f"{self.manifest.id} does not support live reads")

    @classmethod
    def live_headers(cls, secrets: dict[str, str]) -> dict[str, str]:
        """Authentication headers for live reads. Default: ``bearer_token`` or ``api_token`` as a
        bearer token, or ``username``/``password`` as HTTP Basic. Connectors override for vendor schemes."""
        import base64

        token = secrets.get("bearer_token") or secrets.get("api_token")
        if token:
            return {"Authorization": f"Bearer {token}"}
        if secrets.get("username") and secrets.get("password"):
            basic = base64.b64encode(f"{secrets['username']}:{secrets['password']}".encode()).decode()
            return {"Authorization": f"Basic {basic}"}
        return {}

    def live_url(self, key: str) -> str:
        url = str(self.config.get(key) or "")
        if not url:
            raise ConfigError(f"live mode needs '{key}' in the configuration")
        return url

    # ------------------------------------------------------------- normalize (pure)
    @staticmethod
    @abstractmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        """Deterministic and side-effect free. Raise SchemaDriftError on unexpected payloads."""

    # ------------------------------------------------------------- push (optional)
    def parse_webhook(self, body: dict[str, Any]) -> list[tuple[str, RawRecord]]:
        """Returns [(stream, record)] for webhook-capable connectors."""
        raise ConfigError(f"{self.manifest.id} does not accept webhooks")

    # ------------------------------------------------------------- scenarios (sandbox)
    def scenario_records(self, scenario: str, step: int) -> list[tuple[str, RawRecord]]:
        if self.ctx.mode != "sandbox":
            raise ConfigError("scenarios exist only in sandbox mode")
        now = self.ctx.clock()
        out = []
        for stream, item in self.simulator.scenario_items(scenario, step, now):
            out.append((stream, self._raw(self.streams[stream], item, now)))
        return out

    # ------------------------------------------------------------- actions (guarded, not overridable)
    async def execute_action(self, invocation: ActionInvocation) -> ActionResult:
        spec = next((a for a in self.manifest.actions if a.key == invocation.key), None)
        if spec is None:
            raise ConfigError(f"unknown action {invocation.key}")
        assert_execution_allowed(
            ExecutionMode(invocation.mode),
            platform_mode=self.ctx.platform_execution_mode,
            connector_mode=ConnectorMode(self.ctx.mode),
            certification=Certification(self.manifest.certification),
        )
        if invocation.mode == "dry_run":
            return ActionResult(
                status="succeeded",
                mode="dry_run",
                simulated=True,
                message=f"Would run {spec.key} on {invocation.target}",
            )
        return self.simulate_action(invocation)

    def simulate_action(self, invocation: ActionInvocation) -> ActionResult:
        """Simulated outcome from sandbox state only. Must never use the transport."""
        target = str(invocation.target)
        before = self.simulator.state.get(target, {"state": "normal"}) if self.ctx.mode == "sandbox" else {}
        after = {"state": f"after:{invocation.key}"}
        if self.ctx.mode == "sandbox":
            self.simulator.state[target] = after
        return ActionResult(
            status="succeeded",
            mode="simulate",
            simulated=True,
            before=before,
            after=after,
            message=f"Simulated {invocation.key}",
        )
