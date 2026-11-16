"""Connector testing kit (docs/06 §9).

``run_contract(cls)`` returns a list of problems (empty = compliant). It checks the manifest,
module hygiene (no direct network imports), sandbox fetch with pagination and checkpoints,
normalize purity and determinism, test_connection, and the action guard.
"""

from __future__ import annotations

import ast
import inspect
from datetime import UTC, datetime
from typing import Any

from nocsoc_connector_sdk.base import Connector, ConnectorContext
from nocsoc_connector_sdk.errors import ConnectorError
from nocsoc_connector_sdk.execution import ExecutionDisabledError
from nocsoc_connector_sdk.models import ActionInvocation, Checkpoint, FetchBudget, Manifest

FORBIDDEN_IMPORTS = {"requests", "httpx", "socket", "urllib.request", "aiohttp", "http.client", "subprocess"}
OUTPUT_KIND = {
    "alert@1": "alert",
    "asset@1": "asset",
    "vuln_finding@1": "vuln_finding",
    "security_event@1": "security_event",
    "metric@1": "metric",
    "ticket@1": "ticket",
}
FIXED_NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


def _ctx(clock: datetime = FIXED_NOW) -> ConnectorContext:
    return ConnectorContext(
        tenant_id="00000000-0000-4000-8000-000000000001", instance_id="contract", clock=lambda: clock
    )


def _imports(cls: type) -> set[str]:
    tree = ast.parse(inspect.getsource(inspect.getmodule(cls)))  # type: ignore[arg-type]
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


async def run_contract(cls: type[Connector], config: dict[str, Any] | None = None) -> list[str]:
    problems: list[str] = []
    m = cls.manifest
    if not isinstance(m, Manifest):  # runtime guard: third-party connectors are not type-checked
        return ["manifest is not a Manifest"]  # type: ignore[unreachable]

    bad = {
        i
        for i in _imports(cls)
        if i in FORBIDDEN_IMPORTS or i.split(".")[0] in {"requests", "httpx", "aiohttp", "socket"}
    }
    if bad:
        problems.append(f"direct network imports are not allowed: {sorted(bad)}")

    stream_names = {s.name for s in m.streams}
    if stream_names != set(cls.streams):
        problems.append(f"manifest streams {sorted(stream_names)} != implemented {sorted(cls.streams)}")
    for s in m.streams:
        if s.output not in OUTPUT_KIND:
            problems.append(f"stream {s.name}: unknown output {s.output}")
    if m.webhook and cls.parse_webhook is Connector.parse_webhook:
        problems.append("manifest declares webhook but parse_webhook is not implemented")

    conn = cls(_ctx(), config or {})
    if conn.validate_config():
        problems.append(f"default config invalid: {conn.validate_config()}")
    if not (await conn.test_connection()).ok:
        problems.append("test_connection failed in sandbox")

    for s in m.streams:
        first = await conn.fetch(s.name, None)
        if not first.records:
            problems.append(f"stream {s.name}: no records in a 1-hour sandbox window")
            continue
        # Normalize: valid output kinds, deterministic, pure.
        for rec in first.records[:50]:
            try:
                a = cls.normalize(s.name, rec)
                b = cls.normalize(s.name, rec)
            except ConnectorError as exc:
                problems.append(f"stream {s.name}: normalize raised {type(exc).__name__}")
                break
            if a != b:
                problems.append(f"stream {s.name}: normalize is not deterministic")
                break
            if any(r.kind != OUTPUT_KIND[s.output] for r in a):
                problems.append(f"stream {s.name}: normalize produced {[r.kind for r in a]} for output {s.output}")
                break
        # Checkpoint: re-fetching from the checkpoint at the same time returns nothing new.
        again = await conn.fetch(s.name, first.checkpoint)
        if again.records:
            problems.append(f"stream {s.name}: checkpoint not monotonic ({len(again.records)} duplicate records)")
        # Pagination: small pages cover the same records without duplicates.
        seen: list[str] = []
        cp: Checkpoint | None = None
        for _ in range(500):
            page = await conn.fetch(s.name, cp, FetchBudget(max_records=3))
            seen.extend(r.source_id for r in page.records)
            cp = page.checkpoint
            if not page.has_more:
                break
        if sorted(seen) != sorted(r.source_id for r in first.records):
            problems.append(f"stream {s.name}: paginated fetch differs from single fetch")

    # Determinism across instances of the same tenant at the same time.
    if m.streams:
        s0 = m.streams[0].name
        r1 = await cls(_ctx(), config or {}).fetch(s0, None)
        r2 = await cls(_ctx(), config or {}).fetch(s0, None)
        if [r.payload for r in r1.records] != [r.payload for r in r2.records]:
            problems.append("sandbox data is not deterministic")

    for action in m.actions:
        try:
            await conn.execute_action(ActionInvocation(key=action.key, mode="live", target={"id": "x"}))
            problems.append(f"action {action.key}: live mode was not blocked")
        except ExecutionDisabledError:
            pass
        result = await conn.execute_action(ActionInvocation(key=action.key, mode="simulate", target={"id": "x"}))
        if not result.simulated or result.mode != "simulate":
            problems.append(f"action {action.key}: simulate did not return a simulated result")

    return problems
