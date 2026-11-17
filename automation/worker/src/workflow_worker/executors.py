"""Connector action execution: sandbox instances only, dry_run or simulate only (SEC-ACT-03).

The connector SDK independently refuses live execution (``assert_execution_allowed``), so even
a bug here could not reach a real system: there is no live transport in this build either.
"""

from __future__ import annotations

from typing import Any

from nocsoc_connector_sdk import ActionInvocation, ConnectorContext
from nocsoc_connectors import REGISTRY

ALLOWED_MODES = ("dry_run", "simulate")


class ExecutionRefusedError(Exception):
    pass


async def execute_connector_action(spec: dict[str, Any]) -> dict[str, Any]:
    if spec["mode"] not in ALLOWED_MODES:
        raise ExecutionRefusedError("live execution is disabled")
    instance = spec.get("instance")
    if not instance:
        raise ExecutionRefusedError("no connector instance for this action")
    if instance.get("mode") != "sandbox":
        raise ExecutionRefusedError("only sandbox connector instances can execute in this build")
    cls = REGISTRY.get(spec["connector_id"])
    if cls is None or cls.manifest.id != instance["definition_id"]:
        raise ExecutionRefusedError("connector mismatch")
    connector = cls(
        ConnectorContext(tenant_id=spec["tenant_id"], instance_id=instance["id"], mode="sandbox"),
        instance.get("config") or {},
    )
    result = await connector.execute_action(
        ActionInvocation(key=spec["action_key"], mode=spec["mode"], target=spec["target"], params=spec["params"])
    )
    return result.model_dump()
