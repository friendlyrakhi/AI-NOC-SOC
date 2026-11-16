"""Runner behaviour under sandbox fault injection (P2 exit: health transitions)."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from connector_runner.bus import raw_topic
from connector_runner.health import FAILING_AFTER, InstanceHealth, TokenBucket
from connector_runner.scheduler import Scheduler
from nocsoc_connector_sdk import AuthError, RateLimitedError, TransientError

TENANT = str(uuid.UUID(int=1))


class FakeApi:
    def __init__(self, items: list[dict[str, Any]], secrets: dict[str, str] | None = None) -> None:
        self.items = items
        self.secrets = secrets or {}
        self.reports: list[tuple[str, dict[str, Any]]] = []

    async def work(self) -> list[dict[str, Any]]:
        return self.items

    async def credentials(self, instance_id: str) -> dict[str, str]:
        return self.secrets

    async def report(self, instance_id: str, body: dict[str, Any]) -> None:
        self.reports.append((instance_id, body))
        # Mirror the platform: remember the run so the next tick sees it, advance the checkpoint.
        for item in self.items:
            if str(item["instance_id"]) == instance_id:
                item["last_runs"][body["stream"]] = body["finished_at"]
                if body["cursor"] is not None:
                    item["checkpoints"][body["stream"]] = body["cursor"]


class MemoryBus:
    def __init__(self, fail: bool = False) -> None:
        self.messages: list[tuple[str, bytes, bytes]] = []
        self.fail = fail

    async def send(self, topic: str, key: bytes, value: bytes) -> None:
        if self.fail:
            raise ConnectionError("broker down")
        self.messages.append((topic, key, value))


def item(definition: str = "prometheus", faults: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    config: dict[str, Any] = {}
    if faults:
        config["sandbox_faults"] = faults
    return {
        "instance_id": str(uuid.uuid4()),
        "tenant_id": TENANT,
        "definition_id": definition,
        "mode": "sandbox",
        "config": config,
        "sync_requested_at": None,
        "checkpoints": {},
        "last_runs": {},
        **extra,
    }


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def reports_for(api: FakeApi, stream: str) -> list[dict[str, Any]]:
    return [b for _, b in api.reports if b["stream"] == stream]


def test_healthy_run_publishes_envelopes_and_checkpoints() -> None:
    it = item()
    api, bus = FakeApi([it]), MemoryBus()
    assert run(Scheduler(api, bus).tick()) == 2  # alerts + metrics
    alerts = reports_for(api, "alerts")[0]
    assert alerts["status"] == "succeeded" and alerts["health"] == "healthy"
    assert alerts["records"] > 0 and alerts["cursor"]
    topic, key, value = bus.messages[0]
    assert topic == raw_topic("prometheus") == "raw.prometheus"
    env = json.loads(value)
    assert key.decode() == f"{TENANT}:{it['instance_id']}"
    assert env["tenantid"] == TENANT and env["connector"] == "prometheus" and env["trigger"] == "schedule"
    assert env["data"]["schema"] and env["data"]["source_id"]


def test_not_due_until_interval_elapses_then_manual_sync_runs() -> None:
    it = item()
    api, bus = FakeApi([it]), MemoryBus()
    sched = Scheduler(api, bus)
    run(sched.tick())
    n = len(api.reports)
    assert run(sched.tick()) == 0  # within interval
    it["sync_requested_at"] = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
    assert run(sched.tick()) == 2
    assert {b["trigger"] for b in [b for _, b in api.reports[n:]]} == {"manual"}
    later = datetime.now(UTC) + timedelta(minutes=5)
    it["sync_requested_at"] = None
    assert run(sched.tick(later)) == 2


def test_auth_failure_is_failing_immediately_and_opens_circuit() -> None:
    it = item(faults={"auth_failure": True})
    api, bus = FakeApi([it]), MemoryBus()
    sched = Scheduler(api, bus)
    run(sched.tick())
    r = reports_for(api, "alerts")[0]
    assert (r["status"], r["health"], r["error_class"]) == ("failed", "failing", "AuthError")
    assert r["cursor"] is None and not bus.messages
    n = len(api.reports)
    run(sched.tick(datetime.now(UTC) + timedelta(minutes=2)))  # due again, but the circuit is open
    assert len(api.reports) == n


def test_transient_errors_degrade_then_fail_after_threshold() -> None:
    it = item(faults={"error_rate": 1.0})
    api, bus = FakeApi([it]), MemoryBus()
    sched = Scheduler(api, bus)
    states = []
    now = datetime.now(UTC)
    for i in range(FAILING_AFTER):
        for h in sched.health.get(it["instance_id"], {}).values():  # let the backoff elapse
            h.open_until = 0.0
        run(sched.tick(now + timedelta(minutes=2 * (i + 1))))
        states.append(reports_for(api, "alerts")[-1]["health"])
    assert states == ["degraded", "degraded", "failing"]


def test_rate_limited_source_is_degraded() -> None:
    it = item(faults={"rate_limit_rate": 1.0})
    api, bus = FakeApi([it]), MemoryBus()
    run(Scheduler(api, bus).tick())
    r = reports_for(api, "alerts")[0]
    assert (r["health"], r["error_class"]) == ("degraded", "RateLimitedError")


def test_schema_drift_is_published_but_degrades_health() -> None:
    it = item(faults={"schema_drift_rate": 1.0})
    api, bus = FakeApi([it]), MemoryBus()
    run(Scheduler(api, bus).tick())
    r = reports_for(api, "alerts")[0]
    assert r["status"] == "succeeded" and r["health"] == "degraded" and r["error_class"] == "SchemaDriftError"
    assert bus.messages  # evidence still reaches the worker, which dead-letters it


def test_recovery_after_faults_are_removed() -> None:
    it = item(faults={"auth_failure": True})
    api, bus = FakeApi([it]), MemoryBus()
    sched = Scheduler(api, bus)
    run(sched.tick())
    assert reports_for(api, "alerts")[-1]["health"] == "failing"
    it["config"] = {}  # operator fixes the configuration
    run(sched.tick(datetime.now(UTC) + timedelta(minutes=2)))
    assert reports_for(api, "alerts")[-1]["health"] == "healthy"


def test_bus_outage_does_not_blame_the_source() -> None:
    it = item()
    api, bus = FakeApi([it]), MemoryBus(fail=True)
    sched = Scheduler(api, bus)
    run(sched.tick())
    assert api.reports == []  # nothing published, nothing to checkpoint
    assert sched.instance_health(it["instance_id"]) == "healthy"


def test_refuses_non_sandbox_instances() -> None:
    it = item(mode="live")
    api, bus = FakeApi([it]), MemoryBus()
    run(Scheduler(api, bus).tick())
    assert all(b["status"] == "failed" for _, b in api.reports)
    assert not bus.messages


def test_webhook_only_connector_has_no_polling() -> None:
    assert Scheduler.due_streams(item("generic.webhook"), datetime.now(UTC)) == []


def test_removed_instances_are_forgotten() -> None:
    it = item()
    api, bus = FakeApi([it]), MemoryBus()
    sched = Scheduler(api, bus)
    run(sched.tick())
    api.items = []
    run(sched.tick())
    assert sched.health == {} and sched._connectors == {}


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (AuthError("x"), "failing"),
        (TransientError("x"), "degraded"),
        (RateLimitedError("x", 1), "degraded"),
        (RuntimeError("x"), "degraded"),
    ],
)
def test_health_state_machine(exc: Exception, expected: str) -> None:
    assert InstanceHealth().failure(exc, now=0) == expected


def test_token_bucket() -> None:
    b = TokenBucket(per_minute=2, updated=0.0)
    assert b.take(0.0) and b.take(0.0) and not b.take(0.0)
    assert b.take(30.0)  # one token refills in 30 s at 2/min
