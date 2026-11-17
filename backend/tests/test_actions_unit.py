"""Policy engine, playbook DSL and the "live mode impossible" release gate (SEC-ACT-03)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import ValidationError

from app.actions.catalog import catalog, raise_tier
from app.actions.dsl import validate_definition
from app.actions.policy import MAX_ACTIONS_PER_INCIDENT_HOUR, PolicyInput, decide
from app.actions.samples import SAMPLE_PLAYBOOKS
from app.config import Settings


def pi(key: str, **kw: Any) -> PolicyInput:
    return PolicyInput(action=catalog()[key], **{"mode": "simulate", "requested_by_type": "user", **kw})


@pytest.mark.parametrize(
    ("key", "decision", "approvals"),
    [
        ("platform.timeline_note", "auto", 0),  # T0
        ("itsm.create_incident", "auto", 0),  # T1
        ("aws.reboot_instance", "approve_1", 1),  # T2
        ("edr.isolate_host", "approve_2", 2),  # T3
    ],
)
def test_tiers_map_to_approvals(key: str, decision: str, approvals: int) -> None:
    d = decide(pi(key))
    assert (d.decision, d.required_approvals) == (decision, approvals)


def test_ai_requests_always_need_a_human() -> None:
    """SEC-ACT-07: even T0/T1 actions suggested by AI need an approval."""
    assert decide(pi("itsm.create_incident", requested_by_type="ai")).required_approvals == 1
    assert decide(pi("platform.timeline_note", requested_by_type="ai")).decision == "approve_1"
    assert decide(pi("edr.isolate_host", requested_by_type="ai")).required_approvals == 2


def test_live_mode_always_denied() -> None:
    for key in catalog():
        assert decide(pi(key, mode="live")).decision == "deny"


def test_kill_switch_denies_except_dry_runs() -> None:
    assert decide(pi("itsm.create_incident", kill_switch=True)).decision == "deny"
    assert decide(pi("edr.isolate_host", kill_switch=True, mode="dry_run")).decision == "auto"


def test_dry_runs_need_no_approval() -> None:
    assert decide(pi("edr.isolate_host", mode="dry_run")).decision == "auto"


def test_tenant_policy_and_criticality_raise_tier_only() -> None:
    assert raise_tier("T3", "T1") == "T3"  # cannot lower
    assert decide(pi("itsm.create_incident", tenant_tier_override="T3")).decision == "approve_2"
    assert decide(pi("aws.reboot_instance", target_criticality=5)).decision == "approve_2"
    assert decide(pi("itsm.create_incident", tenant_allowed=False)).decision == "deny"
    assert decide(pi("itsm.create_incident", require_justification=True)).decision == "deny"
    assert decide(pi("itsm.create_incident", require_justification=True, justification="ok")).decision == "auto"


def test_runaway_protection() -> None:
    """SEC-ACT-05: per-incident caps and loop detection."""
    assert (
        decide(pi("itsm.create_incident", incident_actions_last_hour=MAX_ACTIONS_PER_INCIDENT_HOUR)).decision == "deny"
    )
    assert "loop" in decide(pi("itsm.create_incident", same_action_target_last_10_min=3)).reasons[0]
    assert decide(pi("itsm.create_incident", integration_available=False)).decision == "deny"


def test_sample_playbooks_validate() -> None:
    for pb in SAMPLE_PLAYBOOKS:
        parsed, problems = validate_definition(pb["definition"])
        assert parsed is not None, (pb["key"], problems)


@pytest.mark.parametrize(
    ("definition", "problem"),
    [
        ({"steps": [{"id": "a", "action": "nope.nothing", "target": "incident"}]}, "unknown action"),
        ({"steps": [{"id": "a", "action": "edr.isolate_host", "target": "incident"}]}, "targets an asset"),
        (
            {"steps": [{"id": "a", "action": "platform.timeline_note", "target": "incident", "params": {"x": 1}}]},
            "params",
        ),
        (
            {
                "steps": [
                    {
                        "id": "a",
                        "action": "platform.timeline_note",
                        "target": "incident",
                        "params": {"text": "x"},
                        "requires": ["b"],
                    }
                ]
            },
            "not an earlier step",
        ),
        (
            {
                "steps": [
                    {"id": "a", "action": "platform.enrich_asset", "target": "incident.primary_asset"},
                    {"id": "a", "action": "platform.enrich_asset", "target": "incident.primary_asset"},
                ]
            },
            "duplicate",
        ),
        ({"steps": []}, "steps"),
        (
            {
                "steps": [
                    {"id": "a", "action": "platform.enrich_asset", "target": "incident.primary_asset", "run": "rm -rf"}
                ]
            },
            "Extra inputs",
        ),
    ],
)
def test_invalid_playbooks_rejected(definition: dict[str, Any], problem: str) -> None:
    parsed, problems = validate_definition(definition)
    assert parsed is None
    assert any(problem in p for p in problems), problems


def test_release_gate_live_execution_impossible() -> None:
    """SEC-ACT-03 (release gate): live execution is refused at every layer.

    1. Settings: "live" is not an accepted execution mode.
    2. Policy engine: denies every catalog action in live mode (above).
    3. Worker executor: refuses live mode and non-sandbox instances.
    4. Connector SDK: execute_action raises for live, for every connector action.
    """
    with pytest.raises(ValidationError, match="execution_mode"):
        Settings(execution_mode="live")  # type: ignore[arg-type]

    from nocsoc_connector_sdk import ActionInvocation, ConnectorContext, ExecutionDisabledError
    from nocsoc_connectors import REGISTRY
    from workflow_worker.executors import ExecutionRefusedError, execute_connector_action

    for key, action in catalog().items():
        if action.connector_id == "platform":
            continue
        spec = {
            "mode": "live",
            "instance": {"id": "x", "definition_id": action.connector_id, "mode": "sandbox"},
            "connector_id": action.connector_id,
            "tenant_id": "t",
            "action_key": key,
            "target": {},
            "params": {},
        }
        with pytest.raises(ExecutionRefusedError):
            asyncio.run(execute_connector_action(spec))
        live_instance = {**spec, "mode": "simulate", "instance": {**spec["instance"], "mode": "live"}}
        with pytest.raises(ExecutionRefusedError):
            asyncio.run(execute_connector_action(live_instance))
        conn = REGISTRY[action.connector_id](ConnectorContext(tenant_id="t", instance_id="i"))
        with pytest.raises(ExecutionDisabledError):
            asyncio.run(conn.execute_action(ActionInvocation(key=key, mode="live", target={})))


def test_simulated_execution_returns_before_and_after() -> None:
    from workflow_worker.executors import execute_connector_action

    spec = {
        "mode": "simulate",
        "instance": {"id": "i1", "definition_id": "crowdstrike.falcon", "mode": "sandbox", "config": {}},
        "connector_id": "crowdstrike.falcon",
        "tenant_id": "t",
        "action_key": "edr.isolate_host",
        "target": {"asset_id": "a1", "name": "win-01"},
        "params": {},
    }
    out = asyncio.run(execute_connector_action(spec))
    assert out["simulated"] is True and out["mode"] == "simulate" and out["status"] == "succeeded"
