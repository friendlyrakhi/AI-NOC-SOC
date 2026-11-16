"""ContractSuite for every connector (P2 exit criterion: all 16 connectors pass)."""

import asyncio
from datetime import UTC, datetime

import pytest

from nocsoc_connector_sdk import (
    ActionInvocation,
    AlertV1,
    AuthError,
    Checkpoint,
    ConnectorContext,
    ExecutionDisabledError,
    RateLimitedError,
    SchemaDriftError,
    TransientError,
)
from nocsoc_connector_sdk.testing import run_contract
from nocsoc_connectors import REGISTRY, SCENARIOS

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
TENANT = "00000000-0000-4000-8000-0000000000aa"


def ctx(instance: str = "i-1") -> ConnectorContext:
    return ConnectorContext(tenant_id=TENANT, instance_id=instance, clock=lambda: NOW)


def test_catalog_has_all_targets() -> None:
    assert len(REGISTRY) == 16
    assert {c.manifest.category for c in REGISTRY.values()} == {
        "observability",
        "cloud_monitoring",
        "siem",
        "edr",
        "vuln",
        "itsm",
        "generic",
    }
    assert all(c.manifest.certification == "sandbox" for c in REGISTRY.values())


@pytest.mark.parametrize("connector_id", sorted(REGISTRY))
def test_contract(connector_id: str) -> None:
    problems = asyncio.run(run_contract(REGISTRY[connector_id]))
    assert problems == [], problems


@pytest.mark.parametrize("connector_id", sorted(REGISTRY))
def test_live_mode_needs_a_runner_supplied_transport(connector_id: str) -> None:
    from nocsoc_connector_sdk import ConfigError

    with pytest.raises(ConfigError):
        REGISTRY[connector_id](ConnectorContext(tenant_id=TENANT, instance_id="x", mode="live"))


def test_same_tenant_connectors_share_one_estate() -> None:
    """Different tools describe the same hosts (enables cross-tool correlation in P3)."""
    sw = REGISTRY["solarwinds.orion"](ctx())
    pr = REGISTRY["prometheus"](ctx())
    assert sw.simulator.world.hosts == pr.simulator.world.hosts


def test_faults_raise_the_right_errors() -> None:
    def run(faults: dict[str, object]) -> None:
        conn = REGISTRY["datadog"](ctx(), {"sandbox_faults": faults})
        asyncio.run(conn.fetch("events", None))

    with pytest.raises(AuthError):
        run({"auth_failure": True})
    with pytest.raises(TransientError):
        run({"error_rate": 1.0})
    with pytest.raises(RateLimitedError):
        run({"rate_limit_rate": 1.0})


def test_schema_drift_is_detected_by_normalize() -> None:
    conn = REGISTRY["crowdstrike.falcon"](ctx(), {"sandbox_faults": {"schema_drift_rate": 1.0}})
    result = asyncio.run(conn.fetch("alerts", None))
    assert result.records
    with pytest.raises(SchemaDriftError):
        REGISTRY["crowdstrike.falcon"].normalize("alerts", result.records[0])


def test_checkpoint_resumes_without_gaps() -> None:
    conn = REGISTRY["prometheus"](ctx())
    first = asyncio.run(conn.fetch("alerts", Checkpoint(cursor={"since": "2026-11-16T10:00:00Z"})))
    later = REGISTRY["prometheus"](
        ConnectorContext(tenant_id=TENANT, instance_id="i-1", clock=lambda: NOW.replace(hour=13))
    )
    second = asyncio.run(later.fetch("alerts", first.checkpoint))
    assert first.records
    assert second.records
    assert min(r.observed_at for r in second.records) > max(r.observed_at for r in first.records)


@pytest.mark.parametrize("connector_id", [c for c in sorted(REGISTRY) if REGISTRY[c].manifest.actions])
def test_actions_are_simulated_and_live_is_blocked(connector_id: str) -> None:
    conn = REGISTRY[connector_id](ctx())
    action = conn.manifest.actions[0]
    with pytest.raises(ExecutionDisabledError):
        asyncio.run(conn.execute_action(ActionInvocation(key=action.key, mode="live", target={"host": "x"})))
    result = asyncio.run(conn.execute_action(ActionInvocation(key=action.key, mode="simulate", target={"host": "x"})))
    assert result.simulated is True


# ---------------------------------------------------------------- scenarios
def scenario_alerts(name: str) -> list[tuple[str, AlertV1]]:
    out = []
    for cid in SCENARIOS[name].connectors:
        cls = REGISTRY[cid]
        conn = cls(ctx())
        for stream, rec in conn.scenario_records(name, 0):
            for n in cls.normalize(stream, rec):
                if isinstance(n, AlertV1):
                    out.append((cid, n))
    return out


def test_core_switch_scenario_golden() -> None:
    alerts = scenario_alerts("core_switch_failure")
    by = {(cid, a.severity) for cid, a in alerts}
    assert ("solarwinds.orion", "critical") in by
    assert sum(1 for cid, a in alerts if cid == "prometheus" and a.title.startswith("TargetDown")) == 4
    assert any(cid == "datadog" and "payments-api" in a.title for cid, a in alerts)
    assert all(a.domain == "noc" for _, a in alerts)


def test_phishing_and_ransomware_scenarios_are_security() -> None:
    phish = scenario_alerts("phishing_credential_misuse")
    assert {cid for cid, _ in phish} == {"microsoft.defender", "microsoft.sentinel", "splunk"}
    assert any("T1566" in t for _, a in phish for t in a.mitre_techniques)
    ransom = scenario_alerts("ransomware_precursor")
    assert any("T1490" in a.mitre_techniques for _, a in ransom)
    assert {a.domain for _, a in ransom} == {"noc", "soc"}  # joint by construction


def test_noise_scenario_dedups_to_few_keys() -> None:
    alerts = scenario_alerts("noise_flapping")
    assert len(alerts) == 14
    assert len({a.dedup_key for _, a in alerts}) == 2


def test_injection_text_is_kept_as_data() -> None:
    alerts = scenario_alerts("adversarial_injection")
    assert any("Ignore all previous instructions" in a.title + a.description for _, a in alerts)


def test_kev_scenario_produces_known_exploited_findings() -> None:
    findings = []
    for cid in SCENARIOS["kev_exposure"].connectors:
        cls = REGISTRY[cid]
        for stream, rec in cls(ctx()).scenario_records("kev_exposure", 0):
            findings += cls.normalize(stream, rec)
    assert len(findings) == 5
    assert all(f.kev and f.vuln_id.startswith("CVE-DEMO-") for f in findings)  # type: ignore[union-attr]
