"""Correlation quality on the seeded scenarios (P3 exit: precision >= 0.9, recall >= 0.8).

Each scenario's real normalized alerts go through the pure engine. Services come from the
sandbox topology that the ServiceNow connector publishes. Scenarios are independent events
two hours apart (longer than any correlation window). Precision and recall are pairwise:
two alerts in the same predicted incident are a true pair if the ground truth puts them together.
"""

from __future__ import annotations

import itertools
import random
import uuid
from datetime import UTC, datetime, timedelta

from app.incidents.correlation import (
    AlertFacts,
    Candidate,
    Rule,
    absorb,
    decide,
    effective_rules,
    observable_keys,
    priority_for,
)
from app.incidents.sla import DEFAULT_TARGETS, compute_metrics, evaluate, merged_targets
from nocsoc_connector_sdk import AlertV1, ConnectorContext, World
from nocsoc_connectors import REGISTRY, SCENARIOS

TENANT = "00000000-0000-0000-0000-0000000000c1"
INSTANCE = "00000000-0000-0000-0000-0000000000c2"
T0 = datetime(2026, 11, 16, 0, 0, tzinfo=UTC)

# Ground truth: which scenarios must form exactly one incident, in which domain, with which services.
EXPECTED = {
    "core_switch_failure": ("noc", {"Payments", "Order Management"}),
    "db_cpu_saturation": ("noc", {"Order Management"}),
    "phishing_credential_misuse": ("soc", {"Identity (SSO)"}),
    "ransomware_precursor": ("joint", {"File Services"}),
}
NO_INCIDENT = {"noise_flapping", "adversarial_injection", "kev_exposure"}


def topology_index() -> tuple[dict[tuple[str, str], set[str]], dict[str, str]]:
    world = World.for_tenant(TENANT)
    by_ref: dict[tuple[str, str], set[str]] = {}
    alias: dict[str, str] = {}
    for svc in world.topology():
        for kind, value in [*svc["members"], *svc["depends_on"]]:
            by_ref.setdefault((kind, value.lower()), set()).add(svc["name"])
        for a in svc["aliases"]:
            alias[a] = svc["name"]
    return by_ref, alias


def facts(alert: AlertV1, at: datetime) -> AlertFacts:
    by_ref, alias = topology_index()
    services: set[str] = set()
    for ref in alert.asset_refs:
        services |= by_ref.get((ref.kind, ref.value.lower()), set())
    if alert.service_hint and alert.service_hint in alias:
        services.add(alias[alert.service_hint])
    asset = alert.asset_refs[0].value.lower() if alert.asset_refs else None
    return AlertFacts(
        id=str(uuid.uuid4()),
        domain=alert.domain,
        severity=alert.severity,
        observed_at=at,
        asset_id=asset,
        asset_name=asset,
        services=frozenset(services),
        observables=observable_keys(o.model_dump() for o in alert.observables),
        title=alert.title,
    )


def scenario_alerts(key: str) -> list[AlertV1]:
    out = []
    for cid in SCENARIOS[key].connectors:
        conn = REGISTRY[cid](ConnectorContext(tenant_id=TENANT, instance_id=INSTANCE))
        for stream, rec in conn.scenario_records(key, 0):
            out += [
                n for n in REGISTRY[cid].normalize(stream, rec) if isinstance(n, AlertV1) and n.status != "resolved"
            ]
    return out


def run(  # type: ignore[no-untyped-def]
    order: list[str],
    rules: tuple[Rule, ...] | None = None,
    gap: timedelta = timedelta(hours=2),
    seed: int | None = None,
):
    """Replays scenarios through the engine (alerts of a scenario in a shuffled order when
    ``seed`` is given). Returns (alert -> scenario, alert -> incident, open incidents)."""
    truth: dict[str, str] = {}
    placed: dict[str, str] = {}
    incidents: dict[str, Candidate] = {}
    pending: dict[str, AlertFacts] = {}  # recent alerts not in any incident yet
    for i, key in enumerate(order):
        at = T0 + gap * i
        alerts = scenario_alerts(key)
        if seed is not None:
            random.Random(seed * 1000 + i).shuffle(alerts)  # noqa: S311 - test ordering only
        for j, alert in enumerate(alerts):
            f = facts(alert, at + timedelta(seconds=j))
            truth[f.id] = key
            d = decide(f, incidents.values(), rules or effective_rules())
            if d.action == "create":
                cid = f"inc-{len(truth)}"
                incidents[cid] = Candidate(cid, f.domain, f.observed_at, opened_at=f.observed_at)
            elif d.action == "join":
                cid = d.incident_id  # type: ignore[assignment]
                if d.escalate_to_joint:
                    incidents[cid].domain = "joint"
                for mid in d.merge_ids:
                    gone = incidents.pop(mid)
                    keep = incidents[cid]
                    keep.assets |= gone.assets
                    keep.services |= gone.services
                    keep.observables |= gone.observables
                    keep.last_alert_at = max(keep.last_alert_at, gone.last_alert_at)
                    placed.update({a: cid for a, inc in placed.items() if inc == mid})
            else:
                pending[f.id] = f
                continue
            c = incidents[cid]
            c.last_alert_at = max(c.last_alert_at, f.observed_at)
            c.assets |= {f.asset_id} if f.asset_id else set()
            c.services |= f.services
            c.observables |= f.observables
            placed[f.id] = cid
            for taken, _rule, _why in absorb(c, pending.values(), rules or effective_rules()):
                placed[taken.id] = cid
                del pending[taken.id]
    return truth, placed, incidents


def pairwise(truth: dict[str, str], placed: dict[str, str]) -> tuple[float, float]:
    should = {k for k, s in truth.items() if s in EXPECTED}
    true_pairs = {frozenset(p) for p in itertools.combinations(should, 2) if truth[p[0]] == truth[p[1]]}
    predicted = {frozenset(p) for p in itertools.combinations(placed, 2) if placed[p[0]] == placed[p[1]]}
    # An alert from a no-incident scenario placed into an incident is a false positive pair-wise
    # (it pairs with every alert of that incident) and also counts below as a lone false incident.
    tp = len(true_pairs & predicted)
    precision = tp / len(predicted) if predicted else 1.0
    recall = tp / len(true_pairs) if true_pairs else 1.0
    return precision, recall


ALL = list(SCENARIOS)


def test_precision_and_recall_meet_exit_criteria() -> None:
    truth, placed, _ = run(ALL)
    precision, recall = pairwise(truth, placed)
    assert precision >= 0.9, precision
    assert recall >= 0.8, recall


def test_each_scenario_yields_expected_incident() -> None:
    for key in ALL:
        truth, placed, incidents = run([key])
        if key in NO_INCIDENT:
            assert not incidents, f"{key} must not open an incident"
            continue
        domain, services = EXPECTED[key]
        assert len(incidents) == 1, (key, len(incidents))
        (inc,) = incidents.values()
        assert inc.domain == domain, (key, inc.domain)
        assert inc.services >= services, (key, inc.services)
        assert set(placed) == set(truth), f"{key}: every alert joins the incident"


def test_core_switch_impacts_exactly_the_services_behind_it() -> None:
    _, _, incidents = run(["core_switch_failure"])
    (inc,) = incidents.values()
    assert inc.services == {"Payments", "Order Management"}


def test_noise_alone_never_opens_incidents_even_when_repeated() -> None:
    _, placed, incidents = run(["noise_flapping"] * 5, gap=timedelta(minutes=1))
    assert not incidents and not placed


def test_scenarios_far_apart_never_merge() -> None:
    _, _, incidents = run(["core_switch_failure", "core_switch_failure"], gap=timedelta(hours=3))
    assert len(incidents) == 2


def test_disabled_rule_changes_outcome() -> None:
    rules = effective_rules({"same_asset": (False, 60)})
    _, _, incidents = run(["ransomware_precursor"], rules)
    # Without same_asset, the NOC file-share alert cannot join the SOC incident.
    assert all(c.domain != "joint" for c in incidents.values())


def test_window_is_respected() -> None:
    alert = AlertFacts("a", "noc", "high", T0, "h1", "h1", frozenset(), frozenset(), "x")
    near = Candidate("i1", "noc", T0 - timedelta(minutes=59), assets={"h1"})
    far = Candidate("i2", "noc", T0 - timedelta(minutes=61), assets={"h1"})
    assert decide(alert, [near]).incident_id == "i1"
    assert decide(alert, [far]).action == "create"


def test_cross_domain_join_escalates_to_joint() -> None:
    alert = AlertFacts("a", "noc", "high", T0, "h1", "h1", frozenset(), frozenset(), "x")
    d = decide(alert, [Candidate("i1", "soc", T0, assets={"h1"})])
    assert d.action == "join" and d.escalate_to_joint and d.rule == "same_asset"
    d = decide(alert, [Candidate("i1", "joint", T0, assets={"h1"})])
    assert not d.escalate_to_joint


def test_priority_rules() -> None:
    assert priority_for("critical", None) == "P1"
    assert priority_for("high", 1) == "P1"
    assert priority_for("high", 2) == "P2"
    assert priority_for("medium", 1) == "P3"
    assert priority_for("low", None) == "P4"


def test_sla_evaluation_and_overrides() -> None:
    state = evaluate("P1", T0, T0 + timedelta(minutes=10), None, T0 + timedelta(hours=5))
    assert not state.ack_breached and state.resolve_breached
    assert state.ack_due_at == T0 + timedelta(minutes=DEFAULT_TARGETS["P1"]["ack"])
    custom = merged_targets({"P1": {"ack": 5}, "PX": {"ack": 1}})
    assert custom["P1"] == {"ack": 5, "resolve": 240} and "PX" not in custom


def test_mtta_mttr_and_sla_attainment_are_exact() -> None:
    from types import SimpleNamespace as R

    m = timedelta(minutes=1)
    rows = [
        # P1: acked after 10 min (target 15: met), resolved after 200 min (target 240: met)
        R(priority="P1", status="resolved", detected_at=T0, acknowledged_at=T0 + 10 * m, resolved_at=T0 + 200 * m),
        # P1: acked after 20 min (missed), resolved after 300 min (missed)
        R(priority="P1", status="closed", detected_at=T0, acknowledged_at=T0 + 20 * m, resolved_at=T0 + 300 * m),
        # P2: acked after 30 min (met exactly), still open, resolve deadline (480 min) not reached
        R(priority="P2", status="investigating", detected_at=T0, acknowledged_at=T0 + 30 * m, resolved_at=None),
        # P3: never acknowledged, ack deadline (240 min) passed
        R(priority="P3", status="open", detected_at=T0, acknowledged_at=None, resolved_at=None),
    ]
    out = compute_metrics(rows, merged_targets(None), now=T0 + 400 * m)
    assert out["total"] == 4 and out["open"] == 2 and out["acknowledged"] == 3 and out["resolved"] == 2
    assert out["mtta_seconds"] == (10 + 20 + 30) / 3 * 60
    assert out["mttr_seconds"] == (200 + 300) / 2 * 60
    assert out["ack_sla_attainment"] == 2 / 4  # met: 10, 30; missed: 20, never (deadline passed)
    assert out["resolve_sla_attainment"] == 1 / 2  # P2 still within window, P3 within 2880 min: not counted
    assert out["by_priority"] == {"P1": 2, "P2": 1, "P3": 1}


def test_outcome_does_not_depend_on_arrival_order() -> None:
    """Partitions deliver alerts in any order. Every order must yield the same incidents."""
    for seed in range(40):
        for key in EXPECTED:
            truth, placed, incidents = run([key], seed=seed)
            domain, services = EXPECTED[key]
            assert len(incidents) == 1, (key, seed, len(incidents))
            (inc,) = incidents.values()
            assert inc.domain == domain and inc.services >= services, (key, seed)
            assert set(placed) == set(truth)
        truth, placed, _ = run(ALL, seed=seed)
        precision, recall = pairwise(truth, placed)
        assert precision >= 0.9 and recall >= 0.8, (seed, precision, recall)


def test_bridging_alert_merges_open_incidents() -> None:
    t = T0
    a = Candidate("old", "noc", t, assets={"h1"}, services={"S1"}, opened_at=t - timedelta(minutes=5))
    b = Candidate("new", "noc", t, assets={"h2"}, services={"S2"}, opened_at=t)
    bridge = AlertFacts("x", "noc", "critical", t, "sw", "sw", frozenset({"S1", "S2"}), frozenset(), "switch down")
    d = decide(bridge, [b, a])
    assert (d.action, d.incident_id, d.merge_ids, d.rule) == ("join", "old", ("new",), "service_topology")
    manual = Candidate("manual", "noc", t, services={"S2"}, opened_at=t, auto=False)
    assert decide(bridge, [a, manual]).merge_ids == ()  # analyst-created incidents are never merged automatically
