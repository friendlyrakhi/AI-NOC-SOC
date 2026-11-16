"""Correlation rules (docs/02 §6, docs/03 §2.6). Pure and deterministic.

Each new alert is compared with open incidents whose latest alert is recent. Rules are tried in
order; the first match wins and the most recently active incident breaks ties:

1. ``same_asset`` (any domain, 60 min): the alert's asset is already in the incident.
2. ``service_topology`` (NOC alerts, 30 min): the alert's asset runs, or is infrastructure for,
   a service the incident already impacts.
3. ``shared_observable`` (SOC alerts, 60 min): the alert shares a user, IP, hash or host with
   the incident's alerts.

An alert from the other domain turns the incident **joint** (NOC and SOC both see it).
Without a match, a critical or high alert opens a new incident; a medium, low or info alert on
its own does not, because opening incidents for noise is what correlation is meant to prevent.
If an alert matches several open correlation-created incidents under the same rule, it bridges
them: they merge into the oldest, so the outcome does not depend on the order alerts arrive in.
Every decision carries the rule and a reason sentence, which go to the incident timeline.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

Domain = Literal["noc", "soc", "joint"]

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
OPENING_SEVERITIES = frozenset({"critical", "high"})
# Observable types that identify an entity across tools. Processes and URLs are too generic.
CORRELATING_OBSERVABLES = frozenset({"user", "ip", "sha256", "hostname", "email", "domain"})


@dataclass(frozen=True)
class Rule:
    key: str
    title: str
    description: str
    window_minutes: int
    enabled: bool = True


BUILTIN_RULES: tuple[Rule, ...] = (
    Rule("same_asset", "Same asset", "Alerts on an asset already in an open incident join it (any domain).", 60),
    Rule(
        "service_topology",
        "Service topology",
        "NOC alerts on assets that run, or are infrastructure for, an impacted service join that incident.",
        30,
    ),
    Rule(
        "shared_observable",
        "Shared observable",
        "SOC alerts sharing a user, IP, hash or host with an open incident join it.",
        60,
    ),
)
RULE_KEYS = frozenset(r.key for r in BUILTIN_RULES)


def effective_rules(overrides: Mapping[str, tuple[bool, int]] | None = None) -> tuple[Rule, ...]:
    """Built-in rules with per-tenant ``{key: (enabled, window_minutes)}`` overrides applied."""
    overrides = overrides or {}
    out = []
    for r in BUILTIN_RULES:
        if r.key in overrides:
            enabled, window = overrides[r.key]
            r = Rule(r.key, r.title, r.description, window, enabled)
        out.append(r)
    return tuple(out)


@dataclass(frozen=True)
class AlertFacts:
    id: str
    domain: Literal["noc", "soc"]
    severity: str
    observed_at: datetime
    asset_id: str | None
    asset_name: str | None
    # Services the asset runs (member) or supports (dependency), plus any service named by the
    # alert's service hint.
    services: frozenset[str]
    observables: frozenset[str]  # "type:value", lower-cased
    title: str


@dataclass
class Candidate:
    id: str
    domain: Domain
    last_alert_at: datetime
    assets: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    observables: set[str] = field(default_factory=set)
    opened_at: datetime | None = None  # detection time; the oldest match survives a merge
    auto: bool = True  # created by correlation (only those may be merged automatically)


@dataclass(frozen=True)
class Decision:
    action: Literal["join", "create", "none"]
    incident_id: str | None = None
    rule: str | None = None
    reason: str = ""
    escalate_to_joint: bool = False
    # Other open incidents the alert also matches under the same rule: this alert bridges them,
    # so they are merged into ``incident_id``. Makes the result independent of arrival order.
    merge_ids: tuple[str, ...] = ()


def observable_keys(observables: Iterable[Mapping[str, str]]) -> frozenset[str]:
    return frozenset(
        f"{o['type']}:{str(o['value']).strip().lower()}"
        for o in observables
        if o.get("type") in CORRELATING_OBSERVABLES and o.get("value")
    )


def _within(alert: AlertFacts, c: Candidate, minutes: int) -> bool:
    return abs(alert.observed_at - c.last_alert_at) <= timedelta(minutes=minutes)


def _match(rule: Rule, alert: AlertFacts, c: Candidate) -> str | None:
    """A reason sentence if ``rule`` links the alert to candidate ``c``, else None."""
    if not rule.enabled or not _within(alert, c, rule.window_minutes):
        return None
    if rule.key == "same_asset":
        if alert.asset_id and alert.asset_id in c.assets:
            return f"Same asset ({alert.asset_name or alert.asset_id}) as alerts already in the incident."
    elif rule.key == "service_topology":
        if alert.domain == "noc" and c.domain in ("noc", "joint"):
            shared = alert.services & c.services
            if shared:
                return f"Asset is part of, or supports, an impacted service ({len(shared)} shared)."
    elif rule.key == "shared_observable" and alert.domain == "soc" and c.domain in ("soc", "joint"):
        shared = alert.observables & c.observables
        if shared:
            return "Shares " + ", ".join(sorted(shared)[:3]) + " with the incident."
    return None


def decide(alert: AlertFacts, candidates: Iterable[Candidate], rules: tuple[Rule, ...] = BUILTIN_RULES) -> Decision:
    pool = list(candidates)
    for rule in rules:
        matches = [(c, why) for c in pool if (why := _match(rule, alert, c))]
        if not matches:
            continue
        # The oldest matching incident survives; correlation-created others merge into it.
        matches.sort(key=lambda m: (m[0].opened_at or m[0].last_alert_at, m[0].id))
        primary, reason = matches[0]
        merged = tuple(c.id for c, _ in matches[1:] if c.auto)
        domains = {alert.domain, primary.domain} | {c.domain for c, _ in matches[1:] if c.auto}
        joint = primary.domain != "joint" and len(domains) > 1
        if merged:
            reason += f" Bridges {len(merged)} other open incident(s), which are merged."
        return Decision("join", primary.id, rule.key, reason, joint, merged)
    if alert.severity in OPENING_SEVERITIES:
        return Decision(
            "create", reason=f"New {alert.severity} {alert.domain.upper()} alert with no related open incident."
        )
    return Decision("none", reason="Below the severity that opens an incident, and no related open incident.")


def absorb(
    incident: Candidate, pending: Iterable[AlertFacts], rules: tuple[Rule, ...] = BUILTIN_RULES
) -> list[tuple[AlertFacts, str, str]]:
    """Recent alerts that arrived before ``incident`` existed (or before it grew) and match it
    now: [(alert, rule, reason)]. Repeats until nothing more matches, updating ``incident`` as
    it goes, so a chain of related alerts is pulled in regardless of arrival order."""
    remaining = sorted(pending, key=lambda a: (a.observed_at, a.id))
    taken: list[tuple[AlertFacts, str, str]] = []
    changed = True
    while changed:
        changed = False
        for alert in list(remaining):
            for rule in rules:
                reason = _match(rule, alert, incident)
                if reason:
                    taken.append((alert, rule.key, reason))
                    remaining.remove(alert)
                    if alert.asset_id:
                        incident.assets.add(alert.asset_id)
                    incident.services |= alert.services
                    incident.observables |= alert.observables
                    incident.last_alert_at = max(incident.last_alert_at, alert.observed_at)
                    if incident.domain != "joint" and alert.domain != incident.domain:
                        incident.domain = "joint"
                    changed = True
                    break
    return taken


# ---------------------------------------------------------------- priority and SLA
def priority_for(severity: str, best_service_tier: int | None) -> str:
    """P1 for critical, or high on a tier-1 service; then P2 high, P3 medium, P4 otherwise."""
    if severity == "critical" or (severity == "high" and best_service_tier == 1):
        return "P1"
    return {"high": "P2", "medium": "P3"}.get(severity, "P4")


def max_severity(a: str, b: str) -> str:
    return a if SEVERITY_RANK.get(a, 9) <= SEVERITY_RANK.get(b, 9) else b


def max_priority(a: str, b: str) -> str:
    return min(a, b)  # "P1" < "P2" < ...
