"""Policy engine (ADR-0010, docs/02 §5.4). Pure: same inputs, same decision.

Decisions: ``deny``, ``auto`` (no approval), ``approve_1`` or ``approve_2`` (two distinct
approvers). Rules, in order:

1. Live execution is never allowed in this build (SEC-ACT-03).
2. The kill switch denies everything except dry runs (SEC-ACT-05).
3. A tenant may forbid an action, or require a justification.
4. Runaway protection: per-incident hourly cap and repeat (loop) detection (SEC-ACT-05).
5. Dry runs change nothing, so they need no approval.
6. Tier (raised by tenant policy and by a critical target asset) sets the approvals:
   T0/T1 auto, T2 one approver, T3 two approvers.
7. AI-originated requests always need at least one human approval (SEC-ACT-07).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

from app.actions.catalog import TIERS, CatalogAction, Tier, raise_tier

Decision = Literal["deny", "auto", "approve_1", "approve_2"]

MAX_ACTIONS_PER_INCIDENT_HOUR = 20
MAX_REPEATS_10_MIN = 3


@dataclass(frozen=True)
class PolicyInput:
    action: CatalogAction
    mode: str
    requested_by_type: Literal["user", "ai", "playbook"]
    kill_switch: bool = False
    tenant_allowed: bool = True
    tenant_tier_override: str | None = None
    require_justification: bool = False
    justification: str = ""
    target_criticality: int | None = None
    incident_actions_last_hour: int = 0
    same_action_target_last_10_min: int = 0
    integration_available: bool = True


@dataclass
class PolicyDecision:
    decision: Decision
    tier: Tier
    required_approvals: int
    reasons: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, object]:
        return asdict(self)


def _deny(tier: Tier, reason: str) -> PolicyDecision:
    return PolicyDecision("deny", tier, 0, [reason])


def decide(i: PolicyInput) -> PolicyDecision:
    tier = raise_tier(i.action.tier, i.tenant_tier_override)
    reasons: list[str] = []
    if i.tenant_tier_override and tier != i.action.tier:
        reasons.append(f"Tenant policy raises {i.action.key} from {i.action.tier} to {tier}.")
    if i.target_criticality is not None and i.target_criticality >= 4 and tier != "T3":
        tier = TIERS[TIERS.index(tier) + 1]
        reasons.append(f"Target asset criticality {i.target_criticality} raises the tier to {tier}.")

    if i.mode not in ("dry_run", "simulate"):
        return _deny(tier, "Live execution is disabled in this build.")
    if i.kill_switch and i.mode != "dry_run":
        return _deny(tier, "The automation kill switch is engaged.")
    if not i.tenant_allowed:
        return _deny(tier, f"Tenant policy does not allow {i.action.key}.")
    if not i.integration_available:
        return _deny(tier, f"No enabled integration can perform {i.action.key}.")
    if i.require_justification and not i.justification.strip():
        return _deny(tier, "Tenant policy requires a justification for this action.")
    if i.incident_actions_last_hour >= MAX_ACTIONS_PER_INCIDENT_HOUR:
        return _deny(tier, f"More than {MAX_ACTIONS_PER_INCIDENT_HOUR} actions on this incident in the last hour.")
    if i.same_action_target_last_10_min >= MAX_REPEATS_10_MIN:
        return _deny(tier, "The same action on the same target repeated too often (possible loop).")

    if i.mode == "dry_run":
        return PolicyDecision("auto", tier, 0, [*reasons, "Dry run: nothing changes, so no approval is needed."])

    required = {"T0": 0, "T1": 0, "T2": 1, "T3": 2}[tier]
    reasons.append(f"Tier {tier} needs {required} approval(s)." if required else f"Tier {tier} runs without approval.")
    if i.requested_by_type == "ai" and required == 0:
        required = 1
        reasons.append("Suggested by AI: a human must approve.")
    decision: Decision = "auto" if required == 0 else "approve_1" if required == 1 else "approve_2"
    return PolicyDecision(decision, tier, required, reasons)
