"""SLA targets and evaluation. MTTA = acknowledged - detected; MTTR = resolved - detected."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

# Minutes per priority. A tenant can replace these (sla_policies); missing keys fall back here.
DEFAULT_TARGETS: dict[str, dict[str, int]] = {
    "P1": {"ack": 15, "resolve": 240},
    "P2": {"ack": 30, "resolve": 480},
    "P3": {"ack": 240, "resolve": 2880},
    "P4": {"ack": 1440, "resolve": 10080},
}


def merged_targets(custom: dict[str, Any] | None) -> dict[str, dict[str, int]]:
    out = {p: dict(v) for p, v in DEFAULT_TARGETS.items()}
    for p, v in (custom or {}).items():
        if p in out and isinstance(v, dict):
            out[p].update({k: int(v[k]) for k in ("ack", "resolve") if k in v})
    return out


@dataclass(frozen=True)
class SlaState:
    ack_due_at: datetime
    resolve_due_at: datetime
    ack_breached: bool
    resolve_breached: bool


def evaluate(
    priority: str,
    detected_at: datetime,
    acknowledged_at: datetime | None,
    resolved_at: datetime | None,
    now: datetime,
    targets: dict[str, dict[str, int]] | None = None,
) -> SlaState:
    t = (targets or DEFAULT_TARGETS)[priority]
    ack_due = detected_at + timedelta(minutes=t["ack"])
    resolve_due = detected_at + timedelta(minutes=t["resolve"])
    return SlaState(
        ack_due_at=ack_due,
        resolve_due_at=resolve_due,
        ack_breached=(acknowledged_at or now) > ack_due,
        resolve_breached=(resolved_at or now) > resolve_due,
    )


TERMINAL = ("resolved", "closed")


def compute_metrics(rows: Sequence[Any], targets: dict[str, dict[str, int]], now: datetime) -> dict[str, Any]:
    """KPIs over incident rows (priority, status, detected_at, acknowledged_at, resolved_at).

    - MTTA: mean of (acknowledged - detected) over acknowledged incidents.
    - MTTR: mean of (resolved - detected) over resolved incidents.
    - SLA attainment counts only incidents whose outcome is known: the target was met, or its
      deadline has already passed. Incidents still inside their window are not counted yet.
    """
    acked = [r for r in rows if r.acknowledged_at]
    resolved = [r for r in rows if r.resolved_at]
    ack_met = ack_due = res_met = res_due = 0
    by_priority: dict[str, int] = {}
    for r in rows:
        by_priority[r.priority] = by_priority.get(r.priority, 0) + 1
        s = evaluate(r.priority, r.detected_at, r.acknowledged_at, r.resolved_at, now, targets)
        if r.acknowledged_at or now > s.ack_due_at:
            ack_due += 1
            ack_met += not s.ack_breached
        if r.resolved_at or now > s.resolve_due_at:
            res_due += 1
            res_met += not s.resolve_breached
    return {
        "total": len(rows),
        "open": sum(1 for r in rows if r.status not in TERMINAL),
        "acknowledged": len(acked),
        "resolved": len(resolved),
        "mtta_seconds": sum((r.acknowledged_at - r.detected_at).total_seconds() for r in acked) / len(acked)
        if acked
        else None,
        "mttr_seconds": sum((r.resolved_at - r.detected_at).total_seconds() for r in resolved) / len(resolved)
        if resolved
        else None,
        "ack_sla_attainment": ack_met / ack_due if ack_due else None,
        "resolve_sla_attainment": res_met / res_due if res_due else None,
        "by_priority": by_priority,
    }
