"""Action catalog (docs/03 §2.8): every action a request or playbook may name.

Connector actions come from the connector manifests; two platform-native actions (T0) annotate
and enrich without touching any external system. Tenants may raise a tier, never lower it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Literal

from nocsoc_connectors import REGISTRY

Tier = Literal["T0", "T1", "T2", "T3"]
TargetKind = Literal["asset", "incident"]
TIERS: tuple[Tier, ...] = ("T0", "T1", "T2", "T3")

TIER_TEXT = {
    "T0": "read-only or annotation",
    "T1": "low impact, reversible (ticketing, silencing)",
    "T2": "service-affecting (restart, scan)",
    "T3": "high impact (isolation, containment)",
}

# Actions that act on an incident rather than an asset.
INCIDENT_TARGETED = {
    "itsm.create_incident",
    "itsm.update_incident",
    "itsm.create_change",
    "sentinel.update_incident",
    "splunk.update_notable",
}


@dataclass(frozen=True)
class CatalogAction:
    key: str
    connector_id: str  # "platform" for native actions
    tier: Tier
    reversible: bool
    target_kind: TargetKind
    params_schema: dict[str, Any] = field(default_factory=dict)
    description: str = ""


PLATFORM_ACTIONS = (
    CatalogAction(
        "platform.timeline_note",
        "platform",
        "T0",
        True,
        "incident",
        {
            "type": "object",
            "properties": {"text": {"type": "string", "minLength": 1, "maxLength": 2000}},
            "required": ["text"],
            "additionalProperties": False,
        },
        "Add a note to the incident timeline.",
    ),
    CatalogAction(
        "platform.enrich_asset",
        "platform",
        "T0",
        True,
        "asset",
        {"type": "object", "properties": {}, "additionalProperties": False},
        "Collect asset details, services and open alerts into the incident timeline.",
    ),
)


@lru_cache(maxsize=1)
def catalog() -> dict[str, CatalogAction]:
    out = {a.key: a for a in PLATFORM_ACTIONS}
    for cid, cls in sorted(REGISTRY.items()):
        for a in cls.manifest.actions:
            schema = dict(a.params_schema or {"type": "object", "properties": {}})
            schema.setdefault("additionalProperties", False)
            out[a.key] = CatalogAction(
                key=a.key,
                connector_id=cid,
                tier=a.tier,
                reversible=a.reversible,
                target_kind="incident" if a.key in INCIDENT_TARGETED else "asset",
                params_schema=schema,
                description=f"{cls.manifest.name}: {a.key.split('.', 1)[1].replace('_', ' ')}",
            )
    return out


def raise_tier(base: Tier, override: str | None) -> Tier:
    """Tenant overrides can only make an action stricter."""
    if override in TIERS and TIERS.index(override) > TIERS.index(base):
        return override
    return base
