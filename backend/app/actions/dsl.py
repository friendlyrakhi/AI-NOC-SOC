"""Playbook DSL (P5). A playbook is an ordered list of action steps run against an incident.

    steps:
      - id: isolate
        action: edr.isolate_host
        target: incident.primary_asset      # or "incident" for incident-targeted actions
        params: {}
        justification: "Ransomware precursor on the file server"
        requires: [note]                    # earlier steps that must have succeeded
        on_failure: stop                    # or continue

Validation happens at save time (and again at publish): unknown actions, bad parameters
(JSON Schema from the catalog), wrong target kinds, forward or unknown dependencies and
duplicate ids are all rejected. There are no loops, conditions on data, or free-form code.
"""

from __future__ import annotations

from typing import Any, Literal

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.actions.catalog import catalog

TARGETS = {"asset": {"incident.primary_asset"}, "incident": {"incident"}}
MAX_STEPS = 20


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,40}$")
    action: str = Field(max_length=80)
    target: Literal["incident", "incident.primary_asset"]
    params: dict[str, Any] = Field(default_factory=dict)
    justification: str = Field(default="", max_length=1000)
    requires: list[str] = Field(default_factory=list, max_length=MAX_STEPS)
    on_failure: Literal["stop", "continue"] = "stop"


class Definition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(default="", max_length=2000)
    approval_timeout_minutes: int = Field(default=30, ge=1, le=1440)
    steps: list[Step] = Field(min_length=1, max_length=MAX_STEPS)


def validate_definition(raw: Any) -> tuple[Definition | None, list[str]]:
    try:
        d = Definition.model_validate(raw)
    except ValidationError as exc:
        return None, [f"{'/'.join(map(str, e['loc'])) or 'definition'}: {e['msg']}" for e in exc.errors()]
    problems: list[str] = []
    seen: list[str] = []
    actions = catalog()
    for s in d.steps:
        if s.id in seen:
            problems.append(f"step {s.id}: duplicate id")
        action = actions.get(s.action)
        if action is None:
            problems.append(f"step {s.id}: unknown action {s.action!r}")
        else:
            if s.target not in TARGETS[action.target_kind]:
                problems.append(f"step {s.id}: {s.action} targets an {action.target_kind}, not {s.target!r}")
            for e in Draft202012Validator(action.params_schema).iter_errors(s.params):
                problems.append(f"step {s.id}: params {'/'.join(map(str, e.path)) or ''} {e.validator} check failed")
        for r in s.requires:
            if r not in seen:
                problems.append(f"step {s.id}: requires {r!r}, which is not an earlier step")
        seen.append(s.id)
    return (d if not problems else None), problems
