"""Action requests: creation, approval, claiming for execution, completion.

All functions run inside a tenant transaction (RLS). The database is the only source of truth
for whether an action may run: ``claim`` re-checks status, approvals, expiry and the kill switch
and atomically moves the request to ``executing``. Whatever a workflow carries in its input or
signals, nothing executes without a successful claim (threat model T21, SEC-ACT-01).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from jsonschema import Draft202012Validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.actions.catalog import CatalogAction, catalog
from app.actions.policy import PolicyDecision, PolicyInput, decide
from app.errors import ProblemError, not_found
from app.incidents import store as incident_store

MAX_PARAMS_BYTES = 4096


class ActionRefusedError(ProblemError):
    pass


@dataclass
class Created:
    row: dict[str, Any]
    decision: PolicyDecision


def _problem(code: str, title: str, detail: str, status: int = 422) -> ProblemError:
    return ProblemError(status, code, title, detail)


async def resolve_target(
    conn: AsyncConnection, action: CatalogAction, *, asset_id: UUID | None, incident_id: UUID | None
) -> tuple[dict[str, Any], int | None]:
    """Targets must be real objects of this tenant (SEC-ACT-06). Returns (target, criticality)."""
    if action.target_kind == "incident":
        if incident_id is None:
            raise _problem("action.target_required", "Incident required", f"{action.key} acts on an incident.")
        inc = (
            await conn.execute(text("SELECT id, number, title FROM incidents WHERE id = :i"), {"i": incident_id})
        ).one_or_none()
        if inc is None:
            raise not_found("Incident")
        return {"incident_id": str(inc.id), "ref": str(inc.id), "number": inc.number, "title": inc.title}, None
    if asset_id is None:
        raise _problem("action.target_required", "Asset required", f"{action.key} acts on an asset.")
    asset = (
        await conn.execute(
            text(
                "SELECT a.id, a.name, a.criticality, coalesce((SELECT jsonb_object_agg(i.kind, i.value) FROM "
                "asset_identifiers i WHERE i.asset_id = a.id), '{}'::jsonb) AS identifiers FROM assets a WHERE a.id "
                "= :i"
            ),
            {"i": asset_id},
        )
    ).one_or_none()
    if asset is None:
        raise not_found("Asset")
    return {"asset_id": str(asset.id), "name": asset.name, "identifiers": asset.identifiers}, asset.criticality


async def primary_asset(conn: AsyncConnection, incident_id: UUID) -> UUID | None:
    """The asset of the incident's most severe, earliest alert."""
    return (
        await conn.execute(
            text(
                "SELECT a.asset_id FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id "
                "WHERE ia.incident_id = :i AND a.asset_id IS NOT NULL "
                "ORDER BY severity_rank(a.severity), a.first_seen LIMIT 1"
            ),
            {"i": incident_id},
        )
    ).scalar_one_or_none()


async def create_request(
    conn: AsyncConnection,
    *,
    action_key: str,
    asset_id: UUID | None,
    incident_id: UUID | None,
    params: dict[str, Any],
    justification: str,
    mode: str,
    requested_by_type: str,
    requested_by: UUID | None,
    expiry_minutes: int,
    ai_run_id: UUID | None = None,
    workflow_run_id: UUID | None = None,
    step_id: str | None = None,
    idempotency_key: str | None = None,
) -> Created:
    if mode not in ("dry_run", "simulate"):
        raise ProblemError(
            422,
            "action.execution_disabled",
            "Live execution disabled",
            "Only dry_run and simulate are available in this build.",
        )
    if idempotency_key:
        existing = (
            await conn.execute(text("SELECT * FROM action_requests WHERE idempotency_key = :k"), {"k": idempotency_key})
        ).one_or_none()
        if existing is not None:
            row = dict(existing._mapping)
            return Created(row, PolicyDecision(**row["policy_decision"]))
    action = catalog().get(action_key)
    if action is None:
        raise _problem("action.unknown", "Unknown action", f"No action {action_key!r} in the catalog.")
    if len(json.dumps(params)) > MAX_PARAMS_BYTES:
        raise _problem("action.params_too_large", "Parameters too large", "Keep parameters under 4 KB.")
    errors = [
        f"{'/'.join(map(str, e.path)) or 'params'}: {e.validator}"
        for e in Draft202012Validator(action.params_schema).iter_errors(params)
    ]
    if errors:
        raise _problem("action.invalid_params", "Invalid parameters", "; ".join(errors))
    target, criticality = await resolve_target(conn, action, asset_id=asset_id, incident_id=incident_id)

    if requested_by_type == "ai":
        if ai_run_id is None:
            raise _problem(
                "action.ai_run_required", "AI run required", "AI-suggested actions must reference the AI run."
            )
        run = (await conn.execute(text("SELECT output FROM ai_runs WHERE id = :r"), {"r": ai_run_id})).one_or_none()
        suggested = {a["action_key"] for a in ((run.output or {}).get("suggested_actions") or [])} if run else set()
        if action_key not in suggested:
            raise _problem("action.not_suggested", "Not suggested", "That AI run did not suggest this action.")

    instance = None
    if action.connector_id != "platform":
        instance = (
            await conn.execute(
                text(
                    "SELECT id FROM connector_instances WHERE definition_id = :d AND enabled "
                    "ORDER BY created_at LIMIT 1"
                ),
                {"d": action.connector_id},
            )
        ).scalar_one_or_none()

    policy_row = (
        await conn.execute(
            text("SELECT tier_override, allowed, require_justification FROM action_policies WHERE action_key = :k"),
            {"k": action_key},
        )
    ).one_or_none()
    target_key = target.get("asset_id") or target.get("incident_id")
    counts = (
        await conn.execute(
            text(
                "SELECT "
                "(SELECT count(*) FROM action_requests WHERE CAST(:inc AS uuid) IS NOT NULL AND incident_id = :inc "
                " AND execution_mode = 'simulate' AND created_at > now() - interval '1 hour') AS per_incident, "
                "(SELECT count(*) FROM action_requests WHERE action_key = :k AND execution_mode = 'simulate' "
                " AND coalesce(target->>'asset_id', target->>'incident_id') = :t "
                " AND created_at > now() - interval '10 minutes') AS repeats, "
                "kill_switch_engaged() AS killed"
            ),
            {"inc": incident_id, "k": action_key, "t": target_key},
        )
    ).one()
    decision = decide(
        PolicyInput(
            action=action,
            mode=mode,
            requested_by_type=requested_by_type,  # type: ignore[arg-type]
            kill_switch=bool(counts.killed),
            tenant_allowed=policy_row.allowed if policy_row else True,
            tenant_tier_override=policy_row.tier_override if policy_row else None,
            require_justification=policy_row.require_justification if policy_row else False,
            justification=justification,
            target_criticality=criticality,
            incident_actions_last_hour=int(counts.per_incident),
            same_action_target_last_10_min=int(counts.repeats),
            integration_available=action.connector_id == "platform" or instance is not None,
        )
    )
    status = {"deny": "denied", "auto": "approved"}.get(decision.decision, "pending_approval")
    expires = datetime.now(UTC) + timedelta(minutes=expiry_minutes) if status == "pending_approval" else None
    inserted = (
        await conn.execute(
            text(
                "INSERT INTO action_requests (tenant_id, incident_id, workflow_run_id, step_id, action_key, "
                "connector_id, "
                "instance_id, target, params, tier, required_approvals, requested_by_type, requested_by, ai_run_id, "
                "justification, policy_decision, execution_mode, status, idempotency_key, expires_at) VALUES "
                "(app_tenant(), :inc, :run, :step, :k, :c, :inst, CAST(:t AS jsonb), CAST(:p AS jsonb), :tier, :req, "
                ":rbt, "
                ":rb, :ai, :j, CAST(:pd AS jsonb), :mode, :st, :idem, :exp) RETURNING *"
            ),
            {
                "inc": incident_id,
                "run": workflow_run_id,
                "step": step_id,
                "k": action_key,
                "c": action.connector_id,
                "inst": instance,
                "t": json.dumps(target),
                "p": json.dumps(params),
                "tier": decision.tier,
                "req": decision.required_approvals,
                "rbt": requested_by_type,
                "rb": requested_by,
                "ai": ai_run_id,
                "j": justification,
                "pd": json.dumps(decision.to_json()),
                "mode": mode,
                "st": status,
                "idem": idempotency_key,
                "exp": expires,
            },
        )
    ).one()
    if incident_id is not None:
        await incident_store.timeline(
            conn,
            incident_id,
            "action_requested",
            {
                "request_id": str(inserted.id),
                "action": action_key,
                "mode": mode,
                "tier": decision.tier,
                "decision": decision.decision,
                "by": requested_by_type,
                "reasons": decision.reasons,
            },
            actor_type="user" if requested_by_type in ("user", "ai") else "system",
            actor_id=requested_by,
        )
    return Created(dict(inserted._mapping), decision)


async def approve_or_deny(
    conn: AsyncConnection, request_id: UUID, *, approver: UUID, decision: str, comment: str, step_up_at: datetime
) -> dict[str, Any]:
    req = (
        await conn.execute(text("SELECT * FROM action_requests WHERE id = :i FOR UPDATE"), {"i": request_id})
    ).one_or_none()
    if req is None:
        raise not_found("Action request")
    if req.status != "pending_approval":
        raise ProblemError(409, "action.not_pending", "Not awaiting approval", f"The request is {req.status}.")
    if req.expires_at is not None and req.expires_at <= datetime.now(UTC):
        # The caller records the expiry in its own transaction (this one rolls back with the error).
        raise ProblemError(
            409, "action.expired", "Approval window closed", "This request expired and can no longer be approved."
        )
    if req.requested_by == approver:
        raise ProblemError(
            403, "action.self_approval", "Self-approval not allowed", "Another person must approve your request."
        )
    if (
        await conn.execute(
            text("SELECT 1 FROM approvals WHERE action_request_id = :i AND approver_id = :a"),
            {"i": request_id, "a": approver},
        )
    ).first():
        raise ProblemError(
            409, "action.already_decided", "Already decided", "You have already decided on this request."
        )
    await conn.execute(
        text(
            "INSERT INTO approvals (tenant_id, action_request_id, approver_id, decision, comment, step_up_at) "
            "VALUES (app_tenant(), :i, :a, :d, :c, :s)"
        ),
        {"i": request_id, "a": approver, "d": decision, "c": comment, "s": step_up_at},
    )
    approvals = (
        await conn.execute(
            text("SELECT count(*) FROM approvals WHERE action_request_id = :i AND decision = 'approve'"),
            {"i": request_id},
        )
    ).scalar_one()
    new_status = (
        "denied" if decision == "deny" else "approved" if approvals >= req.required_approvals else "pending_approval"
    )
    if new_status != req.status:
        await conn.execute(
            text("UPDATE action_requests SET status = :s, updated_at = now(), version = version + 1 WHERE id = :i"),
            {"s": new_status, "i": request_id},
        )
    if req.incident_id is not None:
        await incident_store.timeline(
            conn,
            req.incident_id,
            "approval",
            {
                "request_id": str(request_id),
                "action": req.action_key,
                "decision": decision,
                "approvals": int(approvals),
                "required": req.required_approvals,
                "status": new_status,
                "comment": comment,
            },
            actor_type="user",
            actor_id=approver,
        )
    return {
        "status": new_status,
        "approvals": int(approvals),
        "required": req.required_approvals,
        "workflow_id": req.temporal_workflow_id,
        "run_id": req.workflow_run_id,
    }


async def claim(conn: AsyncConnection, request_id: UUID) -> dict[str, Any]:
    """Atomically moves an approved request to ``executing`` after re-checking everything from
    the database. Raises ActionRefusedError otherwise."""
    req = (
        await conn.execute(text("SELECT * FROM action_requests WHERE id = :i FOR UPDATE"), {"i": request_id})
    ).one_or_none()
    if req is None:
        raise ActionRefusedError(404, "action.unknown_request", "Unknown request", "No such action request.")
    if req.execution_mode not in ("dry_run", "simulate"):
        raise ActionRefusedError(409, "action.execution_disabled", "Live execution disabled", "Refused.")
    if req.status != "approved":
        raise ActionRefusedError(409, "action.not_approved", "Not approved", f"The request is {req.status}.")
    approvals = (
        await conn.execute(
            text(
                "SELECT count(*) FILTER (WHERE decision = 'approve') AS ok, count(*) FILTER (WHERE decision = "
                "'deny') AS no, "
                "count(DISTINCT approver_id) FILTER (WHERE decision = 'approve' AND approver_id IS DISTINCT FROM "
                ":rb) AS distinct_ok "
                "FROM approvals WHERE action_request_id = :i"
            ),
            {"i": request_id, "rb": req.requested_by},
        )
    ).one()
    if approvals.no or approvals.distinct_ok < req.required_approvals:
        raise ActionRefusedError(
            409, "action.approvals_missing", "Approvals missing", "Required approvals are not recorded."
        )
    if req.execution_mode != "dry_run" and (await conn.execute(text("SELECT kill_switch_engaged()"))).scalar_one():
        await conn.execute(
            text(
                "UPDATE action_requests SET status = 'cancelled', error = 'Halted by the automation kill switch', "
                "updated_at = now(), version = version + 1 WHERE id = :i"
            ),
            {"i": request_id},
        )
        if req.incident_id is not None:
            await incident_store.timeline(
                conn,
                req.incident_id,
                "action_result",
                {
                    "request_id": str(request_id),
                    "action": req.action_key,
                    "status": "cancelled",
                    "detail": "Halted by the automation kill switch",
                },
            )
        raise ActionRefusedError(409, "action.kill_switch", "Kill switch engaged", "Automation is halted.")
    await conn.execute(
        text(
            "UPDATE action_requests SET status = 'executing', updated_at = now(), version = version + 1 WHERE id = :i"
        ),
        {"i": request_id},
    )
    instance = None
    if req.instance_id is not None:
        inst = (
            await conn.execute(
                text("SELECT id, definition_id, config, mode FROM connector_instances WHERE id = :i"),
                {"i": req.instance_id},
            )
        ).one_or_none()
        if inst is not None:
            instance = {
                "id": str(inst.id),
                "definition_id": inst.definition_id,
                "config": inst.config,
                "mode": inst.mode,
            }
    return {
        "request_id": str(req.id),
        "tenant_id": str(req.tenant_id),
        "action_key": req.action_key,
        "connector_id": req.connector_id,
        "instance": instance,
        "target": req.target,
        "params": req.params,
        "mode": req.execution_mode,
    }


async def complete(
    conn: AsyncConnection, request_id: UUID, *, status: str, result: dict[str, Any], error: str | None
) -> None:
    req = (
        await conn.execute(
            text("SELECT status, incident_id, action_key FROM action_requests WHERE id = :i FOR UPDATE"),
            {"i": request_id},
        )
    ).one_or_none()
    if req is None:
        raise not_found("Action request")
    if req.status != "executing":
        raise ProblemError(409, "action.not_executing", "Not executing", f"The request is {req.status}.")
    await conn.execute(
        text(
            "UPDATE action_requests SET status = :s, result = CAST(:r AS jsonb), error = :e, executed_at = now(), "
            "updated_at = now(), version = version + 1 WHERE id = :i"
        ),
        {"s": status, "r": json.dumps(result, default=str), "e": (error or None) and error[:1000], "i": request_id},
    )
    if req.incident_id is not None:
        await incident_store.timeline(
            conn,
            req.incident_id,
            "action_result",
            {
                "request_id": str(request_id),
                "action": req.action_key,
                "status": status,
                "simulated": bool(result.get("simulated", True)),
                "mode": result.get("mode"),
                "detail": (error or result.get("message") or "")[:300],
            },
        )


async def platform_execute(conn: AsyncConnection, spec: dict[str, Any]) -> dict[str, Any]:
    """Platform-native T0 actions. They only annotate or read inside the tenant."""
    key, target, params = spec["action_key"], spec["target"], spec["params"]
    if key == "platform.timeline_note":
        if spec["mode"] == "dry_run":
            return {
                "status": "succeeded",
                "mode": "dry_run",
                "simulated": True,
                "message": "Would add a note to the timeline.",
            }
        await incident_store.timeline(
            conn, target["incident_id"], "comment", {"text": params["text"], "source": "playbook"}, actor_type="system"
        )
        return {
            "status": "succeeded",
            "mode": spec["mode"],
            "simulated": False,
            "message": "Note added to the timeline.",
        }
    if key == "platform.enrich_asset":
        info = (
            await conn.execute(
                text(
                    "SELECT a.name, a.type, a.environment, a.criticality, "
                    "coalesce((SELECT array_agg(s.name) FROM service_assets sa JOIN services s ON s.id = sa.service_id "
                    "          WHERE sa.asset_id = a.id), '{}') AS services, "
                    "(SELECT count(*) FROM alerts x WHERE x.asset_id = a.id AND x.status NOT IN "
                    "('resolved','closed','suppressed')) "
                    "AS open_alerts FROM assets a WHERE a.id = :i"
                ),
                {"i": target["asset_id"]},
            )
        ).one()
        return {
            "status": "succeeded",
            "mode": spec["mode"],
            "simulated": False,
            "after": {
                "name": info.name,
                "type": info.type,
                "environment": info.environment,
                "criticality": info.criticality,
                "services": list(info.services),
                "open_alerts": info.open_alerts,
            },
            "message": f"Enriched {info.name}.",
        }
    raise ActionRefusedError(422, "action.unknown", "Unknown platform action", key)
