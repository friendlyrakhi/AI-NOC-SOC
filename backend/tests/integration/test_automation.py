"""P5 against a real Temporal server and the real workflow worker (simulate mode only).

Exit criteria: two distinct approvers for T3, no self-approval, expired approvals rejected,
a dead worker's workflow resumes, the kill switch halts runs at the next activity, and
SEC-ACT-01..07 (including the live-mode release gate).
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import psycopg
import pytest
from psycopg import errors
from support.automation import AutomationEnv

pytestmark = pytest.mark.integration

ADMIN = {"globex": "admin@globex.example", "initech": "admin@initech.example"}
APPROVERS = {
    "globex": ("approver.one@globex.example", "approver.two@globex.example"),
    "initech": ("approver.one@initech.example", "approver.two@initech.example"),
}


def as_user(a: AutomationEnv, email: str, slug: str, *, step_up: bool = False) -> str:
    a.api.switch(email, slug)
    if step_up:
        a.api.step_up(email)
    return email


def scenario(a: AutomationEnv, slug: str, name: str = "host", criticality: int = 3) -> dict[str, str]:
    """An asset with a high alert, and an incident linking it (created through the API)."""
    t = a.env.tenants[slug]
    with a.env.su() as c:
        asset = c.execute(
            "INSERT INTO assets (tenant_id, type, name, criticality) VALUES (%s, 'host', %s, %s) RETURNING id",
            (t, f"{name}-{uuid.uuid4().hex[:6]}", criticality),
        ).fetchone()[0]
        alert = c.execute(
            "INSERT INTO alerts (tenant_id, domain, connector_id, source_alert_id, fingerprint, title, severity, "
            "asset_id, "
            "first_seen, last_seen) VALUES (%s, 'soc', 'crowdstrike.falcon', %s, %s, 'Suspicious process', 'high', %s, "
            "now(), now()) RETURNING id",
            (t, uuid.uuid4().hex, uuid.uuid4().hex, asset),
        ).fetchone()[0]
    admin = as_user(a, ADMIN[slug], slug)
    r = a.api.post(
        admin, "/incidents", {"title": f"P5 {name}", "domain": "soc", "severity": "high", "alert_ids": [str(alert)]}
    )
    assert r.status_code == 201, r.text
    return {"asset_id": str(asset), "incident_id": r.json()["id"]}


def request(a: AutomationEnv, slug: str, body: dict[str, Any], email: str | None = None) -> Any:
    email = as_user(a, email or ADMIN[slug], slug)
    return a.api.post(email, "/actions/requests", body)


def decide(a: AutomationEnv, slug: str, email: str, request_id: str, verb: str = "approve") -> Any:
    as_user(a, email, slug, step_up=True)
    return a.api.post(email, f"/actions/requests/{request_id}/{verb}", {"comment": "test"})


# ---------------------------------------------------------------- tiers and approvals
def test_t0_runs_without_approval(automation: AutomationEnv) -> None:
    s = scenario(automation, "globex", "enrich")
    r = request(
        automation,
        "globex",
        {"action_key": "platform.enrich_asset", "asset_id": s["asset_id"], "incident_id": s["incident_id"]},
    )
    assert r.status_code == 201, r.text
    assert r.json()["policy_decision"]["decision"] == "auto"
    done = automation.wait_request(ADMIN["globex"], r.json()["id"], {"succeeded", "failed"})
    assert done["status"] == "succeeded" and done["result"]["after"]["name"].startswith("enrich-")


def test_t2_needs_one_approval_and_blocks_self_approval(automation: AutomationEnv) -> None:
    s = scenario(automation, "globex", "web")
    r = request(
        automation,
        "globex",
        {"action_key": "aws.reboot_instance", "asset_id": s["asset_id"], "incident_id": s["incident_id"]},
    )
    req = r.json()
    assert req["status"] == "pending_approval" and req["required_approvals"] == 1
    own = decide(automation, "globex", ADMIN["globex"], req["id"])
    assert own.status_code == 403 and own.json()["code"] == "action.self_approval"
    ok = decide(automation, "globex", APPROVERS["globex"][0], req["id"])
    assert ok.status_code == 200 and ok.json()["status"] in ("approved", "executing", "succeeded")
    done = automation.wait_request(ADMIN["globex"], req["id"], {"succeeded", "failed"})
    assert done["status"] == "succeeded"
    assert done["result"]["simulated"] is True and done["result"]["mode"] == "simulate"
    timeline = automation.api.get(ADMIN["globex"], f"/incidents/{s['incident_id']}/timeline").json()
    assert {"action_requested", "approval", "action_result"} <= {e["kind"] for e in timeline}


def test_t3_needs_two_distinct_approvers(automation: AutomationEnv) -> None:
    """Exit criterion + SEC-ACT-02."""
    s = scenario(automation, "initech", "fs")
    req = request(
        automation,
        "initech",
        {"action_key": "edr.isolate_host", "asset_id": s["asset_id"], "incident_id": s["incident_id"]},
    ).json()
    assert req["status"] == "pending_approval" and req["required_approvals"] == 2
    one, two = APPROVERS["initech"]
    first = decide(automation, "initech", one, req["id"])
    assert first.json()["status"] == "pending_approval"
    again = decide(automation, "initech", one, req["id"])
    assert again.status_code == 409 and again.json()["code"] == "action.already_decided"
    inbox_one = automation.api.get(one, "/approvals/inbox").json()
    assert req["id"] not in {x["id"] for x in inbox_one}  # already decided by them
    inbox_two = automation.api.get(as_user(automation, two, "initech"), "/approvals/inbox").json()
    assert req["id"] in {x["id"] for x in inbox_two}
    decide(automation, "initech", two, req["id"])
    done = automation.wait_request(ADMIN["initech"], req["id"], {"succeeded", "failed"})
    assert done["status"] == "succeeded" and len(done["approvals"]) == 2


def test_self_approval_blocked_in_database(automation: AutomationEnv) -> None:
    s = scenario(automation, "globex", "db")
    req = request(
        automation,
        "globex",
        {"action_key": "aws.reboot_instance", "asset_id": s["asset_id"], "incident_id": s["incident_id"]},
    ).json()
    admin_id = automation.env.users[ADMIN["globex"]]["id"]
    with automation.env.su() as c, pytest.raises(errors.InsufficientPrivilege):
        c.execute(
            "INSERT INTO approvals (tenant_id, action_request_id, approver_id, decision, step_up_at) "
            "VALUES (%s, %s, %s, 'approve', now())",
            (automation.env.tenants["globex"], req["id"], admin_id),
        )


def test_expired_approvals_are_rejected(automation: AutomationEnv) -> None:
    s = scenario(automation, "globex", "exp")
    req = request(
        automation,
        "globex",
        {"action_key": "aws.reboot_instance", "asset_id": s["asset_id"], "incident_id": s["incident_id"]},
    ).json()
    with automation.env.su() as c:
        c.execute("UPDATE action_requests SET expires_at = now() - interval '1 minute' WHERE id = %s", (req["id"],))
    late = decide(automation, "globex", APPROVERS["globex"][0], req["id"])
    assert late.status_code == 409 and late.json()["code"] == "action.expired"
    assert automation.api.get(ADMIN["globex"], f"/actions/requests/{req['id']}").json()["status"] == "expired"


def test_dry_run_previews_without_approval(automation: AutomationEnv) -> None:
    s = scenario(automation, "initech", "dry")
    req = request(
        automation, "initech", {"action_key": "edr.isolate_host", "asset_id": s["asset_id"], "mode": "dry_run"}
    ).json()
    assert req["policy_decision"]["decision"] == "auto"
    done = automation.wait_request(ADMIN["initech"], req["id"], {"succeeded", "failed"})
    assert done["result"]["mode"] == "dry_run" and "Would run" in done["result"]["message"]


# ---------------------------------------------------------------- SEC-ACT-01: no bypass of the claim
def test_worker_cannot_execute_unapproved_requests(automation: AutomationEnv) -> None:
    s = scenario(automation, "globex", "bypass")
    req = request(automation, "globex", {"action_key": "aws.reboot_instance", "asset_id": s["asset_id"]}).json()
    base = f"/api/v1/internal/workflow/actions/{req['id']}/claim"
    assert automation.api.client.post(base).status_code == 401
    assert automation.api.client.post(base, headers={"X-Workflow-Token": "wrong"}).status_code == 401
    token = automation.settings.workflow_token.get_secret_value()  # type: ignore[union-attr]
    claim = automation.api.client.post(base, headers={"X-Workflow-Token": token}).json()
    assert claim["claimed"] is False and claim["code"] == "action.not_approved"

    from workflow_worker.activities import Activities
    from workflow_worker.api import WorkflowApi

    async def direct() -> dict[str, Any]:
        api = WorkflowApi(automation.api_url, token)
        try:
            return await Activities(api).execute_action(req["id"])
        finally:
            await api.close()

    assert asyncio.run(direct())["status"] == "refused"
    # Forging an "approved" status without approval rows still cannot execute.
    with automation.env.su() as c:
        c.execute("UPDATE action_requests SET status = 'approved' WHERE id = %s", (req["id"],))
    forged = automation.api.client.post(base, headers={"X-Workflow-Token": token}).json()
    assert forged["claimed"] is False and forged["code"] == "action.approvals_missing"


# ---------------------------------------------------------------- SEC-ACT-03: live mode impossible
def test_live_mode_rejected_everywhere(automation: AutomationEnv) -> None:
    s = scenario(automation, "globex", "live")
    r = request(
        automation, "globex", {"action_key": "platform.enrich_asset", "asset_id": s["asset_id"], "mode": "live"}
    )
    assert r.status_code == 422 and r.json()["code"] == "action.execution_disabled"
    pb = next(p for p in automation.api.get(ADMIN["globex"], "/playbooks").json() if p["key"] == "enrich-and-ticket")
    r = automation.api.post(
        ADMIN["globex"], f"/playbooks/{pb['id']}/run", {"incident_id": s["incident_id"], "mode": "live"}
    )
    assert r.status_code == 422
    with automation.env.su() as c, pytest.raises(errors.CheckViolation):
        c.execute(
            "INSERT INTO action_requests (tenant_id, action_key, connector_id, tier, required_approvals, "
            "requested_by_type, "
            "policy_decision, execution_mode, status) VALUES (%s, 'x', 'x', 'T0', 0, 'user', '{}', 'live', 'approved')",
            (automation.env.tenants["globex"],),
        )


# ---------------------------------------------------------------- SEC-ACT-06: parameters and targets
def test_parameters_and_targets_validated(automation: AutomationEnv) -> None:
    s = scenario(automation, "globex", "params")
    bad = request(
        automation,
        "globex",
        {"action_key": "platform.enrich_asset", "asset_id": s["asset_id"], "params": {"cmd": "rm -rf /"}},
    )
    assert bad.status_code == 422 and bad.json()["code"] == "action.invalid_params"
    other = scenario(automation, "initech", "foreign")
    foreign = request(automation, "globex", {"action_key": "platform.enrich_asset", "asset_id": other["asset_id"]})
    assert foreign.status_code == 404
    unknown = request(automation, "globex", {"action_key": "shell.exec", "asset_id": s["asset_id"]})
    assert unknown.status_code == 422 and unknown.json()["code"] == "action.unknown"


def test_asset_action_on_incident_targets_its_primary_asset(automation: AutomationEnv) -> None:
    s = scenario(automation, "globex", "primary")
    body = {"action_key": "platform.enrich_asset", "incident_id": s["incident_id"], "mode": "dry_run"}
    req = request(automation, "globex", body)
    assert req.status_code == 201, req.text
    assert req.json()["target"]["asset_id"] == s["asset_id"]


# ---------------------------------------------------------------- SEC-ACT-05: runaway protection
def test_repeated_action_on_same_target_is_denied(automation: AutomationEnv) -> None:
    s = scenario(automation, "globex", "loop")
    body = {"action_key": "platform.enrich_asset", "asset_id": s["asset_id"]}
    statuses = [request(automation, "globex", body).json()["status"] for _ in range(4)]
    assert statuses[:3] != ["denied"] * 3 and statuses[3] == "denied"


# ---------------------------------------------------------------- SEC-ACT-07: AI only suggests
def test_ai_suggested_action_needs_human_approval(automation: AutomationEnv) -> None:
    s = scenario(automation, "initech", "ai")
    admin = as_user(automation, ADMIN["initech"], "initech")
    run = automation.api.post(admin, f"/ai/incidents/{s['incident_id']}/triage").json()
    suggested = [x["action_key"] for x in run["output"]["suggested_actions"]]
    assert suggested, run
    req = request(
        automation,
        "initech",
        {
            "action_key": suggested[0],
            "asset_id": s["asset_id"],
            "incident_id": s["incident_id"],
            "ai_run_id": run["id"],
        },
    ).json()
    assert req["requested_by_type"] == "ai" and req["required_approvals"] >= 1 and req["status"] == "pending_approval"
    not_suggested = request(
        automation,
        "initech",
        {"action_key": "platform.enrich_asset", "asset_id": s["asset_id"], "ai_run_id": run["id"]},
    )
    assert not_suggested.status_code == 422 and not_suggested.json()["code"] == "action.not_suggested"


def test_api_keys_cannot_approve(automation: AutomationEnv) -> None:
    admin = as_user(automation, ADMIN["globex"], "globex", step_up=True)
    key = automation.api.post(
        admin, "/api-keys", {"name": "bot", "permissions": ["action:read", "action:approve"]}
    ).json()["key"]
    s = scenario(automation, "globex", "bot")
    req = request(automation, "globex", {"action_key": "aws.reboot_instance", "asset_id": s["asset_id"]}).json()
    r = automation.api.client.post(
        f"/api/v1/actions/requests/{req['id']}/approve", json={}, headers={"Authorization": f"Bearer {key}"}
    )
    assert r.status_code == 403  # approvals need a person with a recent step-up


# ---------------------------------------------------------------- playbooks, kill switch, durability
def _playbook(a: AutomationEnv, slug: str, key: str) -> dict[str, Any]:
    return next(p for p in a.api.get(ADMIN[slug], "/playbooks").json() if p["key"] == key)


def test_enrich_and_ticket_playbook_runs_end_to_end(automation: AutomationEnv) -> None:
    s = scenario(automation, "globex", "pb")
    admin = as_user(automation, ADMIN["globex"], "globex")
    pb = _playbook(automation, "globex", "enrich-and-ticket")
    run = automation.api.post(
        admin, f"/playbooks/{pb['id']}/run", {"incident_id": s["incident_id"], "mode": "simulate"}
    ).json()
    done = automation.wait_run(admin, run["id"], lambda r: r["status"] != "running")
    assert done["status"] == "succeeded", done
    assert {k: v["status"] for k, v in done["steps"].items()} == {
        "note": "succeeded",
        "enrich": "succeeded",
        "ticket": "succeeded",
    }


def test_kill_switch_halts_run_at_next_activity(automation: AutomationEnv) -> None:
    s = scenario(automation, "globex", "ks")
    admin = as_user(automation, ADMIN["globex"], "globex", step_up=True)
    pb = _playbook(automation, "globex", "restart-unhealthy-service")
    run = automation.api.post(
        admin, f"/playbooks/{pb['id']}/run", {"incident_id": s["incident_id"], "mode": "simulate"}
    ).json()
    waiting = automation.wait_run(
        admin, run["id"], lambda r: r["steps"].get("restart", {}).get("status") == "awaiting_approval"
    )
    request_id = waiting["steps"]["restart"]["request_id"]
    on = automation.api.post(admin, "/killswitch", {"engaged": True, "reason": "test"})
    assert on.status_code == 200 and on.json()["engaged"] is True
    try:
        decide(automation, "globex", APPROVERS["globex"][0], request_id)
        done = automation.wait_run(admin, run["id"], lambda r: r["status"] != "running")
        assert done["status"] == "halted"
        req = automation.api.get(admin, f"/actions/requests/{request_id}").json()
        assert req["status"] == "cancelled" and "kill switch" in req["error"]
        blocked = request(automation, "globex", {"action_key": "platform.enrich_asset", "asset_id": s["asset_id"]})
        assert blocked.json()["status"] == "denied"
    finally:
        as_user(automation, ADMIN["globex"], "globex", step_up=True)
        automation.api.post(ADMIN["globex"], "/killswitch", {"engaged": False, "reason": "test done"})


def test_worker_killed_mid_run_resumes(automation: AutomationEnv) -> None:
    """Exit criterion: the run is waiting for T3 approval when the worker dies; approvals arrive
    while no worker is running; a new worker picks the run up and finishes it."""
    s = scenario(automation, "initech", "resume")
    admin = as_user(automation, ADMIN["initech"], "initech")
    pb = _playbook(automation, "initech", "contain-host")
    run = automation.api.post(
        admin, f"/playbooks/{pb['id']}/run", {"incident_id": s["incident_id"], "mode": "simulate"}
    ).json()
    waiting = automation.wait_run(
        admin, run["id"], lambda r: r["steps"].get("isolate", {}).get("status") == "awaiting_approval"
    )
    request_id = waiting["steps"]["isolate"]["request_id"]
    automation.worker.stop()
    try:
        for approver in APPROVERS["initech"]:
            r = decide(automation, "initech", approver, request_id)
            assert r.status_code == 200, r.text
        assert automation.api.get(admin, f"/workflow-runs/{run['id']}").json()["status"] == "running"
    finally:
        automation.worker.start()
    done = automation.wait_run(admin, run["id"], lambda r: r["status"] != "running")
    assert done["status"] == "succeeded", done
    assert done["steps"]["isolate"]["status"] == "succeeded" and done["steps"]["ticket"]["status"] == "succeeded"


def test_denied_step_stops_the_run(automation: AutomationEnv) -> None:
    s = scenario(automation, "globex", "deny")
    admin = as_user(automation, ADMIN["globex"], "globex")
    pb = _playbook(automation, "globex", "restart-unhealthy-service")
    run = automation.api.post(
        admin, f"/playbooks/{pb['id']}/run", {"incident_id": s["incident_id"], "mode": "simulate"}
    ).json()
    waiting = automation.wait_run(
        admin, run["id"], lambda r: r["steps"].get("restart", {}).get("status") == "awaiting_approval"
    )
    decide(automation, "globex", APPROVERS["globex"][1], waiting["steps"]["restart"]["request_id"], "deny")
    done = automation.wait_run(admin, run["id"], lambda r: r["status"] != "running")
    assert done["status"] == "failed" and done["steps"]["restart"]["status"] == "denied"


# ---------------------------------------------------------------- SEC-ACT-04: playbook versions
def test_published_versions_are_immutable(automation: AutomationEnv) -> None:
    admin = as_user(automation, ADMIN["globex"], "globex")
    pb = _playbook(automation, "globex", "enrich-and-ticket")
    definition = pb["versions"][0]["definition"]
    bad = automation.api.post(
        admin,
        f"/playbooks/{pb['id']}/versions",
        {"definition": {"steps": [{"id": "x", "action": "shell.exec", "target": "incident"}]}},
    )
    assert bad.status_code == 422
    v2 = automation.api.post(
        admin, f"/playbooks/{pb['id']}/versions", {"definition": {**definition, "description": "v2"}}
    )
    assert v2.status_code == 201
    new_version = max(v["version"] for v in v2.json()["versions"])
    assert (
        automation.api.post(admin, f"/playbooks/{pb['id']}/versions/{new_version}/publish").status_code == 403
    )  # step-up
    as_user(automation, admin, "globex", step_up=True)
    published = automation.api.post(admin, f"/playbooks/{pb['id']}/versions/{new_version}/publish").json()
    assert published["published_version"] == new_version
    assert {v["version"]: v["status"] for v in published["versions"]}[1] == "retired"
    with automation.env.su() as c:
        vid = c.execute(
            "SELECT id FROM playbook_versions WHERE playbook_id = %s AND version = %s", (pb["id"], new_version)
        ).fetchone()[0]
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("UPDATE playbook_versions SET definition = '{}' WHERE id = %s", (vid,))
    audit = {a["action"] for a in automation.api.get(admin, "/audit", params={"limit": 200}).json()}
    assert "playbook.publish" in audit


def test_cross_tenant_requests_invisible(automation: AutomationEnv) -> None:
    s = scenario(automation, "globex", "iso")
    req = request(automation, "globex", {"action_key": "aws.reboot_instance", "asset_id": s["asset_id"]}).json()
    one = APPROVERS["initech"][0]
    as_user(automation, one, "initech", step_up=True)
    assert automation.api.get(one, f"/actions/requests/{req['id']}").status_code == 404
    assert automation.api.post(one, f"/actions/requests/{req['id']}/approve", {}).status_code == 404
    assert req["id"] not in {x["id"] for x in automation.api.get(one, "/approvals/inbox").json()}
