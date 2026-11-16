"""P3 through the real pipeline: CMDB topology -> scenario replay -> Redpanda -> ingest worker
(correlation) -> Postgres -> API. Covers the exit criteria for scenarios 1 and 4, lifecycle
timestamps (MTTA/MTTR), maintenance and suppression, ServiceNow two-way sync with loop
prevention, live updates, the per-tenant ingest quota and search.

Every test starts from a clean incident state for Globex (open incidents and alerts closed), so
correlation decisions depend only on what the test replays.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import redis
from support.stream import StreamEnv

from app import live
from app.streaming import Envelope, raw_topic
from nocsoc_connector_sdk import Checkpoint, ConnectorContext
from nocsoc_connector_sdk.signing import sign
from nocsoc_connectors import REGISTRY

pytestmark = pytest.mark.integration

ADMIN = "admin@globex.example"


# ---------------------------------------------------------------- helpers
def instance(s: StreamEnv, definition_id: str) -> dict[str, Any]:
    s.api.switch(ADMIN, "globex")
    existing = sorted(
        (i for i in s.api.get(ADMIN, "/connectors/instances").json() if i["definition_id"] == definition_id),
        key=lambda i: i["created_at"],
    )
    if existing:
        return existing[0]  # type: ignore[no-any-return]
    r = s.api.post(ADMIN, "/connectors/instances", {"definition_id": definition_id, "name": f"{definition_id} p3"})
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def publish(s: StreamEnv, envelopes: list[Envelope]) -> None:
    from aiokafka import AIOKafkaProducer

    async def go() -> None:
        p = AIOKafkaProducer(bootstrap_servers=s.settings.kafka_bootstrap)
        await p.start()
        try:
            for e in envelopes:
                await p.send_and_wait(raw_topic(e.connector), e.to_bytes(), key=e.key())
        finally:
            await p.stop()

    asyncio.run(go())


def sync_topology(s: StreamEnv) -> None:
    """What the runner does for the ServiceNow cmdb_services stream."""
    inst = instance(s, "servicenow.itsm")
    tenant = s.env.tenants["globex"]
    conn = REGISTRY["servicenow.itsm"](ConnectorContext(tenant_id=tenant, instance_id=inst["id"]), inst["config"])
    result = asyncio.run(conn.fetch("cmdb_services", Checkpoint(cursor={})))
    envs = [
        Envelope.for_record(
            tenant_id=tenant,
            instance_id=inst["id"],
            connector="servicenow.itsm",
            stream="cmdb_services",
            trigger="scenario",
            record=rec,
        )
        for rec in result.records
    ]
    assert len({e.data["payload"]["name"] for e in envs}) == 5
    publish(s, envs)
    s.drain(minimum=len(envs))


def reset(s: StreamEnv) -> None:
    """Close Globex's open incidents and alerts so earlier tests cannot be correlated with."""
    t = s.env.tenants["globex"]
    with s.env.su() as c:
        c.execute(
            "UPDATE incidents SET status = 'closed', closed_at = now() WHERE tenant_id = %s AND status <> 'closed'",
            (t,),
        )
        c.execute("UPDATE alerts SET status = 'closed' WHERE tenant_id = %s AND status <> 'closed'", (t,))
        c.execute(
            "UPDATE maintenance_windows SET cancelled_at = now() WHERE tenant_id = %s AND cancelled_at IS NULL", (t,)
        )
        c.execute("UPDATE suppression_rules SET enabled = false WHERE tenant_id = %s", (t,))


def replay(s: StreamEnv, scenario: str, times: int = 1) -> int:
    from nocsoc_connectors import SCENARIOS

    for cid in SCENARIOS[scenario].connectors:
        instance(s, cid)
    r = s.api.post(ADMIN, f"/connectors/scenarios/{scenario}/replay?times={times}")
    assert r.status_code == 200, r.text
    published = int(r.json()["published"])
    s.drain(minimum=published)
    return published


def open_incidents(s: StreamEnv, portal: str | None = None) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"open_only": "true", "limit": 200}
    if portal:
        params["portal"] = portal
    r = s.api.get(ADMIN, "/incidents", params=params)
    assert r.status_code == 200, r.text
    return r.json()["items"]  # type: ignore[no-any-return]


def timeline(s: StreamEnv, incident_id: str) -> list[dict[str, Any]]:
    r = s.api.get(ADMIN, f"/incidents/{incident_id}/timeline")
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


@pytest.fixture(scope="module")
def topo(stream: StreamEnv) -> StreamEnv:
    stream.api.switch(ADMIN, "globex")
    sync_topology(stream)
    return stream


# ---------------------------------------------------------------- topology
def test_cmdb_sync_builds_services_and_topology(topo: StreamEnv) -> None:
    services = {s["name"]: s for s in topo.api.get(ADMIN, "/services").json()}
    assert set(services) >= {"Payments", "Order Management", "Customer Portal", "Identity (SSO)", "File Services"}
    payments = topo.api.get(ADMIN, f"/services/{services['Payments']['id']}").json()
    roles = {(a["role"], a["name"].split("-", 1)[1]) for a in payments["assets"]}
    assert ("member", "lnx-01") in roles and ("dependency", "core-sw-01") in roles
    assert payments["tier"] == 1 and payments["owner_team"] == "Payments Platform"


# ---------------------------------------------------------------- exit criteria: scenarios 1 and 4
def test_scenario_1_core_switch_is_a_single_noc_incident_with_impacted_services(topo: StreamEnv) -> None:
    reset(topo)
    replay(topo, "core_switch_failure")
    incidents = open_incidents(topo)
    assert len(incidents) == 1, [i["title"] for i in incidents]
    inc = incidents[0]
    assert inc["domain"] == "noc" and inc["priority"] == "P1" and inc["created_by_type"] == "correlation"
    assert {s["name"] for s in inc["services"]} == {"Payments", "Order Management"}
    alerts = topo.api.get(ADMIN, f"/incidents/{inc['id']}/alerts").json()
    assert len(alerts) == inc["alert_count"] == 8
    rules = {a["rule_key"] for a in alerts}
    assert None in rules and "service_topology" in rules  # one opener, the rest joined by topology
    entries = timeline(topo, inc["id"])
    added = sum(1 for e in entries if e["kind"] == "alert_added")
    merged = sum(e["body"].get("alerts", 0) for e in entries if e["kind"] == "merge")
    # Arrival order decides whether a second incident briefly existed and was merged in.
    assert entries[0]["kind"] == "created" and added + merged == 8
    # The alert queue shows the incident link and the service.
    queue = topo.api.get(ADMIN, "/alerts", params={"domain": "noc", "in_incident": "true", "limit": 200}).json()[
        "items"
    ]
    assert {a["incident"]["number"] for a in queue if a["incident"]} >= {inc["number"]}
    payments = next(s for s in topo.api.get(ADMIN, "/services").json() if s["name"] == "Payments")
    assert payments["health"] == "down" and payments["open_incidents"] >= 1


def test_scenario_4_ransomware_is_joint_and_visible_in_both_portals(topo: StreamEnv) -> None:
    reset(topo)
    replay(topo, "ransomware_precursor")
    incidents = open_incidents(topo)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["domain"] == "joint"
    assert {s["name"] for s in inc["services"]} == {"File Services"}
    assert inc["id"] in {i["id"] for i in open_incidents(topo, "noc")}
    assert inc["id"] in {i["id"] for i in open_incidents(topo, "soc")}
    escalations = [e for e in timeline(topo, inc["id"]) if e["kind"] == "escalation"]
    assert escalations and escalations[0]["body"]["to"] == "joint"


def test_phishing_correlates_by_shared_user(topo: StreamEnv) -> None:
    reset(topo)
    replay(topo, "phishing_credential_misuse")
    (inc,) = open_incidents(topo)
    assert inc["domain"] == "soc" and inc["alert_count"] == 4
    alerts = topo.api.get(ADMIN, f"/incidents/{inc['id']}/alerts").json()
    assert "shared_observable" in {a["rule_key"] for a in alerts}


def test_noise_opens_no_incident(topo: StreamEnv) -> None:
    reset(topo)
    replay(topo, "noise_flapping")
    assert open_incidents(topo) == []


def test_replayed_alerts_do_not_duplicate_incidents(topo: StreamEnv) -> None:
    reset(topo)
    replay(topo, "core_switch_failure", times=3)
    (inc,) = open_incidents(topo)
    assert inc["alert_count"] == 8  # repeats de-duplicate into the same alerts


# ---------------------------------------------------------------- lifecycle and MTTA/MTTR
def test_lifecycle_sets_timestamps_and_metrics(topo: StreamEnv) -> None:
    reset(topo)
    r = topo.api.post(ADMIN, "/incidents", {"title": "Manual major incident", "domain": "noc", "severity": "critical"})
    assert r.status_code == 201, r.text
    inc = r.json()
    assert inc["priority"] == "P1" and inc["acknowledged_at"] is None and inc["sla"]["ack_breached"] is False
    iid = inc["id"]

    def move(to: str, version: int, expected: int = 200) -> dict[str, Any]:
        r = topo.api.post(ADMIN, f"/incidents/{iid}/status", {"to": to, "version": version, "reason": "test"})
        assert r.status_code == expected, r.text
        return r.json()  # type: ignore[no-any-return]

    inc = move("investigating", inc["version"])
    assert inc["acknowledged_at"] is not None
    move("investigating", inc["version"] - 1, expected=409)  # stale version
    inc = move("resolved", inc["version"])
    assert inc["resolved_at"] is not None
    acked = datetime.fromisoformat(inc["acknowledged_at"])
    inc = move("investigating", inc["version"])  # reopen clears resolution, keeps acknowledgement
    assert inc["resolved_at"] is None and datetime.fromisoformat(inc["acknowledged_at"]) == acked
    inc = move("resolved", inc["version"])
    inc = move("closed", inc["version"])
    move("open", inc["version"], expected=409)  # closed is final

    # Exact MTTA/MTTR over controlled timestamps.
    t = topo.env.tenants["globex"]
    det = datetime.now(UTC) - timedelta(hours=2)
    with topo.env.su() as c:
        c.execute(
            "UPDATE incidents SET detected_at = %s, acknowledged_at = %s, resolved_at = %s WHERE id = %s",
            (det, det + timedelta(minutes=12), det + timedelta(minutes=90), iid),
        )
        rows = c.execute(
            "SELECT acknowledged_at - detected_at, resolved_at - detected_at FROM incidents "
            "WHERE tenant_id = %s AND detected_at >= now() - interval '30 days'",
            (t,),
        ).fetchall()
    acks = [r[0].total_seconds() for r in rows if r[0] is not None]
    ress = [r[1].total_seconds() for r in rows if r[1] is not None]
    m = topo.api.get(ADMIN, "/incidents/metrics", params={"days": 30}).json()
    assert m["mtta_seconds"] == pytest.approx(sum(acks) / len(acks))
    assert m["mttr_seconds"] == pytest.approx(sum(ress) / len(ress))
    kinds = [e["kind"] for e in timeline(topo, iid)]
    assert kinds.count("state_change") == 5


def test_comments_tasks_assignment_and_audit(topo: StreamEnv) -> None:
    reset(topo)
    inc = topo.api.post(ADMIN, "/incidents", {"title": "Workflow test", "domain": "soc", "severity": "high"}).json()
    iid = inc["id"]
    c = topo.api.post(ADMIN, f"/incidents/{iid}/comments", {"body": "<script>alert(1)</script> stored as text"})
    assert c.status_code == 201 and c.json()["body"]["text"].startswith("<script>")
    task = topo.api.post(ADMIN, f"/incidents/{iid}/tasks", {"title": "Isolate host"}).json()
    r = topo.api.patch(ADMIN, f"/incidents/{iid}/tasks/{task['id']}", {"status": "done", "version": task["version"]})
    assert r.status_code == 200 and r.json()["status"] == "done"
    me = topo.env.users[ADMIN]["id"]
    r = topo.api.patch(ADMIN, f"/incidents/{iid}", {"assignee_id": me, "version": inc["version"]})
    assert r.status_code == 200 and r.json()["assignee_id"] == me
    outsider = topo.env.users["admin@initech.example"]["id"]
    r = topo.api.patch(ADMIN, f"/incidents/{iid}", {"assignee_id": outsider, "version": r.json()["version"]})
    assert r.status_code == 422  # assignees must be members of this tenant
    r = topo.api.post(ADMIN, f"/incidents/{iid}/escalate", {"reason": "operational impact"})
    assert r.status_code == 200 and r.json()["domain"] == "joint"
    audit = {a["action"] for a in topo.api.get(ADMIN, "/audit", params={"limit": 200}).json()}
    assert {"incident.create", "incident.comment", "incident.task.create", "incident.escalate"} <= audit


def test_timeline_is_append_only(topo: StreamEnv) -> None:
    import psycopg
    from psycopg import errors

    for dsn in (topo.env.app_dsn, topo.env.worker_dsn):
        with psycopg.connect(dsn) as c:
            c.execute("SELECT set_config('app.tenant_id', %s, false)", (topo.env.tenants["globex"],))
            with pytest.raises(errors.InsufficientPrivilege):
                c.execute("UPDATE timeline_entries SET body = '{}'")
            c.rollback()
            c.execute("SELECT set_config('app.tenant_id', %s, false)", (topo.env.tenants["globex"],))
            with pytest.raises(errors.InsufficientPrivilege):
                c.execute("DELETE FROM timeline_entries")


# ---------------------------------------------------------------- maintenance and suppression
def test_maintenance_window_suppresses_alerts_on_its_service(topo: StreamEnv) -> None:
    reset(topo)
    payments = next(s for s in topo.api.get(ADMIN, "/services").json() if s["name"] == "Payments")
    now = datetime.now(UTC)
    r = topo.api.post(
        ADMIN,
        "/maintenance-windows",
        {
            "title": "Payments patching",
            "service_ids": [payments["id"]],
            "starts_at": (now - timedelta(minutes=5)).isoformat(),
            "ends_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert r.status_code == 201 and r.json()["state"] == "active"
    replay(topo, "core_switch_failure")
    t = topo.env.tenants["globex"]
    with topo.env.su() as c:
        suppressed = c.execute(
            "SELECT a.title, a.suppression_reason, ia.incident_id FROM alerts a "
            "LEFT JOIN incident_alerts ia ON ia.alert_id = a.id WHERE a.tenant_id = %s AND a.status = 'suppressed'",
            (t,),
        ).fetchall()
    assert suppressed and all(r[1] == "Maintenance window: Payments patching" for r in suppressed)
    assert all(r[2] is None for r in suppressed)  # suppressed alerts never join incidents
    titles = " ".join(r[0] for r in suppressed)
    assert "payments-api" in titles and "Node is down" in titles
    assert topo.api.delete(ADMIN, f"/maintenance-windows/{r.json()['id']}").status_code == 204


def test_suppression_rule_matches_and_counts(topo: StreamEnv) -> None:
    reset(topo)
    bad = topo.api.post(ADMIN, "/suppression-rules", {"name": "empty", "match": {}, "reason": "x"})
    assert bad.status_code == 422
    rule = topo.api.post(
        ADMIN,
        "/suppression-rules",
        {"name": "Disk noise", "match": {"connector": "datadog", "title_contains": "Disk usage"}, "reason": "known"},
    ).json()
    replay(topo, "noise_flapping")
    rules = {r["id"]: r for r in topo.api.get(ADMIN, "/suppression-rules").json()}
    assert rules[rule["id"]]["hits"] == 1  # one alert (the rest de-duplicate into it)
    queue = topo.api.get(ADMIN, "/alerts", params={"status": "suppressed", "limit": 200}).json()["items"]
    assert any(a["suppression_reason"] == "Suppression rule: Disk noise" for a in queue)


# ---------------------------------------------------------------- ServiceNow two-way sync
def _sn_webhook(s: StreamEnv, secret: str, inst_id: str, body: dict[str, Any]) -> None:
    raw = json.dumps(body).encode()
    ts, nonce = int(time.time()), secrets.token_hex(12)
    r = s.api.client.post(
        f"/api/v1/ingest/webhooks/{inst_id}",
        content=raw,
        headers={
            "X-NocSoc-Timestamp": str(ts),
            "X-NocSoc-Nonce": nonce,
            "X-NocSoc-Signature": sign(secret, ts, nonce, raw),
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 202, r.text


def test_servicenow_two_way_sync_without_loops(topo: StreamEnv) -> None:
    reset(topo)
    inst = instance(topo, "servicenow.itsm")
    topo.api.step_up(ADMIN)
    secret = topo.api.post(ADMIN, f"/connectors/instances/{inst['id']}/webhook-secret").json()["webhook_secret"]
    inc = topo.api.post(ADMIN, "/incidents", {"title": "ITSM sync", "domain": "noc", "severity": "high"}).json()
    r = topo.api.post(ADMIN, f"/incidents/{inc['id']}/external-tickets", {"system": "servicenow"})
    assert r.status_code == 201, r.text
    ticket = r.json()["external_tickets"][0]
    assert ticket["external_number"].startswith("INC") and ticket["last_sync_origin"] == "platform"
    assert topo.api.post(ADMIN, f"/incidents/{inc['id']}/external-tickets", {}).status_code == 409
    with topo.env.su() as c:
        sys_id = c.execute("SELECT external_id FROM external_tickets WHERE incident_id = %s", (inc["id"],)).fetchone()[
            0
        ]

    # Outbound: our status change is pushed (simulated) and remembered.
    inc = topo.api.post(
        ADMIN, f"/incidents/{inc['id']}/status", {"to": "investigating", "version": inc["version"]}
    ).json()
    base = {
        "sys_id": sys_id,
        "number": ticket["external_number"],
        "short_description": "x",
        "sys_updated_on": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Echo of our own push (state 2 = in progress): recorded, but changes nothing.
    _sn_webhook(topo, secret, inst["id"], {**base, "state": "2"})
    topo.drain(minimum=1)
    after_echo = topo.api.get(ADMIN, f"/incidents/{inc['id']}").json()
    assert after_echo["version"] == inc["version"]
    inbound = [e for e in timeline(topo, inc["id"]) if e["kind"] == "external_sync" and e["actor_type"] == "connector"]
    assert inbound == []

    # A genuine change in ServiceNow (resolved there) flows in once.
    _sn_webhook(topo, secret, inst["id"], {**base, "state": "6"})
    topo.drain(minimum=1)
    final = topo.api.get(ADMIN, f"/incidents/{inc['id']}").json()
    assert final["status"] == "resolved"
    assert final["external_tickets"][0]["last_sync_origin"] == "external"
    inbound = [e for e in timeline(topo, inc["id"]) if e["kind"] == "external_sync" and e["actor_type"] == "connector"]
    assert len(inbound) == 1 and inbound[0]["body"]["applied"] is True


# ---------------------------------------------------------------- live updates
def test_worker_publishes_tenant_scoped_live_events(topo: StreamEnv) -> None:
    reset(topo)
    st = topo.settings
    client = redis.Redis(host=st.valkey_host, port=st.valkey_port, password=st.valkey_password.get_secret_value())  # type: ignore[union-attr]
    pubsub = client.pubsub(ignore_subscribe_messages=True)
    pubsub.subscribe(live.channel(topo.env.tenants["globex"]), live.channel(topo.env.tenants["initech"]))
    started = time.monotonic()
    replay(topo, "ransomware_precursor")
    got: list[tuple[str, dict[str, Any]]] = []
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        m = pubsub.get_message(timeout=0.5)
        if m and m["type"] == "message":
            got.append((m["channel"].decode(), json.loads(m["data"])))
    pubsub.close()
    assert {ch for ch, _ in got} == {live.channel(topo.env.tenants["globex"])}
    types = {e["type"] for _, e in got}
    assert types == {"alert.upserted", "incident.changed"}
    assert time.monotonic() - started < 60


def test_sse_stream_delivers_only_own_tenant_events(topo: StreamEnv) -> None:
    st = topo.settings
    globex, initech = uuid.UUID(topo.env.tenants["globex"]), topo.env.tenants["initech"]

    class FakeRequest:
        def __init__(self) -> None:
            self.calls = 0

        async def is_disconnected(self) -> bool:
            self.calls += 1
            return self.calls > 200

    async def go() -> list[bytes]:
        import redis.asyncio as aredis

        c = aredis.Redis(host=st.valkey_host, port=st.valkey_port, password=st.valkey_password.get_secret_value())  # type: ignore[union-attr]
        gen = live._events(FakeRequest(), c, globex)  # type: ignore[arg-type]
        chunks = [await gen.__anext__()]  # "connected" (subscribed)
        await live.publish(c, initech, {"type": "incident.changed", "id": "other-tenant"})
        await live.publish(c, globex, {"type": "incident.changed", "id": "mine"})
        await live.publish(c, globex, {"type": "not.allowed", "id": "dropped"})
        async for chunk in gen:
            chunks.append(chunk)
            if b"mine" in chunk:
                break
        await gen.aclose()
        await c.aclose()
        return chunks

    body = b"".join(asyncio.run(go()))
    assert b"event: incident.changed" in body and b'"id":"mine"' in body
    assert b"other-tenant" not in body and b"dropped" not in body
    assert topo.api.client.get("/api/v1/stream").status_code == 401


# ---------------------------------------------------------------- ingest quota
def test_tenant_ingest_quota_dead_letters_excess(topo: StreamEnv) -> None:
    reset(topo)
    if datetime.now(UTC).second > 45:  # keep the burst inside one quota window
        time.sleep(61 - datetime.now(UTC).second)
    tight = dataclasses.replace(topo, settings=topo.settings.model_copy(update={"tenant_ingest_records_per_minute": 3}))
    r = topo.api.post(ADMIN, "/connectors/scenarios/noise_flapping/replay?times=1")
    published = r.json()["published"]
    stats = tight.drain(minimum=published)
    assert stats["dead_letter"] >= published - 3 and stats["stored"] <= 3
    letters = topo.api.get(ADMIN, "/connectors/dead-letters", params={"limit": 200}).json()
    assert sum(1 for d in letters if d["reason"] == "quota_exceeded") >= published - 3


# ---------------------------------------------------------------- search, rules, SLA
def test_search_finds_incidents_alerts_assets_and_services(topo: StreamEnv) -> None:
    reset(topo)
    replay(topo, "core_switch_failure")
    (inc,) = open_incidents(topo)
    hits = topo.api.get(ADMIN, "/search", params={"q": inc["number"]}).json()["hits"]
    assert any(h["kind"] == "incident" and h["id"] == inc["id"] for h in hits)
    kinds = {h["kind"] for h in topo.api.get(ADMIN, "/search", params={"q": "core"}).json()["hits"]}
    assert {"alert", "asset"} <= kinds or {"incident", "asset"} <= kinds
    assert any(h["kind"] == "service" for h in topo.api.get(ADMIN, "/search", params={"q": "payments"}).json()["hits"])
    assert topo.api.get(ADMIN, "/search", params={"q": "x"}).status_code == 422


def test_correlation_rules_and_sla_policy_need_step_up(topo: StreamEnv) -> None:
    rules = topo.api.get(ADMIN, "/correlation-rules").json()
    assert [r["key"] for r in rules] == ["same_asset", "service_topology", "shared_observable"]
    topo.api.login(ADMIN, fresh=True)
    topo.api.switch(ADMIN, "globex")
    body = {"enabled": True, "window_minutes": 45}
    assert topo.api.patch(ADMIN, "/correlation-rules/same_asset", body).status_code == 403  # no step-up yet
    topo.api.step_up(ADMIN)
    r = topo.api.patch(ADMIN, "/correlation-rules/same_asset", body)
    assert r.status_code == 200 and r.json()[0]["window_minutes"] == 45
    assert topo.api.patch(ADMIN, "/correlation-rules/nope", body).status_code == 404
    bad = {"targets": {"P1": {"ack": 60, "resolve": 30}}}
    assert topo.api.put(ADMIN, "/sla-policy", bad).status_code == 422
    good = {"targets": {"P1": {"ack": 10, "resolve": 120}}}
    r = topo.api.put(ADMIN, "/sla-policy", good)
    assert r.status_code == 200 and r.json()["targets"]["P1"] == {"ack": 10, "resolve": 120}
    assert r.json()["targets"]["P2"] == {"ack": 30, "resolve": 480}  # defaults fill the rest
    topo.api.patch(ADMIN, "/correlation-rules/same_asset", {"enabled": True, "window_minutes": 60})


def test_roles_without_incident_permissions_are_refused(topo: StreamEnv) -> None:
    inc = topo.api.post(ADMIN, "/incidents", {"title": "RBAC", "domain": "noc", "severity": "high"}).json()
    key = topo.api.post(ADMIN, "/api-keys", {"name": "alerts only", "permissions": ["alert:read"]})
    assert key.status_code == 201, key.text
    h = {"Authorization": f"Bearer {key.json()['key']}"}
    for path in ("/incidents", f"/incidents/{inc['id']}", "/services", "/maintenance-windows", "/correlation-rules"):
        assert topo.api.client.get(f"/api/v1{path}", headers=h).status_code == 403, path
    assert topo.api.client.get("/api/v1/alerts", headers=h).status_code == 200
    r = topo.api.client.post(f"/api/v1/incidents/{inc['id']}/comments", headers=h, json={"body": "x"})
    assert r.status_code == 403
    responder = topo.api.post(
        ADMIN, "/api-keys", {"name": "responder", "permissions": ["incident:read", "incident:escalate"]}
    ).json()["key"]
    h = {"Authorization": f"Bearer {responder}"}
    r = topo.api.client.post(f"/api/v1/incidents/{inc['id']}/escalate", headers=h, json={"reason": "x"})
    assert r.status_code == 200
    rule = {"enabled": False, "window_minutes": 10}
    assert topo.api.client.patch("/api/v1/correlation-rules/same_asset", headers=h, json=rule).status_code == 403
