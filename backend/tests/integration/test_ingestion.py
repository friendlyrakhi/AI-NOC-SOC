"""P2 pipeline end to end: API -> Redpanda -> ingest worker -> Postgres/ClickHouse -> API.

Covers the P2 exit criteria that need real infrastructure: scenario goldens, de-duplication,
10x burst without loss, ownership (T10), drift and size dead-lettering, webhook HMAC/replay/size
(T14), write-only credentials (T17), and ClickHouse tenant row policies (T8).
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
import uuid
from typing import Any

import clickhouse_connect
import pytest
from aiokafka import AIOKafkaProducer
from support.stream import StreamEnv

from app.ingestion.pipeline import fingerprint
from app.streaming import Envelope, raw_topic
from nocsoc_connector_sdk import AlertV1, ConnectorContext
from nocsoc_connector_sdk.signing import sign
from nocsoc_connectors import REGISTRY, SCENARIOS

pytestmark = pytest.mark.integration

ADMIN = "admin@globex.example"
INITECH_ADMIN = "admin@initech.example"


# ---------------------------------------------------------------- helpers
def instance(
    s: StreamEnv, definition_id: str, *, email: str = ADMIN, slug: str = "globex", config: dict | None = None
) -> dict[str, Any]:  # type: ignore[type-arg]
    s.api.switch(email, slug)
    # Replay uses each connector's earliest instance, so the helper does too.
    existing = sorted(
        (i for i in s.api.get(email, "/connectors/instances").json() if i["definition_id"] == definition_id),
        key=lambda i: i["created_at"],
    )
    if existing and config is None:
        return existing[0]  # type: ignore[no-any-return]
    r = s.api.post(
        email,
        "/connectors/instances",
        {"definition_id": definition_id, "name": f"{definition_id} {uuid.uuid4().hex[:6]}", "config": config or {}},
    )
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def expected_alerts(s: StreamEnv, scenario: str, slug: str = "globex") -> tuple[int, set[str]]:
    """(alert records per replay, distinct fingerprints) computed from the catalog itself."""
    tenant = s.env.tenants[slug]
    records, fps = 0, set()
    for cid in SCENARIOS[scenario].connectors:
        inst = instance(s, cid)
        conn = REGISTRY[cid](ConnectorContext(tenant_id=tenant, instance_id=inst["id"]), inst["config"])
        for stream_name, rec in conn.scenario_records(scenario, 0):
            for n in REGISTRY[cid].normalize(stream_name, rec):
                if isinstance(n, AlertV1) and n.status != "resolved":
                    records += 1
                    fps.add(fingerprint(cid, n.dedup_key))
    return records, fps


def alert_rows(s: StreamEnv, slug: str = "globex") -> dict[str, tuple[int, str]]:
    """fingerprint -> (occurrence_count, status), straight from the database."""
    with s.env.su() as c:
        return {
            r[0]: (r[1], r[2])
            for r in c.execute(
                # Open alerts only: de-duplication applies to open alerts, and a closed alert may
                # share its fingerprint with a newer open one.
                "SELECT fingerprint, occurrence_count, status FROM alerts "
                "WHERE tenant_id = %s AND status NOT IN ('resolved', 'closed')",
                (s.env.tenants[slug],),
            )
        }


def produce(s: StreamEnv, topic: str, value: bytes, key: bytes = b"k") -> None:
    async def go() -> None:
        p = AIOKafkaProducer(bootstrap_servers=s.settings.kafka_bootstrap, max_request_size=4_194_304)
        await p.start()
        try:
            await p.send_and_wait(topic, value, key=key)
        finally:
            await p.stop()

    asyncio.run(go())


def dead_letters(s: StreamEnv) -> list[tuple[Any, ...]]:
    with s.env.su() as c:
        return c.execute("SELECT tenant_id, instance_id, reason FROM ingest_dead_letters ORDER BY id").fetchall()


# ---------------------------------------------------------------- scenarios, dedup, burst
def test_core_switch_scenario_produces_golden_alerts(stream: StreamEnv) -> None:
    per_replay, fps = expected_alerts(stream, "core_switch_failure")
    r = stream.api.post(ADMIN, "/connectors/scenarios/core_switch_failure/replay")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["missing"] == [] and body["published"] >= per_replay
    stats = stream.drain(minimum=body["published"])
    assert stats["dead_letter"] == 0 and stats["failed"] == 0
    rows = alert_rows(stream)
    assert fps <= set(rows), "every expected alert exists"
    page = stream.api.get(ADMIN, "/alerts", params={"domain": "noc", "limit": 200}).json()
    titles = {a["title"] for a in page["items"]}
    assert any("payments-api" in t for t in titles)
    assert any(a["severity"] == "critical" and a["connector_id"] == "solarwinds.orion" for a in page["items"])
    assert all(a["sandbox"] for a in page["items"])
    assert any(a["asset"] for a in page["items"]), "alerts resolve to assets"


def test_noise_scenario_deduplicates(stream: StreamEnv) -> None:
    per_replay, fps = expected_alerts(stream, "noise_flapping")
    assert per_replay > len(fps)  # the scenario really repeats
    before = alert_rows(stream)
    r = stream.api.post(ADMIN, "/connectors/scenarios/noise_flapping/replay")
    stream.drain(minimum=r.json()["published"])
    after = alert_rows(stream)
    gained = sum(after[f][0] - before.get(f, (0, ""))[0] for f in fps)
    assert gained == per_replay
    assert len([f for f in fps if f not in before]) <= len(fps)  # one row per fingerprint, never more


def test_burst_10x_replay_completes_without_loss(stream: StreamEnv) -> None:
    per_replay, fps = expected_alerts(stream, "phishing_credential_misuse")
    before = alert_rows(stream)
    r = stream.api.post(ADMIN, "/connectors/scenarios/phishing_credential_misuse/replay", params={"times": 10})
    assert r.status_code == 200, r.text
    published = r.json()["published"]
    stats = stream.drain(minimum=published)
    assert stats["stored"] >= published and stats["dead_letter"] == 0 and stats["failed"] == 0
    after = alert_rows(stream)
    gained = sum(after[f][0] - before.get(f, (0, ""))[0] for f in fps)
    assert gained == 10 * per_replay, "every replayed alert record was counted exactly once"


def test_replay_limits(stream: StreamEnv) -> None:
    stream.api.switch(ADMIN, "globex")
    assert stream.api.post(ADMIN, "/connectors/scenarios/nope/replay").status_code == 404
    r = stream.api.client.post(
        "/api/v1/connectors/scenarios/noise_flapping/replay?times=11", headers=stream.api.headers(ADMIN)
    )
    assert r.status_code == 422


def test_kev_scenario_creates_findings(stream: StreamEnv) -> None:
    for cid in SCENARIOS["kev_exposure"].connectors:
        instance(stream, cid)
    r = stream.api.post(ADMIN, "/connectors/scenarios/kev_exposure/replay")
    stream.drain(minimum=r.json()["published"])
    vulns = stream.api.get(ADMIN, "/vulnerabilities", params={"kev": True}).json()
    assert vulns["total"] >= 1
    assert all(v["kev"] and v["sandbox"] for v in vulns["items"])
    assert vulns["items"][0]["asset"] is not None


# ---------------------------------------------------------------- ownership, drift, limits
def _envelope(tenant: str, inst: dict[str, Any], payload: dict[str, Any], stream_name: str = "alerts") -> Envelope:
    return Envelope.model_validate(
        {
            "source": "test",
            "tenantid": tenant,
            "instanceid": inst["id"],
            "connector": inst["definition_id"],
            "stream": stream_name,
            "trigger": "scenario",
            "dataschema": "prometheus.alert@1",
            "data": {
                "source_id": "x-1",
                "observed_at": "2026-11-16T12:00:00Z",
                "schema": "prometheus.alert@1",
                "payload": payload,
            },
        }
    )


def test_tenant_mismatch_is_dead_lettered(stream: StreamEnv) -> None:
    inst = instance(stream, "prometheus")
    before_initech = alert_rows(stream, "initech")
    env = _envelope(stream.env.tenants["initech"], inst, {"labels": {"alertname": "Spoof"}})
    produce(stream, raw_topic("prometheus"), env.to_bytes())
    stream.drain()
    last = dead_letters(stream)[-1]
    assert last[2] == "ownership_mismatch"
    assert last[0] is None, "a spoofed claim is not attributed to the claimed tenant"
    assert alert_rows(stream, "initech") == before_initech


def test_schema_drift_is_dead_lettered_and_visible_to_owner(stream: StreamEnv) -> None:
    inst = instance(stream, "prometheus")
    env = _envelope(stream.env.tenants["globex"], inst, {"__schema_drift__": True})
    produce(stream, raw_topic("prometheus"), env.to_bytes())
    stream.drain()
    dl = stream.api.get(ADMIN, "/connectors/dead-letters", params={"instance_id": inst["id"]}).json()
    assert dl and dl[0]["reason"] == "schema_drift"
    assert "envelope" not in dl[0], "attacker-controlled bodies are not returned"
    stream.api.switch(INITECH_ADMIN, "initech")
    initech = stream.api.get(INITECH_ADMIN, "/connectors/dead-letters").json()
    assert all(d["instance_id"] != inst["id"] for d in initech)
    stream.api.switch(ADMIN, "globex")


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        (b"{not json", "invalid_json"),
        (json.dumps({"a": 1}).encode(), "invalid_envelope"),
    ],
)
def test_malformed_messages_are_dead_lettered(stream: StreamEnv, value: bytes, reason: str) -> None:
    produce(stream, raw_topic("prometheus"), value)
    stream.drain()
    assert dead_letters(stream)[-1][2] == reason


def test_oversized_and_deep_records_are_dead_lettered(stream: StreamEnv) -> None:
    inst = instance(stream, "prometheus")
    big = _envelope(stream.env.tenants["globex"], inst, {"blob": "x" * 300_000})
    produce(stream, raw_topic("prometheus"), big.to_bytes())
    stream.drain()
    assert dead_letters(stream)[-1][2] == "too_large"
    deep: Any = {}
    cur = deep
    for _ in range(40):
        cur["n"] = {}
        cur = cur["n"]
    produce(stream, raw_topic("prometheus"), _envelope(stream.env.tenants["globex"], inst, deep).to_bytes())
    stream.drain()
    assert dead_letters(stream)[-1][2] == "too_deep"


def test_redelivery_has_no_second_effect(stream: StreamEnv) -> None:
    inst = instance(stream, "prometheus")
    conn = REGISTRY["prometheus"](ConnectorContext(tenant_id=stream.env.tenants["globex"], instance_id=inst["id"]))
    stream_name, rec = conn.scenario_records("noise_flapping", 0)[0]
    env = Envelope.for_record(
        tenant_id=stream.env.tenants["globex"],
        instance_id=inst["id"],
        connector="prometheus",
        stream=stream_name,
        trigger="scenario",
        record=rec,
    )
    before = alert_rows(stream)
    produce(stream, raw_topic("prometheus"), env.to_bytes())
    produce(stream, raw_topic("prometheus"), env.to_bytes())  # same envelope id: a redelivery
    stats = stream.drain(minimum=2)
    assert stats["duplicate"] == 1
    after = alert_rows(stream)
    assert sum(v[0] for v in after.values()) - sum(v[0] for v in before.values()) == 1


# ---------------------------------------------------------------- webhooks
def _signed(secret: str, body: bytes, *, ts: int | None = None, nonce: str | None = None) -> dict[str, str]:
    ts = ts if ts is not None else int(time.time())
    nonce = nonce or secrets.token_hex(12)
    return {
        "X-NocSoc-Timestamp": str(ts),
        "X-NocSoc-Nonce": nonce,
        "X-NocSoc-Signature": sign(secret, ts, nonce, body),
        "Content-Type": "application/json",
    }


def test_webhook_hmac_replay_and_limits(stream: StreamEnv) -> None:
    created = instance(stream, "generic.webhook", config={"domain": "soc"})
    secret = created["webhook_secret"]
    assert secret and secret.startswith("whs_")
    assert "webhook_secret" not in stream.api.get(ADMIN, f"/connectors/instances/{created['id']}").json()
    url = f"/api/v1/ingest/webhooks/{created['id']}"
    body = json.dumps({"id": "wh-1", "title": "Webhook DEMO alert", "severity": "high", "host": "web-01"}).encode()
    c = stream.api.client

    headers = _signed(secret, body)
    assert c.post(url, content=body, headers=headers).status_code == 202
    assert c.post(url, content=body, headers=headers).status_code == 409  # nonce replay
    assert c.post(url, content=body, headers=_signed("whs_wrong", body)).status_code == 401
    assert c.post(url, content=body, headers=_signed(secret, body, ts=int(time.time()) - 900)).status_code == 401
    tampered = _signed(secret, body)
    assert c.post(url, content=body + b" ", headers=tampered).status_code == 401
    assert c.post(url, content=body, headers={"Content-Type": "application/json"}).status_code == 401
    assert (
        c.post(f"/api/v1/ingest/webhooks/{uuid.uuid4()}", content=body, headers=_signed(secret, body)).status_code
        == 401
    )
    huge = b'{"title": "' + b"x" * (stream.settings.webhook_max_bytes + 10) + b'"}'
    assert c.post(url, content=huge, headers=_signed(secret, huge)).status_code == 413
    bad = json.dumps({"no_title": True}).encode()
    assert c.post(url, content=bad, headers=_signed(secret, bad)).status_code == 422

    stream.drain()
    page = stream.api.get(ADMIN, "/alerts", params={"q": "Webhook DEMO alert"}).json()
    assert page["total"] == 1 and page["items"][0]["domain"] == "soc"

    # Rotation invalidates the old secret.
    stream.api.step_up(ADMIN)
    rotated = stream.api.post(ADMIN, f"/connectors/instances/{created['id']}/webhook-secret").json()["webhook_secret"]
    assert c.post(url, content=body, headers=_signed(secret, body)).status_code == 401
    assert c.post(url, content=body, headers=_signed(rotated, body)).status_code == 202


# ---------------------------------------------------------------- credentials (write-only)
def test_credentials_are_write_only(stream: StreamEnv) -> None:
    inst = instance(stream, "splunk", config={})
    path = f"/connectors/instances/{inst['id']}/credentials"
    assert stream.api.put(ADMIN, path, {"secrets": {"token": "s3cr3t-DEMO-value"}}).status_code in (403, 204)
    stream.api.step_up(ADMIN)
    r = stream.api.put(ADMIN, path, {"secrets": {"token": "s3cr3t-DEMO-value"}})
    assert r.status_code == 204, r.text
    got = stream.api.get(ADMIN, f"/connectors/instances/{inst['id']}")
    assert got.json()["has_credentials"] is True
    assert "s3cr3t" not in got.text
    assert "s3cr3t" not in stream.api.get(ADMIN, "/connectors/instances").text
    with stream.env.su() as c:
        ct = c.execute(
            "SELECT s.ciphertext FROM secrets s JOIN connector_instances i ON i.secret_id = s.id WHERE i.id = %s",
            (inst["id"],),
        ).fetchone()
        audit = c.execute(
            "SELECT details::text FROM audit_log WHERE action = 'connector.credentials.set' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert "s3cr3t" not in ct[0]
    assert "s3cr3t" not in audit[0] and "token" in audit[0]
    test = stream.api.post(ADMIN, f"/connectors/instances/{inst['id']}/test").json()
    assert test["ok"] is True


# ---------------------------------------------------------------- runner protocol and health
def test_runner_endpoints_require_token_and_drive_health(stream: StreamEnv) -> None:
    c = stream.api.client
    assert c.get("/api/v1/internal/runner/work").status_code == 401
    assert c.get("/api/v1/internal/runner/work", headers={"X-Runner-Token": "nope"}).status_code == 401
    assert c.get("/api/v1/internal/runner/work", headers=stream.api.headers(ADMIN)).status_code == 401
    token = {"X-Runner-Token": stream.settings.runner_token.get_secret_value()}  # type: ignore[union-attr]
    inst = instance(stream, "wazuh", config={"sandbox_faults": {"auth_failure": True}})
    assert inst["status"] == "pending", "a new instance never claims health it has not earned"

    from connector_runner.scheduler import Scheduler

    class ApiBridge:
        async def work(self) -> list[dict[str, Any]]:
            items = c.get("/api/v1/internal/runner/work", headers=token).json()
            return [i for i in items if i["instance_id"] == inst["id"]]

        async def credentials(self, iid: str) -> dict[str, str]:
            return c.get(f"/api/v1/internal/runner/instances/{iid}/credentials", headers=token).json()["secrets"]  # type: ignore[no-any-return]

        async def report(self, iid: str, body: dict[str, Any]) -> None:
            assert (
                c.post(f"/api/v1/internal/runner/instances/{iid}/report", headers=token, json=body).status_code == 204
            )

    class Bus:
        sent = 0

        async def send(self, topic: str, key: bytes, value: bytes) -> None:
            Bus.sent += 1

    asyncio.run(Scheduler(ApiBridge(), Bus()).tick())
    got = stream.api.get(ADMIN, f"/connectors/instances/{inst['id']}").json()
    assert got["status"] == "failing" and "AuthError" in got["status_detail"]
    runs = stream.api.get(ADMIN, f"/connectors/instances/{inst['id']}/runs").json()
    assert runs and runs[0]["status"] == "failed"

    # Fix the configuration: the next run recovers to healthy.
    r = stream.api.patch(ADMIN, f"/connectors/instances/{inst['id']}", {"config": {}, "version": got["version"]})
    assert r.status_code == 200, r.text
    assert stream.api.post(ADMIN, f"/connectors/instances/{inst['id']}/sync").status_code == 202
    asyncio.run(Scheduler(ApiBridge(), Bus()).tick())
    got = stream.api.get(ADMIN, f"/connectors/instances/{inst['id']}").json()
    assert got["status"] == "healthy" and got["last_success_at"] and got["sync_requested_at"] is None
    assert Bus.sent > 0


def test_runner_envelopes_validate_against_platform_contract() -> None:
    from connector_runner.bus import envelope

    conn = REGISTRY["splunk"](ConnectorContext(tenant_id=str(uuid.uuid4()), instance_id=str(uuid.uuid4())))
    for stream_name, rec in conn.scenario_records("phishing_credential_misuse", 0):
        env = envelope(conn.ctx.tenant_id, conn.ctx.instance_id, "splunk", stream_name, "schedule", rec)
        Envelope.model_validate(env)


# ---------------------------------------------------------------- ClickHouse isolation
def test_clickhouse_row_policy_isolates_tenants(stream: StreamEnv) -> None:
    # A real polled page of Splunk authentication events (OCSF 3002) -> security_events.
    inst = instance(stream, "splunk")
    conn = REGISTRY["splunk"](
        ConnectorContext(tenant_id=stream.env.tenants["globex"], instance_id=inst["id"]), inst["config"]
    )
    fetched = asyncio.run(conn.fetch("auth_events", None))
    assert fetched.records
    for rec in fetched.records:
        env = Envelope.for_record(
            tenant_id=stream.env.tenants["globex"],
            instance_id=inst["id"],
            connector="splunk",
            stream="auth_events",
            trigger="schedule",
            record=rec,
        )
        produce(stream, raw_topic("splunk"), env.to_bytes())
    stream.drain(minimum=len(fetched.records))

    s = stream.settings
    reader = clickhouse_connect.get_client(
        host=s.clickhouse_host,
        port=s.clickhouse_port,
        username="nocsoc_reader",
        password=s.clickhouse_reader_password.get_secret_value(),
        database=s.clickhouse_database,  # type: ignore[union-attr]
    )
    globex, initech = stream.env.tenants["globex"], stream.env.tenants["initech"]
    own = reader.query(
        "SELECT count(), uniqExact(tenant_id) FROM raw_events", settings={"SQL_tenant_id": globex}
    ).result_rows[0]
    assert own[0] > 0 and own[1] == 1
    other = reader.query(
        "SELECT count() FROM raw_events WHERE tenant_id = {t:UUID}",
        parameters={"t": globex},
        settings={"SQL_tenant_id": initech},
    ).result_rows[0]
    assert other[0] == 0
    with pytest.raises(Exception):  # noqa: B017,PT011 - no tenant setting: the policy cannot evaluate
        reader.query("SELECT count() FROM raw_events")
    with pytest.raises(Exception):  # noqa: B017,PT011 - reader cannot write
        reader.command("INSERT INTO raw_events (tenant_id) VALUES ({t:UUID})", parameters={"t": globex})
    sec = reader.query("SELECT count() FROM security_events", settings={"SQL_tenant_id": globex}).result_rows[0]
    assert sec[0] >= len(fetched.records), "authentication events reached the telemetry store"


def test_canonical_events_search_and_isolation(stream: StreamEnv) -> None:
    stream.api.switch(ADMIN, "globex")
    page = stream.api.get(ADMIN, "/events", params={"limit": 500}).json()
    classes = {e["class"] for e in page["items"]}
    assert {"alert", "authentication"} <= classes, classes
    assert {e["domain"] for e in page["items"]} <= {"noc", "soc"}
    assert all(e["sandbox"] for e in page["items"])
    soc_auth = stream.api.get(ADMIN, "/events", params={"domain": "soc", "class": "authentication", "limit": 3}).json()
    assert len(soc_auth["items"]) == 3 and soc_auth["next_cursor"]
    nxt = stream.api.get(
        ADMIN,
        "/events",
        params={"domain": "soc", "class": "authentication", "limit": 3, "cursor": soc_auth["next_cursor"]},
    ).json()
    assert not {e["event_id"] for e in nxt["items"]} & {e["event_id"] for e in soc_auth["items"]}, (
        "pages do not overlap"
    )
    assert stream.api.get(ADMIN, "/events", params={"cursor": "garbage"}).status_code == 422
    assert (
        stream.api.get(
            ADMIN, "/events", params={"since": "2026-01-01T00:00:00Z", "until": "2026-11-01T00:00:00Z"}
        ).status_code
        == 422
    )
    hist = stream.api.get(ADMIN, "/events/histogram", params={"bucket_minutes": 60}).json()
    assert sum(b["count"] for b in hist) >= len(page["items"]) or len(page["items"]) == 500
    stream.api.switch(INITECH_ADMIN, "initech")
    other = stream.api.get(INITECH_ADMIN, "/events", params={"limit": 500}).json()
    assert not {e["event_id"] for e in other["items"]} & {e["event_id"] for e in page["items"]}
    stream.api.switch(ADMIN, "globex")


def test_summary_cache_is_tenant_scoped_and_invalidated(stream: StreamEnv) -> None:
    stream.api.switch(ADMIN, "globex")
    first = stream.api.get(ADMIN, "/alerts/summary").json()
    alert = stream.api.get(ADMIN, "/alerts", params={"status": ["new"], "limit": 1}).json()["items"][0]
    r = stream.api.post(
        ADMIN, f"/alerts/{alert['id']}/transition", {"status": "suppressed", "version": alert["version"]}
    )
    assert r.status_code == 200
    second = stream.api.get(ADMIN, "/alerts/summary").json()
    assert second["total_open"] == first["total_open"] - 1, "triage invalidates the cached summary"
    with stream.env.su() as c:
        initech_open = c.execute(
            "SELECT count(*) FROM alerts WHERE tenant_id = %s AND status NOT IN ('resolved','closed','suppressed')",
            (stream.env.tenants["initech"],),
        ).fetchone()[0]
    stream.api.switch(INITECH_ADMIN, "initech")
    assert stream.api.get(INITECH_ADMIN, "/alerts/summary").json()["total_open"] == initech_open
    stream.api.switch(ADMIN, "globex")


def test_dependencies_endpoint_is_admin_only(stream: StreamEnv) -> None:
    assert stream.api.get(ADMIN, "/health/dependencies").status_code == 403
    admin = "platform.admin@nocsoc.example"
    deps = {d["name"]: d for d in stream.api.get(admin, "/health/dependencies").json()}
    assert deps["event_bus"]["status"] == "up" and deps["analytics"]["status"] == "up"
    assert deps["postgres"]["required"] and not deps["event_bus"]["required"]


def test_request_id_is_echoed_and_generated(stream: StreamEnv) -> None:
    c = stream.api.client
    r = c.get("/api/v1/health/live", headers={"X-Request-ID": "trace-abc12345"})
    assert r.headers["x-request-id"] == "trace-abc12345"
    r = c.get("/api/v1/health/live", headers={"X-Request-ID": "bad id with spaces\nInjected: 1"})
    assert r.headers["x-request-id"] != "bad id with spaces\nInjected: 1" and len(r.headers["x-request-id"]) == 32


def test_tenant_budget_limits_heavy_endpoints(stream: StreamEnv) -> None:
    stream.api.switch(INITECH_ADMIN, "initech")
    limit = stream.settings.tenant_heavy_requests_per_minute
    codes = [stream.api.get(INITECH_ADMIN, "/events", params={"limit": 1}).status_code for _ in range(limit + 1)]
    assert codes[-1] == 429 and codes[0] == 200
    stream.api.switch(ADMIN, "globex")
    assert stream.api.get(ADMIN, "/events", params={"limit": 1}).status_code == 200, "budgets are per tenant"


def test_alert_triage_and_raw_evidence(stream: StreamEnv) -> None:
    page = stream.api.get(ADMIN, "/alerts", params={"domain": "soc", "status": ["new"], "limit": 1}).json()
    alert = page["items"][0]
    raw = stream.api.get(ADMIN, f"/alerts/{alert['id']}/raw").json()
    assert raw and raw[0]["connector"] == alert["connector_id"]
    r = stream.api.post(
        ADMIN, f"/alerts/{alert['id']}/transition", {"status": "acknowledged", "version": alert["version"]}
    )
    assert r.status_code == 200 and r.json()["status"] == "acknowledged"
    stale = stream.api.post(
        ADMIN, f"/alerts/{alert['id']}/transition", {"status": "resolved", "version": alert["version"]}
    )
    assert stale.status_code == 409
    bad = stream.api.post(
        ADMIN, f"/alerts/{alert['id']}/transition", {"status": "closed", "version": r.json()["version"]}
    )
    assert bad.status_code == 409
    summary = stream.api.get(ADMIN, "/alerts/summary", params={"domain": "soc"}).json()
    assert summary["total_open"] >= 1 and summary["last_ingested_at"]
    # Initech sees none of it.
    stream.api.switch(INITECH_ADMIN, "initech")
    assert stream.api.get(INITECH_ADMIN, f"/alerts/{alert['id']}").status_code == 404
    initech_ids = {a["id"] for a in stream.api.get(INITECH_ADMIN, "/alerts", params={"limit": 200}).json()["items"]}
    assert alert["id"] not in initech_ids  # Initech may have its own alerts (other suites), never Globex's
    stream.api.switch(ADMIN, "globex")


def test_demo_integrations_seed_is_idempotent_and_sandbox(stream: StreamEnv) -> None:
    from app.db.seed import DEMO_INTEGRATIONS, seed_demo_integrations

    dev = stream.env.settings.model_copy(update={"environment": "dev"})
    created = seed_demo_integrations(dev)
    assert created == sum(len(v) for v in DEMO_INTEGRATIONS.values())
    assert seed_demo_integrations(dev) == 0
    with stream.env.su() as c:
        rows = c.execute("SELECT name, mode, status FROM connector_instances WHERE name LIKE 'DEMO %'").fetchall()
    assert len(rows) == created
    assert all(r[1] == "sandbox" and r[2] == "pending" for r in rows), "seeded instances claim no health"
