"""P6 through the real stack: scenario replay -> ingest worker -> Postgres -> projector ->
ClickHouse facts and OpenSearch (security plugin on) -> KPI, search, hunt, report and briefing APIs.

Exit criteria covered here:
- every KPI matches a reference calculation over Postgres (``compute_metrics`` and plain counts)
  and is drillable to exactly the records behind it;
- SEC-ISO-03 extended to OpenSearch: tenant-only index names plus a tenant filter, store users
  that can only read or only write, no client-supplied index or DSL.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import time
import uuid
from collections import namedtuple
from datetime import UTC, datetime
from typing import Any

import clickhouse_connect
import httpx
import pytest
from support.insights import InsightsEnv

from app.analytics import reader_client, reader_query
from app.incidents.sla import compute_metrics, merged_targets

pytestmark = pytest.mark.integration

ADMIN = {"globex": "admin@globex.example", "initech": "admin@initech.example"}
EXEC = "msp.exec@acme.example"
Row = namedtuple("Row", "id priority status detected_at acknowledged_at resolved_at")


# ---------------------------------------------------------------- helpers
def instance(s: InsightsEnv, slug: str, definition_id: str) -> dict[str, Any]:
    email = ADMIN[slug]
    s.api.switch(email, slug)
    existing = sorted(
        (i for i in s.api.get(email, "/connectors/instances").json() if i["definition_id"] == definition_id),
        key=lambda i: i["created_at"],
    )
    if existing:
        return existing[0]  # type: ignore[no-any-return]
    r = s.api.post(email, "/connectors/instances", {"definition_id": definition_id, "name": f"{definition_id} p6"})
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def replay(s: InsightsEnv, slug: str, scenario: str) -> None:
    from nocsoc_connectors import SCENARIOS

    for cid in SCENARIOS[scenario].connectors:
        instance(s, slug, cid)
    r = s.api.post(ADMIN[slug], f"/connectors/scenarios/{scenario}/replay")
    assert r.status_code == 200, r.text
    s.drain(minimum=int(r.json()["published"]))


def move(s: InsightsEnv, slug: str, incident_id: str, to: str) -> None:
    email = ADMIN[slug]
    inc = s.api.get(email, f"/incidents/{incident_id}").json()
    r = s.api.post(email, f"/incidents/{incident_id}/status", {"to": to, "version": inc["version"]})
    assert r.status_code == 200, r.text


def reference(s: InsightsEnv, slug: str, domain: str, since: datetime) -> dict[str, Any]:
    """The KPIs computed straight from Postgres, independently of the analytics pipeline."""
    t = s.env.tenants[slug]
    inc_dom = {"all": "TRUE", "noc": "domain IN ('noc', 'joint')", "soc": "domain IN ('soc', 'joint')"}[domain]
    al_dom = {"all": "TRUE", "noc": "a.domain = 'noc'", "soc": "a.domain = 'soc'"}[domain]
    with s.env.su() as c:
        rows = [
            Row(*r)
            for r in c.execute(
                "SELECT id, priority, status, detected_at, acknowledged_at, resolved_at FROM incidents "
                f"WHERE tenant_id = %s AND merged_into_id IS NULL AND detected_at >= %s AND {inc_dom}",
                (t, since),
            )
        ]
        custom = c.execute("SELECT targets FROM sla_policies WHERE tenant_id = %s", (t,)).fetchone()
        automated = {
            r[0]
            for r in c.execute(
                "SELECT DISTINCT incident_id FROM action_requests WHERE tenant_id = %s AND status = 'succeeded' "
                "AND incident_id IS NOT NULL",
                (t,),
            )
        }
        alerts = c.execute(
            "SELECT a.id, ia.incident_id FROM alerts a LEFT JOIN incident_alerts ia ON ia.alert_id = a.id "
            f"WHERE a.tenant_id = %s AND a.first_seen >= %s AND {al_dom}",
            (t, since),
        ).fetchall()
    m = compute_metrics(rows, merged_targets(custom[0] if custom else None), datetime.now(UTC))
    return {
        "metrics": m,
        "incident_ids": {str(r.id) for r in rows},
        "automated": sum(1 for r in rows if r.id in automated),
        "alert_ids": {str(a[0]) for a in alerts},
        "not_escalated": sum(1 for a in alerts if a[1] is None),
    }


def kpis(s: InsightsEnv, email: str, domain: str = "all", period: str = "7d") -> dict[str, Any]:
    r = s.api.get(email, "/analytics/kpis", params={"domain": domain, "period": period})
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


def by_key(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {k["key"]: k for k in body["kpis"]}


def ch_admin(s: InsightsEnv) -> Any:
    assert s.settings.clickhouse_admin_password
    return clickhouse_connect.get_client(
        host=s.settings.clickhouse_host,
        port=s.settings.clickhouse_port,
        username=s.settings.clickhouse_admin_user,
        password=s.settings.clickhouse_admin_password.get_secret_value(),
        database=s.settings.clickhouse_database,
    )


@pytest.fixture(scope="module")
def data(insights: InsightsEnv) -> InsightsEnv:
    """Globex: a joint ransomware incident, a NOC core-switch incident and pure noise; one
    incident acknowledged, one resolved, one with a succeeded (simulated) action. Initech gets
    the same ransomware scenario, so both tenants hold look-alike events."""
    s = insights
    replay(s, "globex", "ransomware_precursor")
    replay(s, "globex", "core_switch_failure")
    replay(s, "globex", "noise_flapping")
    replay(s, "initech", "ransomware_precursor")
    s.api.switch(ADMIN["globex"], "globex")
    items = s.api.get(ADMIN["globex"], "/incidents", params={"open_only": "true", "limit": 200}).json()["items"]
    assert len(items) >= 2, items
    move(s, "globex", items[0]["id"], "investigating")
    move(s, "globex", items[1]["id"], "resolved")
    with s.env.su() as c:
        c.execute(
            "INSERT INTO action_requests (tenant_id, incident_id, action_key, connector_id, target, tier, "
            "required_approvals, requested_by_type, policy_decision, execution_mode, status, executed_at) VALUES "
            "(%s, %s, 'platform.timeline_note', 'platform', '{}', 'T0', 0, 'user', '{\"decision\": \"auto\"}', "
            "'simulate', 'succeeded', now())",
            (s.env.tenants["globex"], items[0]["id"]),
        )
    s.project()
    return s


# ---------------------------------------------------------------- KPIs: reference calculation and drill-down
@pytest.mark.parametrize("domain", ["all", "noc", "soc"])
def test_kpis_match_reference_calculation(data: InsightsEnv, domain: str) -> None:
    data.api.switch(ADMIN["globex"], "globex")
    body = kpis(data, ADMIN["globex"], domain)
    k = by_key(body)
    ref = reference(data, "globex", domain, datetime.fromisoformat(body["since"]))
    m = ref["metrics"]
    assert k["incidents_opened"]["value"] == m["total"]
    assert k["open_incidents"]["value"] == m["open"]
    assert k["mtta"]["basis"] == m["acknowledged"]
    assert k["mttr"]["basis"] == m["resolved"]
    for key, ref_value in (("mtta", m["mtta_seconds"]), ("mttr", m["mttr_seconds"])):
        if ref_value is None:
            assert k[key]["value"] is None
        else:
            assert k[key]["value"] == pytest.approx(ref_value, abs=0.5), key
    for key, ref_value in (("ack_sla", m["ack_sla_attainment"]), ("resolve_sla", m["resolve_sla_attainment"])):
        assert k[key]["value"] == (pytest.approx(ref_value) if ref_value is not None else None), key
    assert k["automation_rate"]["numerator"] == ref["automated"]
    assert k["alert_volume"]["value"] == len(ref["alert_ids"])
    assert k["noise_ratio"]["numerator"] == ref["not_escalated"]
    if domain == "all":
        assert m["total"] >= 2 and m["acknowledged"] >= 1 and m["resolved"] >= 1 and ref["automated"] >= 1
        assert len(ref["alert_ids"]) > m["total"] and ref["not_escalated"] > 0


KPI_KEYS = [
    "incidents_opened",
    "open_incidents",
    "mtta",
    "mttr",
    "ack_sla",
    "resolve_sla",
    "automation_rate",
    "alert_volume",
    "noise_ratio",
]


@pytest.mark.parametrize("key", KPI_KEYS)
def test_every_kpi_drills_to_its_records(data: InsightsEnv, key: str) -> None:
    data.api.switch(ADMIN["globex"], "globex")
    k = by_key(kpis(data, ADMIN["globex"]))[key]
    r = data.api.get(ADMIN["globex"], f"/analytics/kpis/{key}/records", params={"period": "7d"})
    assert r.status_code == 200, r.text
    drill = r.json()
    assert drill["records"] == k["records"]
    assert drill["total"] == k["basis"], "the drill-down lists exactly the records behind the KPI"
    if k["numerator"] is not None:
        assert drill["counted"] == k["numerator"]
    if key == "open_incidents":
        assert drill["total"] == k["value"]
    if key in ("mtta", "mttr") and drill["items"]:
        mean = sum(i["seconds"] for i in drill["items"]) / len(drill["items"])
        assert mean == pytest.approx(k["value"], abs=0.5)


def test_drill_records_are_the_reference_records(data: InsightsEnv) -> None:
    data.api.switch(ADMIN["globex"], "globex")
    body = kpis(data, ADMIN["globex"])
    ref = reference(data, "globex", "all", datetime.fromisoformat(body["since"]))
    incidents = data.api.get(ADMIN["globex"], "/analytics/kpis/incidents_opened/records").json()
    alerts = data.api.get(ADMIN["globex"], "/analytics/kpis/alert_volume/records", params={"limit": 1000}).json()
    assert {i["id"] for i in incidents["items"]} == ref["incident_ids"]
    assert {a["id"] for a in alerts["items"]} == ref["alert_ids"]


def test_projection_follows_changes(data: InsightsEnv) -> None:
    data.api.switch(ADMIN["globex"], "globex")
    before = by_key(kpis(data, ADMIN["globex"]))["open_incidents"]["value"]
    items = data.api.get(ADMIN["globex"], "/incidents", params={"open_only": "true", "limit": 200}).json()["items"]
    move(data, "globex", items[0]["id"], "resolved")
    data.project()
    after = by_key(kpis(data, ADMIN["globex"]))["open_incidents"]["value"]
    assert after == before - 1


def test_search_outage_does_not_stall_facts(data: InsightsEnv) -> None:
    """Each sink has its own watermark: with OpenSearch unreachable, facts still advance, and
    search catches up once it is back."""
    from app.analytics import ingest_client
    from app.db.engines import AppDatabase
    from app.projector import Projector
    from app.searchstore import SearchStore

    data.api.switch(ADMIN["globex"], "globex")
    before = by_key(kpis(data, ADMIN["globex"]))["open_incidents"]["value"]
    r = data.api.post(ADMIN["globex"], "/incidents", {"title": "Sink outage probe", "domain": "noc", "severity": "low"})
    assert r.status_code == 201, r.text

    async def facts_only_with_dead_search() -> None:
        db = AppDatabase(data.settings, url=data.settings.worker_database_url())
        ch = await ingest_client(data.settings)
        dead = SearchStore("http://127.0.0.1:9", "nocsoc_indexer", "x", timeout=1)
        try:
            projector = Projector(db, ch, dead, data.settings.clickhouse_database)
            await projector.run_once()
            assert projector.stats["failed"] > 0, "the search sink failed"
        finally:
            await dead.close()
            await ch.close()
            await db.dispose()

    asyncio.run(facts_only_with_dead_search())
    assert by_key(kpis(data, ADMIN["globex"]))["open_incidents"]["value"] == before + 1
    hits = data.api.get(ADMIN["globex"], "/search", params={"q": "Sink outage probe"}).json()
    assert r.json()["id"] not in {h["id"] for h in hits["hits"]} or hits["engine"] == "postgres"
    data.project()
    hits = data.api.get(ADMIN["globex"], "/search", params={"q": "Sink outage probe"}).json()
    assert hits["engine"] == "opensearch" and r.json()["id"] in {h["id"] for h in hits["hits"]}


def test_timeseries_counts_add_up(data: InsightsEnv) -> None:
    data.api.switch(ADMIN["globex"], "globex")
    k = by_key(kpis(data, ADMIN["globex"]))
    series = data.api.get(
        ADMIN["globex"], "/analytics/timeseries", params={"metric": "alerts", "interval": "hour", "period": "7d"}
    ).json()
    assert sum(p["count"] for p in series) == k["alert_volume"]["value"]
    incidents = data.api.get(
        ADMIN["globex"], "/analytics/timeseries", params={"metric": "incidents", "group_by": "domain"}
    ).json()
    assert sum(p["count"] for p in incidents) == k["incidents_opened"]["value"]


def test_command_center_overview(data: InsightsEnv) -> None:
    data.api.switch(ADMIN["globex"], "globex")
    r = data.api.get(ADMIN["globex"], "/command-center/overview")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body["kpis"]) == {"all", "noc", "soc"}
    assert by_key({"kpis": body["kpis"]["all"]}) == by_key(kpis(data, ADMIN["globex"]))
    assert all(i["priority"] in ("P1", "P2") for i in body["open_incidents"])


def test_msp_aggregate_command_center_matches_each_customer(data: InsightsEnv) -> None:
    data.api.switch(EXEC, "acme-msp", aggregate=True)
    r = data.api.get(EXEC, "/command-center/customers")
    assert r.status_code == 200, r.text
    customers = {c["slug"]: by_key(c) for c in r.json()}
    assert set(customers) == {"globex", "initech"}
    for slug in ("globex", "initech"):
        data.api.switch(ADMIN[slug], slug)
        own = by_key(kpis(data, ADMIN[slug]))
        for key in KPI_KEYS:
            assert customers[slug][key]["value"] == own[key]["value"], (slug, key)
            assert customers[slug][key]["basis"] == own[key]["basis"], (slug, key)
    # Tenant endpoints stay closed in aggregate mode; the aggregate endpoint is closed in tenant mode.
    data.api.switch(EXEC, "acme-msp", aggregate=True)
    assert data.api.get(EXEC, "/analytics/kpis").status_code in (403, 409)
    data.api.switch(EXEC, "globex")
    assert data.api.get(EXEC, "/command-center/customers").status_code in (403, 409)


# ---------------------------------------------------------------- SEC-ISO-03: ClickHouse
def test_clickhouse_facts_are_tenant_bound(data: InsightsEnv) -> None:
    globex, initech = (uuid.UUID(data.env.tenants[s]) for s in ("globex", "initech"))

    async def go() -> None:
        client = await reader_client(data.settings)
        try:
            for table in ("alert_facts", "incident_facts", "action_facts"):
                rows = await reader_query(client, initech, f"SELECT DISTINCT tenant_id FROM {table}", {})
                assert {r["tenant_id"] for r in rows} <= {initech}, table
            both = await reader_query(client, [globex, initech], "SELECT DISTINCT tenant_id FROM alert_facts", {})
            assert {r["tenant_id"] for r in both} == {globex, initech}
            with pytest.raises(Exception, match="SQL_tenant_id"):
                await client.query("SELECT count() FROM alert_facts")
            empty = await client.query("SELECT count() FROM alert_facts", settings={"SQL_tenant_id": ""})
            assert empty.result_rows[0][0] == 0
        finally:
            await client.close()

    asyncio.run(go())


# ---------------------------------------------------------------- SEC-ISO-03: OpenSearch
def _events(s: InsightsEnv, slug: str, query: dict[str, Any], limit: int = 500) -> dict[str, Any]:
    s.api.switch(ADMIN[slug], slug)
    r = s.api.post(ADMIN[slug], "/search/events", {"query": query, "limit": limit})
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


def _event_tenants(s: InsightsEnv, event_ids: list[str]) -> set[str]:
    client = ch_admin(s)
    try:
        rows = client.query(
            "SELECT DISTINCT toString(tenant_id) FROM events WHERE event_id IN {ids:Array(String)}",
            parameters={"ids": event_ids},
        ).result_rows
    finally:
        client.close()
    return {r[0] for r in rows}


def test_event_search_only_returns_own_tenant(data: InsightsEnv) -> None:
    data.refresh_now()
    for slug, other in (("globex", "initech"), ("initech", "globex")):
        found = _events(data, slug, {"domain": "soc"})
        assert found["total"] > 0, slug
        ids = [e["event_id"] for e in found["items"]]
        assert _event_tenants(data, ids) == {data.env.tenants[slug]}, "only the caller's events"
        everything = _events(data, slug, {"text": "*"})
        assert data.env.tenants[other] not in _event_tenants(data, [e["event_id"] for e in everything["items"]])
    assert set(found["facets"]) == {"severity", "asset", "actor_user", "connector"}


@pytest.mark.parametrize(
    "query",
    [
        {"text": "x", "index": "t-*"},
        {"text": "x", "tenant_id": "00000000-0000-0000-0000-000000000000"},
        {"script": {"source": "1"}},
        {"mitre": ["T1059; DROP"]},
        {"ip": "not-an-ip"},
        {"since": "2020-01-01T00:00:00Z", "until": "2026-01-01T00:00:00Z"},
    ],
)
def test_event_query_is_constrained(data: InsightsEnv, query: dict[str, Any]) -> None:
    data.api.switch(ADMIN["globex"], "globex")
    r = data.api.post(ADMIN["globex"], "/search/events", {"query": query})
    assert r.status_code == 422, r.text


def test_opensearch_store_users_are_least_privilege(data: InsightsEnv) -> None:
    s = data.settings
    assert s.opensearch_url and s.opensearch_reader_password and s.opensearch_indexer_password
    url = s.opensearch_url
    reader = ("nocsoc_reader", s.opensearch_reader_password.get_secret_value())
    indexer = ("nocsoc_indexer", s.opensearch_indexer_password.get_secret_value())
    globex = uuid.UUID(data.env.tenants["globex"]).hex
    action = json.dumps({"index": {"_index": f"t-{globex}-events-2026.11", "_id": "evil"}})
    bulk = action + "\n" + json.dumps({"tenant_id": "x"}) + "\n"
    with httpx.Client(base_url=url, timeout=20) as c:
        assert c.get("/_cluster/health").status_code == 401, "no anonymous access"
        r = c.post("/_bulk", auth=reader, content=bulk, headers={"content-type": "application/x-ndjson"})
        assert r.status_code == 403, "the API's user cannot write"
        assert c.post(f"/t-{globex}-events-*/_search", auth=indexer, json={}).status_code == 403, "writer cannot read"
        assert c.get("/_cat/indices", auth=reader).status_code == 403
        assert c.post("/.opendistro_security/_search", auth=reader, json={}).status_code == 403
        assert c.put("/other/_doc/1", auth=indexer, json={"a": 1}).status_code == 403, "only t-* indices"


def test_global_search_uses_opensearch_within_tenant(data: InsightsEnv) -> None:
    data.api.switch(ADMIN["globex"], "globex")
    inc = data.api.get(ADMIN["globex"], "/incidents", params={"limit": 1}).json()["items"][0]
    r = data.api.get(ADMIN["globex"], "/search", params={"q": inc["number"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["engine"] == "opensearch"
    assert inc["id"] in {h["id"] for h in body["hits"]}
    data.api.switch(ADMIN["initech"], "initech")
    other = data.api.get(ADMIN["initech"], "/search", params={"q": inc["title"][:40]}).json()
    with data.env.su() as c:
        globex_ids = {
            str(r[0]) for r in c.execute("SELECT id FROM incidents WHERE tenant_id = %s", (data.env.tenants["globex"],))
        }
        globex_ids |= {
            str(r[0]) for r in c.execute("SELECT id FROM alerts WHERE tenant_id = %s", (data.env.tenants["globex"],))
        }
    assert not ({h["id"] for h in other["hits"]} & globex_ids)


def test_tampered_tenant_field_in_index_is_still_filtered(data: InsightsEnv) -> None:
    """Defence in depth: even a document planted in Globex's index claiming another tenant
    is not returned, because every query also filters on the caller's tenant."""
    globex = data.env.tenants["globex"]
    index = f"t-{uuid.UUID(globex).hex}-events-{datetime.now(UTC):%Y.%m}"
    with httpx.Client(base_url=data.settings.opensearch_url or "", timeout=20) as c:
        doc = {
            "tenant_id": data.env.tenants["initech"],
            "event_id": "planted",
            "domain": "soc",
            "class": "detection",
            "severity": "high",
            "observed_at": datetime.now(UTC).isoformat(),
            "connector": "x",
            "instance_id": "x",
            "source_id": "x",
            "title": "planted cross-tenant doc",
        }
        r = c.put(f"/{index}/_doc/planted", auth=("admin", data.admin_password), json=doc, params={"refresh": "true"})
        assert r.status_code in (200, 201), r.text
    found = _events(data, "globex", {"text": "planted"})
    assert found["total"] == 0


# ---------------------------------------------------------------- hunting
def _wait_run(s: InsightsEnv, email: str, run_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        run = s.api.get(email, f"/hunt/queries/{run_id}").json()
        if run["status"] in ("succeeded", "failed"):
            return run  # type: ignore[no-any-return]
        time.sleep(0.3)
    raise AssertionError(f"hunt run {run_id} did not finish")


def test_saved_hunt_runs_async_and_matches_search(data: InsightsEnv) -> None:
    email = ADMIN["globex"]
    data.api.switch(email, "globex")
    query = {"domain": "soc"}
    hunt = data.api.post(email, "/hunts", {"name": f"SOC sweep {uuid.uuid4().hex[:6]}", "query": query})
    assert hunt.status_code == 201, hunt.text
    started = data.api.post(email, "/hunt/queries", {"hunt_id": hunt.json()["id"]})
    assert started.status_code == 202, started.text
    run = _wait_run(data, email, started.json()["id"])
    assert run["status"] == "succeeded", run
    results = data.api.get(email, f"/hunt/queries/{run['id']}/results").json()
    expected = _events(data, "globex", query)
    assert results["hit_count"] == expected["total"]
    assert len(results["results"]) == min(expected["total"], 200)
    assert results["facets"]["severity"]
    listed = {h["id"]: h for h in data.api.get(email, "/hunts").json()}
    assert listed[hunt.json()["id"]]["last_hit_count"] == expected["total"]
    # Results to case: attach to an incident.
    inc = data.api.get(email, "/incidents", params={"limit": 1}).json()["items"][0]
    attached = data.api.post(email, f"/hunt/queries/{run['id']}/attach", {"incident_id": inc["id"], "note": "seen"})
    assert attached.status_code == 204, attached.text
    tl = data.api.get(email, f"/incidents/{inc['id']}/timeline").json()
    assert any(e["body"].get("hunt_run_id") == run["id"] for e in tl)
    # Another tenant cannot see the run.
    data.api.switch(ADMIN["initech"], "initech")
    assert data.api.get(ADMIN["initech"], f"/hunt/queries/{run['id']}").status_code == 404


def test_hunt_concurrency_quota(data: InsightsEnv) -> None:
    email = ADMIN["globex"]
    data.api.switch(email, "globex")
    t = data.env.tenants["globex"]
    with data.env.su() as c:
        ids = [
            c.execute(
                "INSERT INTO hunt_runs (tenant_id, query, status) VALUES (%s, '{}', 'running') RETURNING id", (t,)
            ).fetchone()[0]
            for _ in range(data.settings.hunt_max_concurrent)
        ]
    try:
        r = data.api.post(email, "/hunt/queries", {"query": {"text": "x"}})
        assert r.status_code == 429 and r.json()["code"] == "hunt.busy"
    finally:
        with data.env.su() as c:
            c.execute("DELETE FROM hunt_runs WHERE id = ANY(%s)", (ids,))


# ---------------------------------------------------------------- reports
def test_reports_export_csv_and_pdf(data: InsightsEnv) -> None:
    email = ADMIN["globex"]
    data.api.switch(email, "globex")
    rep = data.api.post(email, "/reports", {"name": f"Weekly KPIs {uuid.uuid4().hex[:6]}", "kind": "kpi_summary"})
    assert rep.status_code == 201, rep.text
    r = data.api.client.get(
        f"/api/v1/reports/{rep.json()['id']}/export", params={"format": "csv"}, headers=data.api.headers(email)
    )
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert rows[0] == ["KPI", "Value", "Numerator", "Basis", "Definition"]
    opened = next(row for row in rows if row[0] == "Incidents opened")
    assert opened[1] == f"{by_key(kpis(data, email))['incidents_opened']['value']:.0f}"
    pdf = data.api.client.get(
        f"/api/v1/reports/{rep.json()['id']}/export", params={"format": "pdf"}, headers=data.api.headers(email)
    )
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF-1.4") and pdf.content.rstrip().endswith(b"%%EOF")
    assert b"Incidents opened" in pdf.content
    with data.env.su() as c:
        exports = c.execute(
            "SELECT count(*) FROM audit_log WHERE tenant_id = %s AND action = 'report.export' AND target_id = %s",
            (data.env.tenants["globex"], rep.json()["id"]),
        ).fetchone()[0]
    assert exports == 2


def test_csv_export_neutralises_formulas(data: InsightsEnv) -> None:
    email = ADMIN["globex"]
    data.api.switch(email, "globex")
    evil = '=HYPERLINK("http://evil.example","click")'
    r = data.api.post(email, "/incidents", {"title": evil, "domain": "noc", "severity": "low"})
    assert r.status_code == 201, r.text
    rep = data.api.post(
        email, "/reports", {"name": f"Register {uuid.uuid4().hex[:6]}", "kind": "incident_register", "period": "24h"}
    )
    out = data.api.client.get(f"/api/v1/reports/{rep.json()['id']}/export", headers=data.api.headers(email))
    rows = list(csv.reader(io.StringIO(out.content.decode("utf-8-sig"))))
    titles = [row[1] for row in rows[1:]]
    assert "'" + evil in titles and evil not in titles


def test_executive_can_export_but_not_create(data: InsightsEnv) -> None:
    data.api.switch(ADMIN["globex"], "globex")
    rep = data.api.post(ADMIN["globex"], "/reports", {"name": f"SLA {uuid.uuid4().hex[:6]}", "kind": "sla_report"})
    data.api.switch(EXEC, "globex")
    r = data.api.client.get(f"/api/v1/reports/{rep.json()['id']}/export", headers=data.api.headers(EXEC))
    assert r.status_code == 200, r.text
    assert r.content.decode("utf-8-sig").startswith("Number,Priority,Status")
    assert data.api.post(EXEC, "/reports", {"name": "nope", "kind": "sla_report"}).status_code == 403


# ---------------------------------------------------------------- AI daily briefing
def test_daily_briefing_is_grounded_in_kpis(data: InsightsEnv) -> None:
    email = ADMIN["globex"]
    data.api.switch(email, "globex")
    r = data.api.post(email, "/ai/briefing")
    assert r.status_code == 200, r.text
    run = r.json()
    assert run["task"] == "daily_briefing" and run["validation_status"] == "grounded"
    kpi_refs = {e["ref"] for e in run["evidence"] if e["type"] == "kpi"}
    assert len(kpi_refs) == len(KPI_KEYS)
    cited = {ref for c in run["output"]["claims"] for ref in c["citations"]}
    assert cited & kpi_refs, "numbers in the briefing cite the KPIs they come from"
    # Executives read it without being able to generate one.
    data.api.switch(EXEC, "globex")
    latest = data.api.get(EXEC, "/ai/briefing/latest")
    assert latest.status_code == 200 and latest.json()["id"] == run["id"]
    assert data.api.post(EXEC, "/ai/briefing").status_code == 403
