"""SEC-ISO-01: cross-tenant access through the API, and route-permission coverage (IAM-3).

The generated part walks every route that takes an ID and calls it as a Globex admin with
IDs that belong to Initech. No call may succeed or change Initech's data.
"""

import re

import pytest
from support.integration import Api

pytestmark = pytest.mark.integration

GLOBEX_ADMIN = "admin@globex.example"
INITECH_ADMIN = "admin@initech.example"


def _operations(api: Api) -> list[tuple[str, str, dict]]:  # type: ignore[type-arg]
    """(METHOD, path, operation) from the OpenAPI document: the public contract, independent
    of framework internals (FastAPI 0.16x no longer exposes included routes on app.routes)."""
    spec = api.client.get("/api/v1/openapi.json").json()
    ops = [
        (method.upper(), path, op)
        for path, item in spec["paths"].items()
        for method, op in item.items()
        if method in {"get", "post", "put", "patch", "delete"}
    ]
    assert len(ops) >= 30, f"suspiciously few operations ({len(ops)}): route discovery is broken"
    return ops


def test_every_route_declares_authorization(api: Api) -> None:
    missing = [f"{m} {p}" for m, p, op in _operations(api) if not op.get("x-required-permission")]
    assert not missing, f"routes without an authorization marker: {missing}"


def test_public_routes_are_the_expected_few(api: Api) -> None:
    public = {f"{m} {p}" for m, p, op in _operations(api) if op.get("x-required-permission") == "public"}
    assert public == {
        "GET /api/v1/health/live",
        "GET /api/v1/health/ready",
        "POST /api/v1/auth/login",
        "POST /api/v1/auth/mfa/verify",
        "POST /api/v1/auth/mfa/enroll",
        "POST /api/v1/auth/mfa/confirm",
        "POST /api/v1/auth/invitations/accept",
    }


@pytest.fixture(scope="module")
def initech_ids(api: Api) -> dict[str, str]:
    """Objects owned by Initech: a member, a custom role, an API key, a delegation."""
    api.switch(INITECH_ADMIN, "initech")
    api.step_up(INITECH_ADMIN)
    role = api.post(
        INITECH_ADMIN, "/roles", {"key": "initech_private", "name": "Initech private", "permissions": ["user:read"]}
    )
    assert role.status_code == 201, role.text
    key = api.post(INITECH_ADMIN, "/api-keys", {"name": "initech key", "permissions": ["user:read"]})
    assert key.status_code == 201, key.text
    delegation = api.get(INITECH_ADMIN, "/delegations").json()[0]
    instance = api.post(INITECH_ADMIN, "/connectors/instances", {"definition_id": "prometheus", "name": "initech prom"})
    assert instance.status_code == 201, instance.text
    with api.env.su() as c:
        alert_id = c.execute(
            "INSERT INTO alerts (tenant_id, domain, connector_id, source_alert_id, fingerprint, title, severity, "
            "first_seen, last_seen) VALUES (%s, 'noc', 'prometheus', 'i-1', 'initech-fp', 'Initech private alert', "
            "'high', now(), now()) RETURNING id",
            (api.env.tenants["initech"],),
        ).fetchone()[0]
        asset_id = c.execute(
            "INSERT INTO assets (tenant_id, type, name) VALUES (%s, 'host', 'initech-host') RETURNING id",
            (api.env.tenants["initech"],),
        ).fetchone()[0]
        service_id = c.execute(
            "INSERT INTO services (tenant_id, name) VALUES (%s, 'Initech Billing') RETURNING id",
            (api.env.tenants["initech"],),
        ).fetchone()[0]
    incident = api.post(
        INITECH_ADMIN,
        "/incidents",
        {"title": "Initech private incident", "domain": "noc", "severity": "high", "alert_ids": [str(alert_id)]},
    )
    assert incident.status_code == 201, incident.text
    task = api.post(INITECH_ADMIN, f"/incidents/{incident.json()['id']}/tasks", {"title": "Initech task"})
    assert task.status_code == 201, task.text
    window = api.post(
        INITECH_ADMIN,
        "/maintenance-windows",
        {
            "title": "Initech window",
            "service_ids": [str(service_id)],
            "starts_at": "2030-01-01T00:00:00Z",
            "ends_at": "2030-01-01T02:00:00Z",
        },
    )
    assert window.status_code == 201, window.text
    rule = api.post(
        INITECH_ADMIN,
        "/suppression-rules",
        {"name": "Initech rule", "match": {"connector": "prometheus"}, "reason": "noise"},
    )
    assert rule.status_code == 201, rule.text
    return {
        "incident_id": incident.json()["id"],
        "task_id": task.json()["id"],
        "asset_id": str(asset_id),
        "service_id": str(service_id),
        "window_id": window.json()["id"],
        "rule_id": rule.json()["id"],
        "instance_id": instance.json()["id"],
        "alert_id": str(alert_id),
        "key": "core_switch_failure",  # a scenario key: replaying it may only ever touch the caller's tenant
        "user_id": api.env.users["soc@initech.example"]["id"],
        "role_id": role.json()["id"],
        "key_id": key.json()["id"],
        "delegation_id": delegation["id"],
        "tenant_id": api.env.tenants["initech"],
    }


def _initech_snapshot(api: Api) -> tuple:  # type: ignore[type-arg]
    with api.env.su() as c:
        t = api.env.tenants["initech"]
        return (
            c.execute("SELECT id, status FROM memberships WHERE tenant_id = %s ORDER BY id", (t,)).fetchall(),
            c.execute("SELECT id, name, version FROM roles WHERE tenant_id = %s ORDER BY id", (t,)).fetchall(),
            c.execute("SELECT id, revoked_at FROM api_keys WHERE tenant_id = %s ORDER BY id", (t,)).fetchall(),
            c.execute(
                "SELECT id, revoked_at FROM delegations WHERE customer_tenant_id = %s ORDER BY id", (t,)
            ).fetchall(),
            c.execute("SELECT count(*) FROM role_bindings WHERE tenant_id = %s", (t,)).fetchall(),
            c.execute(
                "SELECT id, name, config, enabled, secret_id, webhook_secret_id, sync_requested_at, status, version "
                "FROM connector_instances WHERE tenant_id = %s ORDER BY id",
                (t,),
            ).fetchall(),
            c.execute("SELECT id, status, version FROM alerts WHERE tenant_id = %s ORDER BY id", (t,)).fetchall(),
            c.execute("SELECT count(*) FROM connector_runs WHERE tenant_id = %s", (t,)).fetchall(),
            c.execute(
                "SELECT id, status, domain, priority, assignee_id, version FROM incidents "
                "WHERE tenant_id = %s ORDER BY id",
                (t,),
            ).fetchall(),
            c.execute("SELECT count(*) FROM timeline_entries WHERE tenant_id = %s", (t,)).fetchall(),
            c.execute(
                "SELECT alert_id, incident_id FROM incident_alerts WHERE tenant_id = %s ORDER BY 1", (t,)
            ).fetchall(),
            c.execute(
                "SELECT id, status, version FROM incident_tasks WHERE tenant_id = %s ORDER BY id", (t,)
            ).fetchall(),
            c.execute("SELECT count(*) FROM external_tickets WHERE tenant_id = %s", (t,)).fetchall(),
            c.execute(
                "SELECT id, cancelled_at FROM maintenance_windows WHERE tenant_id = %s ORDER BY id", (t,)
            ).fetchall(),
            c.execute("SELECT id, enabled FROM suppression_rules WHERE tenant_id = %s ORDER BY id", (t,)).fetchall(),
            c.execute("SELECT id, name, version FROM services WHERE tenant_id = %s ORDER BY id", (t,)).fetchall(),
        )


_BODIES = {
    "PATCH": {"status": "suspended", "name": "pwned", "description": "pwned", "permissions": []},
    "PUT": {"role_ids": []},
    "POST": {},
}


def test_foreign_ids_never_succeed(api: Api, initech_ids: dict[str, str]) -> None:
    api.switch(GLOBEX_ADMIN, "globex")
    api.step_up(GLOBEX_ADMIN)
    before = _initech_snapshot(api)
    tried = []
    for method, route_path, op in _operations(api):
        if "{" not in route_path:
            continue
        # Token/HMAC routes reject a user session outright; a scenario replay acts only on the
        # caller's own tenant (its ID is a catalog key), and with no event bus here it is 503.
        allowed = {403, 404, 409, 422}
        if op.get("x-required-permission") in {"internal", "webhook_hmac"}:
            allowed |= {401}
        if route_path.endswith("/scenarios/{key}/replay"):
            allowed |= {503}
        params = re.findall(r"{(\w+)}", route_path)
        if not all(p in initech_ids for p in params):
            pytest.fail(f"no foreign id for params {params} in {route_path}; extend initech_ids")
        path = route_path
        for p in params:
            path = path.replace("{" + p + "}", initech_ids[p])
        r = api.client.request(method, path, headers=api.headers(GLOBEX_ADMIN), json=_BODIES.get(method))
        tried.append((method, route_path, r.status_code))
        assert r.status_code in allowed, (method, route_path, r.status_code, r.text)
    assert len(tried) >= 8
    assert _initech_snapshot(api) == before, "a cross-tenant call changed Initech data"


def test_lists_contain_only_own_tenant(api: Api, initech_ids: dict[str, str]) -> None:
    api.switch(GLOBEX_ADMIN, "globex")
    users = api.get(GLOBEX_ADMIN, "/users").json()
    assert users
    assert all(u["email"].endswith("@globex.example") for u in users)
    roles = api.get(GLOBEX_ADMIN, "/roles").json()
    assert initech_ids["role_id"] not in {r["id"] for r in roles}
    keys = api.get(GLOBEX_ADMIN, "/api-keys").json()
    assert initech_ids["key_id"] not in {k["id"] for k in keys}
    audit = api.get(GLOBEX_ADMIN, "/audit", params={"limit": 200}).json()
    assert {a["tenant_id"] for a in audit} == {api.env.tenants["globex"]}


def test_cannot_switch_into_foreign_tenant(api: Api) -> None:
    r = api.post(GLOBEX_ADMIN, "/auth/switch-tenant", {"tenant_id": api.env.tenants["initech"]})
    assert r.status_code == 404
    r = api.post(GLOBEX_ADMIN, "/auth/switch-tenant", {"tenant_id": "00000000-0000-0000-0000-000000000000"})
    assert r.status_code == 404


def test_customer_cannot_use_msp_features(api: Api) -> None:
    api.switch(GLOBEX_ADMIN, "globex")
    me = api.get(GLOBEX_ADMIN, "/auth/me").json()
    assert not {"msp:customers:read", "msp:aggregate_read"} & set(me["permissions"])
    assert api.get(GLOBEX_ADMIN, "/customers").status_code == 403
    r = api.post(GLOBEX_ADMIN, "/auth/switch-tenant", {"tenant_id": api.env.tenants["globex"], "aggregate": True})
    assert r.status_code == 404
