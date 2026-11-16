"""IAM-5 (API keys) and platform administration."""

import pytest
from support.integration import Api

pytestmark = pytest.mark.integration

ADMIN = "admin@globex.example"


def test_api_key_lifecycle(api: Api) -> None:
    api.switch(ADMIN, "globex")
    api.step_up(ADMIN)
    created = api.post(ADMIN, "/api-keys", {"name": "reporting", "permissions": ["user:read"], "expires_in_days": 7})
    assert created.status_code == 201, created.text
    key = created.json()["key"]
    assert key.startswith("nsk_")
    listed = api.get(ADMIN, "/api-keys").json()
    assert all("key" not in k for k in listed), "the secret must only be returned once"

    h = {"Authorization": f"Bearer {key}"}
    assert api.client.get("/api/v1/users", headers=h).status_code == 200
    assert api.client.get("/api/v1/roles", headers=h).status_code == 403  # not granted
    assert api.client.get("/api/v1/auth/me", headers=h).status_code == 401  # session-only
    # Keys can never step up, so sensitive endpoints are closed to them.
    assert (
        api.client.post("/api/v1/roles", headers=h, json={"key": "k", "name": "k", "permissions": []}).status_code
        == 403
    )

    assert api.delete(ADMIN, f"/api-keys/{created.json()['id']}").status_code == 204
    assert api.client.get("/api/v1/users", headers=h).status_code == 401


def test_api_key_permissions_are_validated(api: Api) -> None:
    api.switch(ADMIN, "globex")
    api.step_up(ADMIN)
    msp_only = api.post(ADMIN, "/api-keys", {"name": "msp", "permissions": ["msp:aggregate_read"]})
    assert msp_only.status_code == 422
    unknown = api.post(ADMIN, "/api-keys", {"name": "bogus", "permissions": ["root:everything"]})
    assert unknown.status_code == 422


def test_platform_admin_manages_tenants_without_data_access(api: Api) -> None:
    pa = "platform.admin@nocsoc.example"
    tenants = api.get(pa, "/platform/tenants").json()
    assert {"acme-msp", "globex", "initech"} <= {t["slug"] for t in tenants}
    r = api.post(
        pa,
        "/platform/tenants",
        {"name": "Umbrella MSP", "slug": "umbrella", "admin_email": "admin@umbrella.example", "admin_name": "Uma"},
    )
    assert r.status_code == 201, r.text
    # No tenant membership, so no tenant data.
    r = api.get(pa, "/users")
    assert r.status_code == 409
    assert r.json()["code"] == "tenant.none_selected"


def test_platform_endpoints_closed_to_tenant_admins(api: Api) -> None:
    assert api.get(ADMIN, "/platform/tenants").status_code == 403
