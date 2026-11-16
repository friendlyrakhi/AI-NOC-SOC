"""IAM-2a..2c, SEC-ISO-06/07, SEC-AUD-03: MSP delegations, aggregate view, onboarding."""

from urllib.parse import parse_qs, urlparse

import pytest
from support.integration import Api

from app.mail import MemoryMailer

pytestmark = pytest.mark.integration

MSP_ADMIN = "msp.admin@acme.example"
MSP_NOC = "msp.noc@acme.example"
MSP_SOC = "msp.soc@acme.example"


def _tenant_slugs(api: Api, email: str) -> dict[str, str]:
    by_id = {v: k for k, v in api.env.tenants.items()}
    return {by_id[t["id"]]: t["access"] for t in api.get(email, "/auth/me").json()["tenants"] if t["id"] in by_id}


def test_msp_staff_see_only_delegated_customers(api: Api) -> None:
    assert _tenant_slugs(api, MSP_NOC) == {"acme-msp": "member", "globex": "delegated"}
    assert _tenant_slugs(api, MSP_SOC) == {"acme-msp": "member", "initech": "delegated"}
    assert _tenant_slugs(api, MSP_ADMIN) == {"acme-msp": "member", "globex": "delegated", "initech": "delegated"}


def test_delegated_permissions_apply_in_customer(api: Api) -> None:
    api.switch(MSP_NOC, "globex")
    me = api.get(MSP_NOC, "/auth/me").json()
    assert me["via_msp_tenant_id"] == api.env.tenants["acme-msp"]
    assert "portal:noc" in me["permissions"]
    assert "user:read" not in me["permissions"]
    assert api.get(MSP_NOC, "/users").status_code == 403
    r = api.post(MSP_NOC, "/auth/switch-tenant", {"tenant_id": api.env.tenants["initech"]})
    assert r.status_code == 404


def test_aggregate_view_is_scoped_and_read_only(api: Api) -> None:
    api.switch(MSP_NOC, "acme-msp", aggregate=True)
    me = api.get(MSP_NOC, "/auth/me").json()
    assert me["mode"] == "aggregate"
    assert me["aggregate_tenant_ids"] == [api.env.tenants["globex"]]
    customers = api.get(MSP_NOC, "/aggregate/customers").json()
    assert [c["slug"] for c in customers] == ["globex"]
    # Tenant endpoints refuse to run in aggregate mode.
    r = api.get(MSP_NOC, "/users")
    assert r.status_code == 409
    assert r.json()["code"] == "tenant.aggregate_read_only"
    # Activity needs audit:read too.
    assert api.get(MSP_NOC, "/aggregate/activity").status_code == 403


def test_msp_admin_aggregate_sees_both_customers(api: Api) -> None:
    api.switch(MSP_ADMIN, "acme-msp", aggregate=True)
    slugs = [c["slug"] for c in api.get(MSP_ADMIN, "/aggregate/customers").json()]
    assert slugs == ["globex", "initech"]
    activity = api.get(MSP_ADMIN, "/aggregate/activity").json()
    assert {a["tenant_id"] for a in activity} <= {api.env.tenants["globex"], api.env.tenants["initech"]}


def test_delegated_actions_are_audited_in_both_chains(api: Api) -> None:
    api.switch(MSP_ADMIN, "globex")
    api.step_up(MSP_ADMIN)
    r = api.post(MSP_ADMIN, "/roles", {"key": "msp_made", "name": "Made by MSP", "permissions": ["user:read"]})
    assert r.status_code == 201, r.text
    role_id = r.json()["id"]
    with api.env.su() as c:
        rows = c.execute(
            "SELECT tenant_id::text, via_tenant_id::text, details->>'delegated_into' FROM audit_log "
            "WHERE action = 'role.create' AND target_id = %s ORDER BY id",
            (role_id,),
        ).fetchall()
    globex, acme = api.env.tenants["globex"], api.env.tenants["acme-msp"]
    assert (globex, acme, None) in rows  # customer chain, marked as via the MSP
    assert (acme, None, globex) in rows  # MSP chain mirror


def test_customer_sees_and_revokes_delegation_immediately(api: Api) -> None:
    customer_admin = "admin@globex.example"
    api.switch(MSP_NOC, "globex")
    assert api.get(MSP_NOC, "/auth/me").json()["mode"] == "tenant"

    api.switch(customer_admin, "globex")
    api.step_up(customer_admin)
    incoming = [d for d in api.get(customer_admin, "/delegations").json() if d["direction"] == "incoming"]
    assert incoming
    assert all(d["msp_tenant"]["name"] == "Acme Managed Services" for d in incoming)
    noc = next(d for d in incoming if d["customer_role_key"] == "noc_analyst" and d["active"])
    r = api.post(customer_admin, f"/delegations/{noc['id']}/revoke")
    assert r.status_code == 200, r.text
    assert r.json()["active"] is False

    # Next request: the MSP analyst no longer has access to Globex.
    me = api.get(MSP_NOC, "/auth/me").json()
    assert me["mode"] == "none"
    assert api.env.tenants["globex"] not in {t["id"] for t in me["tenants"]}
    # And the MSP sees the revocation in its own audit chain.
    with api.env.su() as c:
        row = c.execute(
            "SELECT 1 FROM audit_log WHERE tenant_id = %s AND action = 'delegation.revoke' AND target_id = %s",
            (api.env.tenants["acme-msp"], noc["id"]),
        ).fetchone()
    assert row is not None


def test_customer_onboarding_end_to_end(api: Api, mailer: MemoryMailer) -> None:
    api.switch(MSP_ADMIN, "acme-msp")
    api.step_up(MSP_ADMIN)
    r = api.post(
        MSP_ADMIN,
        "/customers",
        {"name": "Hooli", "slug": "hooli", "admin_email": "admin@hooli.example", "admin_name": "Holly Admin"},
    )
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["invitation_sent"] is True
    assert len(created["delegation_ids"]) == 1

    mail = next(m for m in reversed(mailer.sent) if m.to == "admin@hooli.example")
    link = next(line for line in mail.body.splitlines() if "/invite/accept?token=" in line)
    token = parse_qs(urlparse(link).query)["token"][0]

    weak = api.client.post("/api/v1/auth/invitations/accept", json={"token": token, "password": "short"})
    assert weak.status_code == 422
    password = "Hooli-Admin-Password-1"
    ok = api.client.post("/api/v1/auth/invitations/accept", json={"token": token, "password": password})
    assert ok.status_code == 200
    reuse = api.client.post("/api/v1/auth/invitations/accept", json={"token": token, "password": password})
    assert reuse.status_code == 404

    # tenant_admin is privileged, so the first sign-in requires MFA enrollment.
    login = api.client.post("/api/v1/auth/login", json={"email": "admin@hooli.example", "password": password}).json()
    assert login["status"] == "mfa_enrollment_required"
    enroll = api.client.post("/api/v1/auth/mfa/enroll", json={"challenge": login["challenge"]}).json()
    assert enroll["otpauth_uri"].startswith("otpauth://totp/")
    from app.core.security import current_totp

    confirm = api.client.post(
        "/api/v1/auth/mfa/confirm", json={"challenge": login["challenge"], "code": current_totp(enroll["secret"])}
    )
    assert confirm.status_code == 200, confirm.text
    h = {"Authorization": f"Bearer {confirm.json()['session_token']}"}
    me = api.client.get("/api/v1/auth/me", headers=h).json()
    assert me["active_tenant_id"] == created["id"]
    assert "user:invite" in me["permissions"]
    incoming = api.client.get("/api/v1/delegations", headers=h).json()
    assert [d["direction"] for d in incoming] == ["incoming"]

    # The MSP admin can now work inside the new customer through the default delegation.
    r = api.post(MSP_ADMIN, "/auth/switch-tenant", {"tenant_id": created["id"]})
    assert r.status_code == 204


def test_msp_cannot_delegate_into_foreign_customer(api: Api) -> None:
    api.switch(MSP_ADMIN, "acme-msp")
    api.step_up(MSP_ADMIN)
    roles = api.get(MSP_ADMIN, "/roles").json()
    admin_role = next(r["id"] for r in roles if r["key"] == "tenant_admin")
    r = api.post(
        MSP_ADMIN,
        "/delegations",
        {
            "customer_tenant_id": api.env.tenants["acme-msp"],
            "msp_role_id": admin_role,
            "customer_role_key": "tenant_admin",
        },
    )
    assert r.status_code == 404
