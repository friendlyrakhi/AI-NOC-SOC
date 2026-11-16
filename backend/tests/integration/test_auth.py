"""IAM-1, SEC-AUTH-01: login, MFA enforcement, replay protection, rate limiting, sessions."""

import pytest
import redis
from fastapi.testclient import TestClient
from support.integration import Api, Env

pytestmark = pytest.mark.integration


def _login(client: TestClient, email: str, password: str) -> dict:  # type: ignore[type-arg]
    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    return {"status_code": r.status_code, **r.json()}


def test_non_privileged_user_signs_in_without_mfa(api: Api) -> None:
    u = api.env.users["msp.noc@acme.example"]
    out = _login(api.client, u["email"], u["password"])
    assert out["status_code"] == 200
    assert out["status"] == "authenticated"
    assert out["session_token"].startswith("nss_")


def test_privileged_user_must_pass_mfa(api: Api) -> None:
    u = api.env.users["admin@globex.example"]
    out = _login(api.client, u["email"], u["password"])
    assert out["status"] == "mfa_required"
    assert out["session_token"] is None
    bad = api.client.post("/api/v1/auth/mfa/verify", json={"challenge": out["challenge"], "code": "000000"})
    assert bad.status_code == 401
    assert bad.json()["code"] == "auth.mfa_invalid"
    good = api.client.post(
        "/api/v1/auth/mfa/verify", json={"challenge": out["challenge"], "code": api.code(u["email"])}
    )
    assert good.status_code == 200


def test_totp_code_cannot_be_replayed(api: Api) -> None:
    u = api.env.users["admin@initech.example"]
    code = api.code(u["email"])
    first = _login(api.client, u["email"], u["password"])
    assert (
        api.client.post("/api/v1/auth/mfa/verify", json={"challenge": first["challenge"], "code": code}).status_code
        == 200
    )
    second = _login(api.client, u["email"], u["password"])
    r = api.client.post("/api/v1/auth/mfa/verify", json={"challenge": second["challenge"], "code": code})
    assert r.status_code == 401


def test_challenge_is_single_use(api: Api) -> None:
    u = api.env.users["auditor@globex.example"]
    out = _login(api.client, u["email"], u["password"])
    ok = api.client.post("/api/v1/auth/mfa/verify", json={"challenge": out["challenge"], "code": api.code(u["email"])})
    assert ok.status_code == 200
    again = api.client.post(
        "/api/v1/auth/mfa/verify", json={"challenge": out["challenge"], "code": api.code(u["email"])}
    )
    assert again.status_code == 401
    assert again.json()["code"] == "auth.challenge_invalid"


def test_wrong_password_and_unknown_user_look_the_same(api: Api) -> None:
    a = api.client.post("/api/v1/auth/login", json={"email": "noc@globex.example", "password": "wrong-password!"})
    b = api.client.post("/api/v1/auth/login", json={"email": "nobody@globex.example", "password": "wrong-password!"})
    assert a.status_code == b.status_code == 401
    assert a.json()["code"] == b.json()["code"] == "auth.invalid_credentials"


def test_login_rate_limited_after_repeated_failures(api: Api, env: Env) -> None:
    email = "soc@initech.example"
    for _ in range(env.settings.login_max_failures):
        api.client.post("/api/v1/auth/login", json={"email": email, "password": "not-the-password"})
    r = api.client.post("/api/v1/auth/login", json={"email": email, "password": env.users[email]["password"]})
    assert r.status_code == 429
    assert r.json()["code"] == "rate_limited"
    assert "Retry-After" in r.headers
    # Clean up so later tests can sign in from the same test client IP.
    s = env.settings
    assert s.valkey_password is not None
    vk = redis.Redis(host=s.valkey_host, port=s.valkey_port, password=s.valkey_password.get_secret_value())
    for key in vk.scan_iter("p:login:*"):
        vk.delete(key)
    vk.close()


def test_logout_revokes_session(api: Api) -> None:
    u = api.env.users["msp.soc@acme.example"]
    token = _login(api.client, u["email"], u["password"])["session_token"]
    h = {"Authorization": f"Bearer {token}"}
    assert api.client.get("/api/v1/auth/me", headers=h).status_code == 200
    assert api.client.post("/api/v1/auth/logout", headers=h).status_code == 204
    assert api.client.get("/api/v1/auth/me", headers=h).status_code == 401


def test_requests_without_or_with_bad_token_are_rejected(api: Api) -> None:
    assert api.client.get("/api/v1/users").status_code == 401
    assert api.client.get("/api/v1/users", headers={"Authorization": "Bearer nss_forged"}).status_code == 401
    assert api.client.get("/api/v1/users", headers={"Authorization": "Basic abc"}).status_code == 401


def test_me_reports_portals_and_permissions(api: Api) -> None:
    me = api.get("noc@globex.example", "/auth/me").json()
    assert me["mode"] == "tenant"
    assert "noc" in me["portals"]
    assert "soc" not in me["portals"]
    assert "user:invite" not in me["permissions"]


def test_step_up_required_for_sensitive_actions(api: Api) -> None:
    admin = "admin@globex.example"
    api.login(admin, fresh=True)  # new session: no step-up yet
    r = api.post(admin, "/roles", {"key": "needs_step_up", "name": "x", "permissions": []})
    assert r.status_code == 403
    assert r.json()["code"] == "auth.step_up_required"
    api.step_up(admin)
    assert api.post(admin, "/roles", {"key": "needs_step_up", "name": "x", "permissions": []}).status_code == 201


def test_privilege_escalation_blocked(api: Api) -> None:
    admin, eng = "admin@globex.example", "noc@globex.example"
    api.step_up(admin)
    role = api.post(
        admin,
        "/roles",
        {"key": "inviter", "name": "Inviter", "permissions": ["user:invite", "role:assign", "role:read"]},
    ).json()
    eng_id = api.env.users[eng]["id"]
    roles = api.get(admin, f"/users/{eng_id}").json()["roles"]
    r = api.put(admin, f"/users/{eng_id}/roles", {"role_ids": [x["id"] for x in roles] + [role["id"]]})
    assert r.status_code == 200, r.text
    tenant_admin = next(x for x in api.get(admin, "/roles").json() if x["key"] == "tenant_admin")
    r = api.post(
        eng, "/users", {"email": "evil@globex.example", "display_name": "Evil", "role_ids": [tenant_admin["id"]]}
    )
    assert r.status_code == 403
    assert r.json()["code"] == "authz.escalation"


def test_cannot_change_own_roles(api: Api) -> None:
    admin = "admin@globex.example"
    api.step_up(admin)
    r = api.put(admin, f"/users/{api.env.users[admin]['id']}/roles", {"role_ids": []})
    assert r.status_code == 409
