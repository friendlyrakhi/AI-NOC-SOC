"""AUD-1 / SEC-AUD-01..02: append-only, hash-chained audit log with tamper detection."""

import psycopg
import pytest
from psycopg import errors
from support.integration import Api, Env

pytestmark = pytest.mark.integration


def _verify(env: Env, slug: str) -> tuple[bool, int, int | None, str | None]:
    with env.su() as c:
        row = c.execute("SELECT * FROM audit_verify(%s)", (env.tenants[slug],)).fetchone()
    assert row is not None
    return row  # type: ignore[return-value]


def test_seeded_chains_verify(env: Env) -> None:
    for slug in env.tenants:
        ok, checked, _, reason = _verify(env, slug)
        assert ok, (slug, reason)
        assert checked >= 1


def test_api_actions_are_audited_and_chain_verifies(api: Api) -> None:
    admin = "admin@globex.example"
    api.switch(admin, "globex")
    api.step_up(admin)
    r = api.post(admin, "/roles", {"key": "audit_probe", "name": "Audit probe", "permissions": ["user:read"]})
    assert r.status_code == 201, r.text
    entries = api.get(admin, "/audit", params={"action": "role.create"}).json()
    assert entries[0]["action"] == "role.create"
    assert entries[0]["actor_id"] == api.env.users[admin]["id"]
    verify = api.get(admin, "/audit/verify").json()
    assert verify["ok"] is True


def test_secrets_never_reach_audit_details(api: Api) -> None:
    with api.env.su() as c:
        rows = c.execute("SELECT details::text FROM audit_log").fetchall()
    blob = " ".join(r[0] for r in rows)
    for user in api.env.users.values():
        assert user["password"] not in blob
        if user["totp_secret"]:
            assert user["totp_secret"] not in blob


def test_update_and_delete_blocked_by_trigger_even_for_owner(env: Env) -> None:
    with env.su() as c:
        c.execute("SET ROLE nocsoc_owner")
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("UPDATE audit_log SET action = 'x' WHERE id = (SELECT min(id) FROM audit_log)")
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("DELETE FROM audit_log WHERE id = (SELECT min(id) FROM audit_log)")


def _tamper(env: Env, sql: str, slug: str) -> None:
    """A superuser who disables triggers can still change rows. Verification must notice."""
    with psycopg.connect(env.superuser_dsn) as c:
        c.execute("SET session_replication_role = replica")  # disables the immutability trigger
        c.execute(sql, (env.tenants[slug],))


def test_modified_entry_is_detected(env: Env) -> None:
    assert _verify(env, "initech")[0]
    _tamper(
        env,
        "UPDATE audit_log SET details = '{\"tampered\": true}' WHERE id = "
        "(SELECT id FROM audit_log WHERE tenant_id = %s ORDER BY seq LIMIT 1)",
        "initech",
    )
    ok, _, bad_seq, reason = _verify(env, "initech")
    assert not ok
    assert bad_seq == 1
    assert reason == "entry content modified"


def test_deleted_middle_entry_is_detected(env: Env) -> None:
    t = env.tenants["acme-msp"]
    with env.su() as c:
        for i in range(3):
            c.execute(
                "SELECT audit_append(%s, 'system', NULL, NULL, NULL, 'test.event', NULL, NULL, 'success', "
                "CAST(%s AS jsonb), NULL)",
                (t, f'{{"i": {i}}}'),
            )
        middle = c.execute(
            "SELECT seq FROM audit_log WHERE tenant_id = %s ORDER BY seq DESC OFFSET 1 LIMIT 1", (t,)
        ).fetchone()
    assert middle is not None
    assert _verify(env, "acme-msp")[0]
    with psycopg.connect(env.superuser_dsn) as c:
        c.execute("SET session_replication_role = replica")
        c.execute("DELETE FROM audit_log WHERE tenant_id = %s AND seq = %s", (t, middle[0]))
    ok, _, bad_seq, reason = _verify(env, "acme-msp")
    assert not ok
    assert bad_seq == middle[0]
    assert reason == "missing entry (sequence gap)"


# Known limitation (residual risk, docs/reports/P1-exit-review.md): deleting the newest
# entries of a chain is not detectable from the chain alone. External anchors (P7) close it.
