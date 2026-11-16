"""Database-level isolation (SEC-ISO-02, SEC-ISO-06, T27/T28): exercised directly as the
application role, bypassing the API, to prove RLS holds even if application code is wrong."""

import psycopg
import pytest
from psycopg import errors
from support.integration import Env

pytestmark = pytest.mark.integration

# Every table in the public schema must be classified. A new table fails this suite until
# its isolation model is decided (ADR-0016 consequences).
TENANT_SCOPED = {
    "tenants",
    "memberships",
    "roles",
    "role_permissions",
    "role_bindings",
    "delegations",
    "api_keys",
    "audit_log",
    "users",
}
IDENTITY_ONLY = {"user_credentials", "sessions", "auth_challenges", "invitations"}  # no app policies
GLOBAL = {"permissions", "alembic_version"}
AGGREGATE_READABLE = {"tenants", "audit_log"}


def app_conn(env: Env, tenant: str | None = None, user: str | None = None) -> psycopg.Connection:
    conn = psycopg.connect(env.app_dsn)
    if tenant:
        conn.execute("SELECT set_config('app.tenant_id', %s, false)", (env.tenants[tenant],))
    if user:
        conn.execute("SELECT set_config('app.user_id', %s, false)", (env.users[user]["id"],))
    return conn


def test_every_table_is_classified_and_protected(env: Env) -> None:
    with env.su() as c:
        tables = {
            r[0]: (r[1], r[2])
            for r in c.execute(
                "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r'"
            )
        }
        aggregate_policies = {
            r[0] for r in c.execute("SELECT tablename FROM pg_policies WHERE 'nocsoc_aggregate' = ANY(roles)")
        }
    unclassified = set(tables) - TENANT_SCOPED - IDENTITY_ONLY - GLOBAL
    assert not unclassified, f"classify new tables in this test: {unclassified}"
    for name in TENANT_SCOPED | IDENTITY_ONLY:
        enabled, forced = tables[name]
        assert enabled, f"{name} must ENABLE row level security"
        assert forced, f"{name} must FORCE row level security"
    assert aggregate_policies == AGGREGATE_READABLE


@pytest.mark.parametrize("table", sorted(TENANT_SCOPED - {"role_permissions", "roles"}))
def test_no_context_sees_nothing(env: Env, table: str) -> None:
    with app_conn(env) as c:
        assert c.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)  # noqa: S608


def test_context_sees_only_own_tenant(env: Env) -> None:
    globex, initech = env.tenants["globex"], env.tenants["initech"]
    with app_conn(env, "globex") as c:
        member_tenants = {str(r[0]) for r in c.execute("SELECT DISTINCT tenant_id FROM memberships")}
        audit_tenants = {str(r[0]) for r in c.execute("SELECT DISTINCT tenant_id FROM audit_log")}
        tenant_ids = {str(r[0]) for r in c.execute("SELECT id FROM tenants")}
    assert member_tenants == {globex}
    assert audit_tenants == {globex}
    assert initech not in tenant_ids
    assert env.tenants["acme-msp"] in tenant_ids  # a customer may see its MSP's row


def test_users_visible_only_for_own_members(env: Env) -> None:
    with app_conn(env, "globex") as c:
        emails = {r[0] for r in c.execute("SELECT email::text FROM users")}
    assert emails
    assert all(e.endswith("@globex.example") for e in emails)


def test_writes_into_other_tenant_rejected(env: Env) -> None:
    with app_conn(env, "globex") as c, pytest.raises(errors.InsufficientPrivilege):
        c.execute("INSERT INTO roles (tenant_id, key, name) VALUES (%s, 'sneaky', 'Sneaky')", (env.tenants["initech"],))


def test_cannot_modify_other_tenant_rows(env: Env) -> None:
    with app_conn(env, "globex") as c:
        cur = c.execute("UPDATE memberships SET status = 'suspended' WHERE tenant_id = %s", (env.tenants["initech"],))
        assert cur.rowcount == 0
        cur = c.execute("DELETE FROM memberships WHERE tenant_id = %s", (env.tenants["initech"],))
        assert cur.rowcount == 0


def test_own_memberships_readable_but_not_writable_across_tenants(env: Env) -> None:
    # msp.admin reads own membership while in globex context, but cannot change it.
    with app_conn(env, "globex", "msp.admin@acme.example") as c:
        rows = c.execute("SELECT tenant_id FROM memberships WHERE user_id = app_user()").fetchall()
        assert {str(r[0]) for r in rows} == {env.tenants["acme-msp"]}
        assert c.execute("DELETE FROM memberships WHERE user_id = app_user()").rowcount == 0


@pytest.mark.parametrize("table", sorted(IDENTITY_ONLY))
def test_identity_tables_not_accessible_to_app(env: Env, table: str) -> None:
    with app_conn(env, "globex") as c, pytest.raises(errors.InsufficientPrivilege):
        c.execute(f"SELECT 1 FROM {table} LIMIT 1")  # noqa: S608


def test_app_cannot_write_audit_directly(env: Env) -> None:
    with app_conn(env, "globex") as c:
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute(
                "INSERT INTO audit_log (tenant_id, seq, at, actor_type, action, outcome, hash) "
                "VALUES (app_tenant(), 999, now(), 'system', 'x', 'success', '\\x00')"
            )
        c.rollback()
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (env.tenants["globex"],))
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("UPDATE audit_log SET action = 'x'")


def test_app_cannot_append_audit_for_other_tenant(env: Env) -> None:
    with app_conn(env, "globex") as c, pytest.raises(errors.InsufficientPrivilege):
        c.execute(
            "SELECT audit_append(%s, 'system', NULL, NULL, NULL, 'forged', NULL, NULL, 'success', '{}', NULL)",
            (env.tenants["initech"],),
        )


def test_app_cannot_assume_privileged_roles(env: Env) -> None:
    for role in ("nocsoc_auth", "nocsoc_owner", "postgres"):
        with app_conn(env) as c, pytest.raises(errors.InsufficientPrivilege):
            c.execute(f"SET ROLE {role}")


def test_aggregate_role_is_read_only_and_scoped(env: Env) -> None:
    ids = f"{env.tenants['globex']}"
    with app_conn(env) as c:
        c.execute("SET ROLE nocsoc_aggregate")
        c.execute("SELECT set_config('app.tenant_ids', %s, false)", (ids,))
        tenants = {str(r[0]) for r in c.execute("SELECT id FROM tenants")}
        audit_tenants = {str(r[0]) for r in c.execute("SELECT DISTINCT tenant_id FROM audit_log")}
        assert tenants == {env.tenants["globex"]}
        assert audit_tenants == {env.tenants["globex"]}
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("UPDATE tenants SET name = 'x'")
        c.rollback()
        c.execute("SET ROLE nocsoc_aggregate")
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("SELECT 1 FROM memberships")


def test_aggregate_without_tenant_list_sees_nothing(env: Env) -> None:
    with app_conn(env) as c:
        c.execute("SET ROLE nocsoc_aggregate")
        assert c.execute("SELECT count(*) FROM audit_log").fetchone() == (0,)


def test_audit_access_check_never_returns_null(env: Env) -> None:
    """Regression: NULL from the access check once let the app append to any tenant's chain."""
    with app_conn(env, "globex") as c:
        for tenant in (env.tenants["initech"], None):
            for mirror in (True, False):
                row = c.execute("SELECT audit_caller_may_access(%s, %s)", (tenant, mirror)).fetchone()
                assert row == (False,)
