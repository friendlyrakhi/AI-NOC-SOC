"""P7 hardening: MFA-bound sessions, external audit anchors, the telemetry outbox, stream and AI limits."""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import uuid
from pathlib import Path
from typing import Any

import clickhouse_connect
import pytest
from pydantic import SecretStr
from support.integration import Api, Env
from support.stream import StreamEnv

from app.config import Settings
from app.core import anchors
from app.db.engines import AppDatabase
from app.ingestion.outbox import ANALYTICS, OutboxRelay
from app.tools.verify_audit import verify
from app.workers.anchor import AnchorService
from app.workers.ingest import Worker

ACME_ADMIN, ACME_EXEC = "msp.admin@acme.example", "msp.exec@acme.example"
GLOBEX_ADMIN = "admin@globex.example"


# ---------------------------------------------------------------- MFA-bound sessions
def test_privilege_granted_mid_session_needs_an_mfa_session(api: Api) -> None:
    """Threat model §7 residual: a role with a privileged permission granted to a signed-in user
    without MFA must not become usable in that session."""
    assert api.env.users[ACME_EXEC]["totp_secret"] is None, "precondition: the executive has no MFA"
    api.login(ACME_EXEC, fresh=True)
    assert api.get(ACME_EXEC, "/ai/settings").status_code == 403

    api.step_up(ACME_ADMIN)
    key = f"ai_admin_{secrets.token_hex(3)}"
    role = api.post(ACME_ADMIN, "/roles", {"key": key, "name": "AI admin", "permissions": ["ai:admin"]})
    assert role.status_code == 201, role.text
    exec_id = api.env.users[ACME_EXEC]["id"]
    current = [x["id"] for x in api.get(ACME_ADMIN, f"/users/{exec_id}").json()["roles"]]
    r = api.put(ACME_ADMIN, f"/users/{exec_id}/roles", {"role_ids": [*current, role.json()["id"]]})
    assert r.status_code == 200, r.text
    try:
        r = api.get(ACME_EXEC, "/ai/settings")
        assert r.status_code == 403 and r.json()["code"] == "auth.mfa_session_required", r.text
        me = api.get(ACME_EXEC, "/auth/me").json()
        assert "ai:admin" in me["withheld_permissions"] and "ai:admin" not in me["permissions"]
        # Signing in again now demands MFA enrollment before any session exists.
        user = api.env.users[ACME_EXEC]
        r = api.client.post("/api/v1/auth/login", json={"email": ACME_EXEC, "password": user["password"]})
        assert r.json()["status"] == "mfa_enrollment_required"
    finally:
        api.step_up(ACME_ADMIN)
        assert api.put(ACME_ADMIN, f"/users/{exec_id}/roles", {"role_ids": current}).status_code == 200


def test_mfa_sessions_keep_privileged_permissions(api: Api) -> None:
    me = api.get(GLOBEX_ADMIN, "/auth/me").json()
    assert me["withheld_permissions"] == []
    assert "role:manage" in me["permissions"]


def test_existing_sessions_of_mfa_users_were_marked_by_the_migration(env: Env) -> None:
    with env.su() as c:
        bad = c.execute(
            "SELECT count(*) FROM sessions s JOIN user_credentials t ON t.user_id = s.user_id AND t.kind = 'totp' "
            "WHERE NOT s.mfa AND s.revoked_at IS NULL"
        ).fetchone()
    assert bad is not None and bad[0] == 0


# ---------------------------------------------------------------- audit anchors (T28)
def anchor_settings(env: Env, path: Path) -> Settings:
    return env.settings.model_copy(
        update={"audit_anchor_key": SecretStr(secrets.token_hex(32)), "audit_anchor_path": str(path)}
    )


def anchor_problems(problems: list[str]) -> list[str]:
    """verify() also recomputes every chain; keep only what the anchors found."""
    return [p for p in problems if "anchor" in p or "removed" in p or "rewritten" in p]


def run_anchor(settings: Settings, *, force: bool = False) -> list[str]:
    async def go() -> list[str]:
        service = AnchorService(settings, AppDatabase(settings, url=settings.worker_database_url()))
        try:
            return await service.run_once(force=force)
        finally:
            await service.db.dispose()

    return asyncio.run(go())


def test_anchor_service_has_no_access_to_audit_content(env: Env) -> None:
    import psycopg

    with psycopg.connect(env.worker_dsn, autocommit=True) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("SELECT details FROM audit_log LIMIT 1")


def test_anchors_detect_tail_truncation_and_rewrites(api: Api, env: Env, tmp_path: Path) -> None:
    settings = anchor_settings(env, tmp_path / "anchors.jsonl")
    assert run_anchor(settings, force=True) == []
    api.login(GLOBEX_ADMIN, fresh=True)  # appends to the platform chain (auth events)
    assert run_anchor(settings) == []
    # Other tests tamper with audit entries on purpose; only anchor problems matter here.
    assert anchor_problems(asyncio.run(verify(settings))) == [], "intact anchors verify"
    history = anchors.read_all(Path(settings.audit_anchor_path), settings.audit_anchor_key.get_secret_value().encode())  # type: ignore[union-attr]
    assert len(history) == 2 and history[1][0].prev == history[0][1]

    # Delete the newest platform entry: the chain alone is still consistent...
    with env.su() as c:
        c.execute("ALTER TABLE audit_log DISABLE TRIGGER audit_no_update")
        try:
            c.execute("DELETE FROM audit_log WHERE id = (SELECT max(id) FROM audit_log WHERE tenant_id IS NULL)")
        finally:
            c.execute("ALTER TABLE audit_log ENABLE TRIGGER audit_no_update")
        ok = c.execute("SELECT ok FROM audit_verify(NULL)").fetchone()
    assert ok is not None and ok[0] is True, "tail truncation is invisible to the chain itself"
    # ...but not to the anchors, and the problem is recorded in the next signed line.
    problems = run_anchor(settings)
    assert problems and "removed" in problems[0]
    assert any("removed" in p for p in anchor_problems(asyncio.run(verify(settings))))


def test_anchor_file_tampering_is_detected(api: Api, env: Env, tmp_path: Path) -> None:
    settings = anchor_settings(env, tmp_path / "anchors.jsonl")
    run_anchor(settings, force=True)
    api.login(GLOBEX_ADMIN, fresh=True)
    run_anchor(settings)
    path = Path(settings.audit_anchor_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    key = settings.audit_anchor_key.get_secret_value().encode()  # type: ignore[union-attr]

    path.write_text(lines[1] + "\n", encoding="utf-8")  # first line removed
    with pytest.raises(anchors.AnchorFileError, match="does not follow"):
        anchors.read_all(path, key)
    path.write_text(lines[0].replace('"seq":', '"seq":1') + "\n", encoding="utf-8")  # edited head
    with pytest.raises(anchors.AnchorFileError, match="signature"):
        anchors.read_all(path, key)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(anchors.AnchorFileError, match="signature"):
        anchors.read_all(path, b"another-key-" + secrets.token_hex(16).encode())
    assert len(anchors.read_all(path, key)) == 2


# ---------------------------------------------------------------- telemetry outbox
class DeadClickHouse:
    async def insert(self, *_: Any, **__: Any) -> None:
        raise ConnectionError("clickhouse is down")


def ch_count(s: Settings, tenant: str) -> int:
    reader = clickhouse_connect.get_client(
        host=s.clickhouse_host,
        port=s.clickhouse_port,
        username="nocsoc_reader",
        password=s.clickhouse_reader_password.get_secret_value(),  # type: ignore[union-attr]
        database=s.clickhouse_database,
    )
    return int(reader.query("SELECT count() FROM raw_events", settings={"SQL_tenant_id": tenant}).result_rows[0][0])


def test_telemetry_survives_a_clickhouse_outage(stream: StreamEnv) -> None:
    """P2/P6 residual: telemetry used to be best effort. Now it waits in the outbox, written in the
    same transaction as the alerts, and the relay delivers it when ClickHouse is back."""
    globex = stream.env.tenants["globex"]
    stream.api.switch(GLOBEX_ADMIN, "globex")
    instances = stream.api.get(GLOBEX_ADMIN, "/connectors/instances").json()
    if not any(i["definition_id"] == "prometheus" for i in instances):
        r = stream.api.post(
            GLOBEX_ADMIN, "/connectors/instances", {"definition_id": "prometheus", "name": "outbox probe", "config": {}}
        )
        assert r.status_code == 201, r.text
    stream.drain(minimum=0, idle_seconds=1)  # anything still on the bus is not part of this test
    before = ch_count(stream.settings, globex)
    r = stream.api.post(GLOBEX_ADMIN, "/connectors/scenarios/noise_flapping/replay")
    assert r.status_code == 200, r.text
    published = r.json()["published"]

    async def ingest_with_clickhouse_down() -> dict[str, int]:
        worker = Worker(stream.settings)
        await worker.start()
        real = worker.ingestor.writer.analytics
        worker.ingestor.writer.analytics = DeadClickHouse()
        try:
            handled, idle = 0, 0
            while handled < published or idle < 4:
                batches = await worker.consumer.getmany(timeout_ms=500, max_records=200)
                idle = 0 if batches else idle + 1
                for _tp, messages in batches.items():
                    for msg in messages:
                        if msg.value is not None:
                            await worker.handle(msg.value)
                            handled += 1
                if batches:
                    await worker.flush_telemetry()
                    await worker.consumer.commit()
            assert real is not None
            return dict(worker.stats)
        finally:
            await worker.stop()

    stats = asyncio.run(ingest_with_clickhouse_down())
    assert stats["stored"] >= 1
    assert ch_count(stream.settings, globex) == before, "nothing reached ClickHouse during the outage"
    with stream.env.su() as c:
        pending = c.execute(
            "SELECT count(*), bool_and(sinks = ARRAY[%s]) FROM telemetry_outbox WHERE tenant_id = %s",
            (ANALYTICS, globex),
        ).fetchone()
        assert pending is not None and pending[0] == stats["stored"] and pending[1]
        c.execute("UPDATE telemetry_outbox SET created_at = created_at - interval '1 minute'")

    async def relay() -> dict[str, int]:
        worker = Worker(stream.settings)
        await worker.start()
        try:
            return await OutboxRelay(worker.db, worker.ingestor.writer).run_once()
        finally:
            await worker.stop()

    result = asyncio.run(relay())
    assert result["delivered"] >= stats["stored"] and result["pending"] == 0
    assert ch_count(stream.settings, globex) == before + stats["stored"], "every stored message's raw event arrived"
    with stream.env.su() as c:
        left = c.execute("SELECT count(*) FROM telemetry_outbox WHERE tenant_id = %s", (globex,)).fetchone()
    assert left is not None and left[0] == 0


def test_outbox_is_tenant_scoped(stream: StreamEnv) -> None:
    import psycopg

    with stream.env.su() as c:
        c.execute(
            "INSERT INTO telemetry_outbox (tenant_id, sinks, rows) VALUES (%s, ARRAY['analytics'], '{}'::jsonb)",
            (stream.env.tenants["initech"],),
        )
    try:
        with psycopg.connect(stream.env.worker_dsn, autocommit=True) as c:
            with c.transaction():
                c.execute("SELECT set_config('app.tenant_id', %s, true)", (stream.env.tenants["globex"],))
                seen = c.execute("SELECT count(*) FROM telemetry_outbox").fetchone()
            assert seen is not None and seen[0] == 0
            assert c.execute("SELECT count(*) FROM telemetry_outbox").fetchone() == (0,), "no context: fail closed"
    finally:
        with stream.env.su() as c:
            c.execute("DELETE FROM telemetry_outbox WHERE tenant_id = %s", (stream.env.tenants["initech"],))


# ---------------------------------------------------------------- live-update and AI limits
def test_live_streams_are_capped_per_user(api: Api) -> None:
    from app import live

    settings = api.client.app.state.services.settings  # type: ignore[attr-defined]
    principal_user = uuid.UUID(api.env.users[GLOBEX_ADMIN]["id"])
    tenant = uuid.UUID(api.env.tenants["globex"])
    keys = live._lease_keys(tenant, principal_user)
    valkey = api.client.app.state.services.valkey  # type: ignore[attr-defined]

    async def fill() -> None:
        for _ in range(settings.sse_streams_per_user):
            await live.renew(valkey, keys, uuid.uuid4().hex)

    async def clear() -> None:
        await valkey.delete(*keys)

    api.client.portal.call(fill)  # type: ignore[attr-defined]
    try:
        r = api.get(GLOBEX_ADMIN, "/stream")
        assert r.status_code == 429 and r.json()["code"] == "stream.limit"
    finally:
        api.client.portal.call(clear)  # type: ignore[attr-defined]


def test_ai_requests_are_limited_per_user(api: Api) -> None:
    services = api.client.app.state.services  # type: ignore[attr-defined]
    original = services.settings
    services.settings = original.model_copy(update={"ai_requests_per_user_hour": 2})
    user = "soc@initech.example"
    try:
        api.switch(user, "initech")
        codes = [api.post(user, "/ai/query-assist", {"intent": "failed logins today"}).status_code for _ in range(3)]
        assert codes == [200, 200, 429], codes
        r = api.post(user, "/ai/query-assist", {"intent": "failed logins today"})
        assert r.json()["code"] == "ai.rate_limited"
    finally:
        services.settings = original
        with contextlib.suppress(Exception):

            async def clear() -> None:
                async for k in services.valkey.scan_iter(match="t:*:ai:user:*"):
                    await services.valkey.delete(k)

            api.client.portal.call(clear)  # type: ignore[attr-defined]
