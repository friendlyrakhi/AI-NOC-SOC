"""Integration test support: container-backed environment and an API driver."""

import secrets
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from testcontainers.community.postgres import PostgresContainer
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

from app.config import Settings
from app.core.security import current_totp
from app.db.migrate import migrate
from app.db.seed import seed
from app.mail import MemoryMailer
from app.main import create_app

PG_IMAGE = "pgvector/pgvector:pg17"
VALKEY_IMAGE = "valkey/valkey:8-alpine"


@dataclass
class Env:
    settings: Settings
    users: dict[str, dict[str, Any]]  # email -> seed info (password, totp_secret, id, tenant)
    tenants: dict[str, str]  # slug -> id
    superuser_dsn: str
    app_dsn: str
    worker_dsn: str

    def su(self) -> psycopg.Connection:
        return psycopg.connect(self.superuser_dsn, autocommit=True)


@pytest.fixture(scope="session")
def env() -> Iterator[Env]:
    pg_password = secrets.token_hex(16)
    valkey_password = secrets.token_hex(16)
    with (
        PostgresContainer(PG_IMAGE, username="postgres", password=pg_password, dbname="nocsoc", driver=None) as pg,
        DockerContainer(VALKEY_IMAGE)
        .with_command(f"valkey-server --requirepass {valkey_password} --save '' --appendonly no")
        .with_exposed_ports(6379)
        .waiting_for(LogMessageWaitStrategy("Ready to accept connections")) as vk,
    ):
        host = pg.get_container_host_ip()
        base: dict[str, Any] = {
            "environment": "dev",  # the seed refuses other environments
            "database_host": host,
            "database_port": int(pg.get_exposed_port(5432)),
            "database_password": SecretStr(secrets.token_hex(16)),
            "auth_database_password": SecretStr(secrets.token_hex(16)),
            "worker_database_password": SecretStr(secrets.token_hex(16)),
            "runner_token": SecretStr(secrets.token_hex(32)),
            "postgres_password": SecretStr(pg_password),
            "valkey_host": vk.get_container_host_ip(),
            "valkey_port": int(vk.get_exposed_port(6379)),
            "valkey_password": SecretStr(valkey_password),
            # AI gateway runs in-process in tests (see attach_gateway); same code as the service.
            "ai_gateway_url": "http://ai-gateway.test",
            "ai_gateway_token": SecretStr(secrets.token_hex(24)),
            "master_key": SecretStr(secrets.token_hex(32)),
            "login_max_failures": 5,
            "web_base_url": "http://web.example",
        }
        settings = Settings(**base)
        migrate(settings)
        seeded = seed(settings)
        assert seeded is not None
        settings = Settings(**{**base, "environment": "test"})
        users = {u["email"]: u for u in seeded}

        def dsn(user: str, password: SecretStr) -> str:
            return psycopg.conninfo.make_conninfo(
                host=host, port=settings.database_port, dbname="nocsoc", user=user, password=password.get_secret_value()
            )

        su_dsn = dsn("postgres", SecretStr(pg_password))
        with psycopg.connect(su_dsn) as c:
            tenants = {r[0]: str(r[1]) for r in c.execute("SELECT slug::text, id FROM tenants")}
        yield Env(
            settings=settings,
            users=users,
            tenants=tenants,
            superuser_dsn=su_dsn,
            app_dsn=dsn("nocsoc_app", base["database_password"]),
            worker_dsn=dsn("nocsoc_worker", base["worker_database_password"]),
        )


def attach_gateway(app: Any, settings: Settings) -> Any:
    """Routes the API's AI gateway client to an in-process gateway app (mock provider)."""
    import httpx

    from ai_gateway.app import create_app as create_gateway
    from ai_gateway.config import GatewaySettings

    gateway = create_gateway(GatewaySettings(gateway_token=settings.ai_gateway_token))
    app.state.services.ai_transport = httpx.ASGITransport(app=gateway)
    return gateway


@pytest.fixture(scope="session")
def mailer() -> MemoryMailer:
    return MemoryMailer()


@pytest.fixture(scope="session")
def client(env: Env, mailer: MemoryMailer) -> Iterator[TestClient]:
    app = create_app(env.settings, mailer=mailer)
    with TestClient(app, base_url="http://api.example") as c:
        attach_gateway(app, env.settings)
        yield c


class Api:
    """Signs users in through the real flows and keeps a token per user."""

    def __init__(self, env: Env, client: TestClient) -> None:
        self.env = env
        self.client = client
        self._tokens: dict[str, str] = {}

    def code(self, email: str) -> str:
        """A fresh TOTP code. Clears the replay marker so tests can authenticate repeatedly."""
        user = self.env.users[email]
        with self.env.su() as c:
            c.execute(
                "UPDATE user_credentials SET last_used_step = NULL WHERE user_id = %s AND kind = 'totp'", (user["id"],)
            )
        return current_totp(user["totp_secret"])

    def login(self, email: str, *, fresh: bool = False) -> str:
        if email in self._tokens and not fresh:
            return self._tokens[email]
        user = self.env.users[email]
        r = self.client.post("/api/v1/auth/login", json={"email": email, "password": user["password"]})
        assert r.status_code == 200, r.text
        body = r.json()
        if body["status"] == "mfa_required":
            r = self.client.post(
                "/api/v1/auth/mfa/verify", json={"challenge": body["challenge"], "code": self.code(email)}
            )
            assert r.status_code == 200, r.text
            token = r.json()["session_token"]
        else:
            assert body["status"] == "authenticated", body
            token = body["session_token"]
        self._tokens[email] = token
        return token

    def headers(self, email: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.login(email)}"}

    def step_up(self, email: str) -> None:
        r = self.client.post("/api/v1/auth/step-up", json={"code": self.code(email)}, headers=self.headers(email))
        assert r.status_code == 204, r.text

    def switch(self, email: str, slug: str, *, aggregate: bool = False) -> None:
        r = self.client.post(
            "/api/v1/auth/switch-tenant",
            json={"tenant_id": self.env.tenants[slug], "aggregate": aggregate},
            headers=self.headers(email),
        )
        assert r.status_code == 204, r.text

    def get(self, email: str, path: str, **kw: Any) -> Any:
        return self.client.get(f"/api/v1{path}", headers=self.headers(email), **kw)

    def post(self, email: str, path: str, json: Any = None, params: dict[str, Any] | None = None) -> Any:
        return self.client.post(f"/api/v1{path}", headers=self.headers(email), json=json, params=params)

    def put(self, email: str, path: str, json: Any = None) -> Any:
        return self.client.put(f"/api/v1{path}", headers=self.headers(email), json=json)

    def patch(self, email: str, path: str, json: Any = None) -> Any:
        return self.client.patch(f"/api/v1{path}", headers=self.headers(email), json=json)

    def delete(self, email: str, path: str) -> Any:
        return self.client.delete(f"/api/v1{path}", headers=self.headers(email))


@pytest.fixture(scope="session")
def api(env: Env, client: TestClient) -> Api:
    return Api(env, client)


def wait_for_next_totp_window() -> None:
    time.sleep(30 - (time.time() % 30) + 0.5)
