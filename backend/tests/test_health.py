import secrets
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.config import Settings
from app.health import get_checks
from app.main import create_app
from app.services import Services


async def _ok(_: Services) -> None:
    return None


async def _fail(_: Services) -> None:
    raise ConnectionError("db password=hunter2 unreachable")


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = create_app(Settings(master_key=SecretStr(secrets.token_hex(32))))
    with TestClient(app) as c:
        c.app.dependency_overrides.clear()  # type: ignore[attr-defined]
        yield c


def test_live(client: TestClient) -> None:
    resp = client.get("/api/v1/health/live")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_ready_when_dependencies_up(client: TestClient) -> None:
    client.app.dependency_overrides[get_checks] = lambda: {"postgres": _ok, "valkey": _ok}  # type: ignore[attr-defined]
    resp = client.get("/api/v1/health/ready")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}


def test_ready_hides_failure_details(client: TestClient) -> None:
    client.app.dependency_overrides[get_checks] = lambda: {"postgres": _fail, "valkey": _ok}  # type: ignore[attr-defined]
    resp = client.get("/api/v1/health/ready")
    assert resp.status_code == 503
    assert resp.json() == {"status": "not_ready"}
    assert "hunter2" not in resp.text
    assert "postgres" not in resp.text


def test_openapi_served_under_versioned_prefix(client: TestClient) -> None:
    resp = client.get("/api/v1/openapi.json")
    assert resp.status_code == 200
    paths = resp.json()["paths"]
    assert "/api/v1/health/live" in paths
    assert "/api/v1/auth/login" in paths


def test_errors_are_problem_json(client: TestClient) -> None:
    resp = client.get("/api/v1/users")
    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/problem+json")
    assert resp.json()["code"] == "auth.unauthenticated"


def test_app_refuses_to_start_without_master_key() -> None:
    app = create_app(Settings())
    with pytest.raises(RuntimeError, match="master key"), TestClient(app):
        pass
