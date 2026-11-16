from fastapi.testclient import TestClient

from app.config import Settings
from app.health import get_checks
from app.main import app


async def _ok(_: Settings) -> None:
    return None


async def _fail(_: Settings) -> None:
    raise ConnectionError("db password=hunter2 unreachable")


def test_live() -> None:
    with TestClient(app) as client:
        resp = client.get("/api/v1/health/live")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_ready_when_dependencies_up() -> None:
    app.dependency_overrides[get_checks] = lambda: {"postgres": _ok, "valkey": _ok}
    try:
        with TestClient(app) as client:
            resp = client.get("/api/v1/health/ready")
    finally:
        app.dependency_overrides.clear()
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}


def test_ready_hides_failure_details() -> None:
    app.dependency_overrides[get_checks] = lambda: {"postgres": _fail, "valkey": _ok}
    try:
        with TestClient(app) as client:
            resp = client.get("/api/v1/health/ready")
    finally:
        app.dependency_overrides.clear()
    assert resp.status_code == 503
    assert resp.json() == {"status": "not_ready"}
    assert "hunter2" not in resp.text
    assert "postgres" not in resp.text


def test_openapi_served_under_versioned_prefix() -> None:
    with TestClient(app) as client:
        resp = client.get("/api/v1/openapi.json")
    assert resp.status_code == 200
    assert "/api/v1/health/live" in resp.json()["paths"]
