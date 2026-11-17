"""P8 live-read gate (ADR-0019) on the real API: every layer refuses on its own."""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import Any

import pytest
from support.integration import Api

ADMIN = "admin@globex.example"
CFG = {"alertmanager_url": "https://am.example.com", "prometheus_url": "https://prom.example.com"}


@contextlib.contextmanager
def settings(api: Api, **changes: Any) -> Iterator[None]:
    services = api.client.app.state.services  # type: ignore[attr-defined]
    original = services.settings
    services.settings = original.model_copy(update=changes)
    try:
        yield
    finally:
        services.settings = original


def create(api: Api, definition: str = "prometheus", name: str = "live", config: Any = None) -> Any:
    body = {"definition_id": definition, "name": name, "config": CFG if config is None else config, "mode": "live"}
    return api.post(ADMIN, "/connectors/instances", body)


VAULT = {"live_read_enabled": True, "secrets_provider": "openbao", "openbao_unseal": "shamir"}


def test_live_is_off_by_default(api: Api) -> None:
    api.switch(ADMIN, "globex")
    r = create(api)
    assert r.status_code == 409 and r.json()["code"] == "connector.live_disabled"


@pytest.mark.parametrize(
    "changes",
    [
        {"live_read_enabled": True},  # local key provider
        {"live_read_enabled": True, "secrets_provider": "openbao", "openbao_unseal": "auto"},  # dev-grade unseal
    ],
    ids=["local-key", "auto-unseal"],
)
def test_live_needs_openbao_with_operator_shares(api: Api, changes: dict[str, Any]) -> None:
    with settings(api, **changes):
        r = create(api)
    assert r.status_code == 409 and r.json()["code"] == "connector.live_needs_vault"


def test_live_needs_connector_support_and_step_up(api: Api) -> None:
    api.login(ADMIN, fresh=True)  # no step-up yet
    api.switch(ADMIN, "globex")
    with settings(api, **VAULT):
        r = create(api, "splunk", "live splunk", {})
        assert r.status_code == 422 and r.json()["code"] == "connector.live_unsupported"
        r = create(api)
        assert r.status_code == 403 and r.json()["code"] == "auth.step_up_required"
        api.step_up(ADMIN)
        r = create(api, name="live prometheus")
        assert r.status_code == 201, r.text
        assert r.json()["mode"] == "live"
        live_id = r.json()["id"]
        test = api.post(ADMIN, f"/connectors/instances/{live_id}/test")
        assert test.status_code == 409 and test.json()["code"] == "connector.live_test_via_runner"
        work = api.client.get("/api/v1/internal/runner/work", headers={"X-Runner-Token": runner_token(api)}).json()
        assert live_id in {w["instance_id"] for w in work}
    # Switched off again: the runner is not handed the live instance.
    work = api.client.get("/api/v1/internal/runner/work", headers={"X-Runner-Token": runner_token(api)}).json()
    assert live_id not in {w["instance_id"] for w in work}
    api.delete(ADMIN, f"/connectors/instances/{live_id}")


def runner_token(api: Api) -> str:
    return api.client.app.state.services.settings.runner_token.get_secret_value()  # type: ignore[attr-defined,no-any-return]
