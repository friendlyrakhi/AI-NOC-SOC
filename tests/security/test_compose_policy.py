"""SEC-INF-01 / SEC-INF-02: the compose policy checker rejects unsafe service definitions."""

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "check-compose.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_compose", _PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load().check

SAFE = {
    "ports": [{"published": "8100", "target": 8000, "host_ip": "127.0.0.1"}],
    "security_opt": ["no-new-privileges:true"],
    "mem_limit": "512m",
    "environment": {"POSTGRES_PASSWORD_FILE": "/run/secrets/x"},
}


def test_safe_service_passes() -> None:
    assert check({"services": {"api": SAFE}}) == []


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"ports": [{"published": "8100", "target": 8000, "host_ip": "0.0.0.0"}]}, "127.0.0.1"),  # noqa: S104
        ({"ports": [{"published": "8100", "target": 8000}]}, "127.0.0.1"),
        ({"privileged": True}, "privileged"),
        ({"cap_add": ["NET_ADMIN"]}, "cap_add"),
        ({"network_mode": "host"}, "host networking"),
        ({"volumes": [{"source": "/var/run/docker.sock", "target": "/s"}]}, "Docker socket"),
        ({"environment": {"DB_PASSWORD": "x"}}, "secret-like env var"),
        ({"environment": {"OPENAI_API_KEY": "x"}}, "secret-like env var"),
        ({"security_opt": []}, "no-new-privileges"),
        ({"mem_limit": None}, "memory limit"),
    ],
)
def test_unsafe_service_rejected(override: dict[str, object], expected: str) -> None:
    svc = {**SAFE, **override}
    problems = check({"services": {"bad": svc}})
    assert any(expected in p for p in problems), problems


# ---------------------------------------------------------------- AI gateway isolation (LLM06, T21)
check_ai = _load().check_ai_isolation

GATEWAY = {
    "networks": {"ai": None},
    "environment": {"NOCSOC_AI_CLOUD_EGRESS_ENABLED": "false"},
    "secrets": [{"source": "ai_gateway_token"}],
}
AI_NETS = {"ai": {"internal": True}}


def test_isolated_gateway_passes() -> None:
    config = {"services": {"ai-gateway": GATEWAY, "api": {"networks": {"ai": None, "data": None}}}, "networks": AI_NETS}
    assert check_ai(config) == []


@pytest.mark.parametrize(
    ("services", "networks", "expected"),
    [
        ({"ai-gateway": {**GATEWAY, "networks": {"ai": None, "bus": None}}}, AI_NETS, "only to network 'ai'"),
        ({"ai-gateway": GATEWAY}, {"ai": {}}, "must be internal"),
        ({"ai-gateway": GATEWAY, "connector-runner": {"networks": {"ai": None}}}, AI_NETS, "must not join"),
        ({"ai-gateway": {**GATEWAY, "secrets": [{"source": "database_password"}]}}, AI_NETS, "unexpected secret"),
        ({"ai-gateway": {**GATEWAY, "environment": {"NOCSOC_RUNNER_TOKEN": "x"}}}, AI_NETS, "platform setting"),
        (
            {"ai-gateway": {**GATEWAY, "environment": {"NOCSOC_AI_CLOUD_EGRESS_ENABLED": "true"}}},
            AI_NETS,
            "egress must be off",
        ),
    ],
)
def test_unsafe_gateway_rejected(services: dict[str, object], networks: dict[str, object], expected: str) -> None:
    problems = check_ai({"services": services, "networks": networks})
    assert any(expected in p for p in problems), problems
