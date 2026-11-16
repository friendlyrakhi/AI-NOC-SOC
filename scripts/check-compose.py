"""Static policy check on the rendered Compose config (threat model T27, T30).

Usage: python scripts/check-compose.py [--env-file PATH]

Renders infrastructure/compose/docker-compose.yml with every profile enabled.

Fails when any service publishes a port on a non-loopback address, runs privileged,
mounts the Docker socket, adds capabilities, or passes secrets as environment values, or
when the connector runner can reach a data store (network or credentials).
"""

import argparse
import json
import re
import shutil
import subprocess  # nosec B404: fixed argv, no shell
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ROOT / "infrastructure" / "compose" / "docker-compose.yml"

SECRET_ENV = re.compile(r"(PASSWORD|SECRET|TOKEN|API_?KEY)(?!_FILE)$", re.IGNORECASE)


def check(config: dict) -> list[str]:
    problems: list[str] = []
    for name, svc in config.get("services", {}).items():
        for port in svc.get("ports", []):
            if port.get("published") and port.get("host_ip") != "127.0.0.1":
                problems.append(f"{name}: port {port.get('published')} not bound to 127.0.0.1")
        if svc.get("privileged"):
            problems.append(f"{name}: privileged container")
        if svc.get("cap_add"):
            problems.append(f"{name}: cap_add {svc['cap_add']}")
        if svc.get("network_mode") == "host":
            problems.append(f"{name}: host networking")
        for vol in svc.get("volumes", []):
            if "docker.sock" in str(vol.get("source", "")):
                problems.append(f"{name}: mounts the Docker socket")
        for key in svc.get("environment") or {}:
            if SECRET_ENV.search(key):
                problems.append(f"{name}: secret-like env var {key}; use a secret file")
        if "no-new-privileges:true" not in (svc.get("security_opt") or []):
            problems.append(f"{name}: missing security_opt no-new-privileges:true")
        if not svc.get("mem_limit") and not svc.get("deploy", {}).get("resources", {}).get("limits", {}).get("memory"):
            problems.append(f"{name}: no memory limit")
    problems += check_isolation(config)
    problems += check_ai_isolation(config)
    return problems


# Services that run connector code must not share a network with the data stores (T13).
CONNECTOR_RUNTIMES = {"connector-runner"}
DATA_STORES = {"postgres", "valkey", "clickhouse"}


def _networks(svc: dict) -> set[str]:
    nets = svc.get("networks") or {"default": None}
    return set(nets)


def check_isolation(config: dict) -> list[str]:
    services = config.get("services", {})
    problems = []
    for runtime in CONNECTOR_RUNTIMES & set(services):
        rt = services[runtime]
        for store in DATA_STORES & set(services):
            shared = _networks(rt) & _networks(services[store])
            if shared:
                problems.append(f"{runtime}: shares network {sorted(shared)} with data store {store}")
        for key in rt.get("environment") or {}:
            if "DATABASE" in key or "CLICKHOUSE" in key or "VALKEY" in key:
                problems.append(f"{runtime}: has data-store setting {key}")
        for secret in rt.get("secrets") or []:
            source = str(secret.get("source", ""))
            if any(s in source for s in ("database", "clickhouse", "valkey", "postgres", "master_key")):
                problems.append(f"{runtime}: has data-store secret {secret.get('source')}")
    return problems


# The AI gateway may talk to the API only (LLM06, T21): one internal network, one secret.
AI_RUNTIMES = {"ai-gateway"}
AI_ALLOWED_SECRETS = {"ai_gateway_token", "anthropic_api_key"}


def check_ai_isolation(config: dict) -> list[str]:
    services = config.get("services", {})
    networks = config.get("networks", {})
    problems = []
    for runtime in AI_RUNTIMES & set(services):
        rt = services[runtime]
        nets = _networks(rt)
        if nets != {"ai"}:
            problems.append(f"{runtime}: must be attached only to network 'ai', found {sorted(nets)}")
        if not (networks.get("ai") or {}).get("internal"):
            problems.append("network 'ai' must be internal (no internet) in the base compose file")
        for name, svc in services.items():
            if name != "api" and name not in AI_RUNTIMES and "ai" in _networks(svc):
                problems.append(f"{name}: must not join the 'ai' network")
        for key in rt.get("environment") or {}:
            if any(k in key for k in ("DATABASE", "CLICKHOUSE", "VALKEY", "KAFKA", "RUNNER")):
                problems.append(f"{runtime}: has platform setting {key}")
        for secret in rt.get("secrets") or []:
            if secret.get("source") not in AI_ALLOWED_SECRETS:
                problems.append(f"{runtime}: unexpected secret {secret.get('source')}")
        if (rt.get("environment") or {}).get("NOCSOC_AI_CLOUD_EGRESS_ENABLED", "false").lower() != "false":
            problems.append(f"{runtime}: cloud egress must be off in the base compose file")
    return problems


def render(env_file: Path) -> dict:
    docker = shutil.which("docker")
    if docker is None:
        raise SystemExit("docker not found on PATH")
    out = subprocess.run(  # noqa: S603  # nosec B603: fixed argv, no shell
        [
            docker,
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "--env-file",
            str(env_file),
            "--profile",
            "*",
            "config",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(out.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_env = ROOT / ".env" if (ROOT / ".env").exists() else ROOT / ".env.example"
    parser.add_argument("--env-file", type=Path, default=default_env)
    config = render(parser.parse_args().env_file)
    problems = check(config)
    for p in problems:
        print(f"FAIL {p}")
    if problems:
        return 1
    print(f"compose policy OK ({len(config.get('services', {}))} services)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
