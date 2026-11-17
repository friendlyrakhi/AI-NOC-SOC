"""Static policy check on the rendered Compose config (threat model T27, T30).

Usage: python scripts/check-compose.py [--env-file PATH]

Renders infrastructure/compose/docker-compose.yml with every profile enabled, on its own and with
the hardened override (P7), and checks both.

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
HARDENED_FILE = ROOT / "infrastructure" / "compose" / "hardened.override.yml"

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
    problems += check_search_isolation(config)
    problems += check_anchor_isolation(config)
    problems += check_telemetry_isolation(config)
    problems += check_vendor_isolation(config)
    return problems


# P8: vendor systems (verification targets, on-premises tools) are reachable by the runner only, and
# the verification targets reach nothing of the platform.
VENDOR_MEMBERS = {"connector-runner", "prometheus-demo", "alertmanager-demo"}


def check_vendor_isolation(config: dict) -> list[str]:
    services = config.get("services", {})
    problems = []
    if "vendors" in config.get("networks", {}) and not (config["networks"]["vendors"] or {}).get("internal"):
        problems.append("network 'vendors' must be internal")
    for name, svc in services.items():
        if "vendors" in _networks(svc) and name not in VENDOR_MEMBERS:
            problems.append(f"{name}: must not join the 'vendors' network")
        if name in {"prometheus-demo", "alertmanager-demo"} and _networks(svc) != {"vendors"}:
            problems.append(f"{name}: must be attached only to network 'vendors'")
        if name in {"prometheus-demo", "alertmanager-demo"} and (svc.get("secrets") or svc.get("ports")):
            problems.append(f"{name}: verification targets get no secrets and publish no ports")
    return problems


# Observability (P7): only these services send telemetry; the backend has no internet.
TELEMETRY_MEMBERS = {"otel-lgtm", "api", "ingest-worker", "audit-anchor", "workflow-worker"}


def check_telemetry_isolation(config: dict) -> list[str]:
    services = config.get("services", {})
    if "otel-lgtm" not in services:
        return []
    problems = []
    if not (config.get("networks", {}).get("telemetry") or {}).get("internal"):
        problems.append("network 'telemetry' must be internal (no internet)")
    if _networks(services["otel-lgtm"]) != {"telemetry"}:
        problems.append("otel-lgtm: must be attached only to network 'telemetry'")
    for name, svc in services.items():
        if "telemetry" in _networks(svc) and name not in TELEMETRY_MEMBERS:
            problems.append(f"{name}: must not join the 'telemetry' network")
    return problems


# Audit anchors (P7, T28): only the anchor service writes the anchor volume and holds the key;
# the verifier reads it. The API and everything else must not see either.
ANCHOR_KEY_HOLDERS = {"audit-anchor", "audit-verify"}
ANCHOR_VOLUME = "auditanchors"


def check_anchor_isolation(config: dict) -> list[str]:
    problems = []
    for name, svc in config.get("services", {}).items():
        for secret in svc.get("secrets") or []:
            if secret.get("source") == "audit_anchor_key" and name not in ANCHOR_KEY_HOLDERS:
                problems.append(f"{name}: must not hold audit_anchor_key")
        for vol in svc.get("volumes") or []:
            if vol.get("source") != ANCHOR_VOLUME:
                continue
            if name not in ANCHOR_KEY_HOLDERS:
                problems.append(f"{name}: must not mount the audit anchor volume")
            elif name != "audit-anchor" and not vol.get("read_only"):
                problems.append(f"{name}: must mount the audit anchor volume read-only")
    return problems


# Services that run connector code must not share a network with the data stores (T13).
# The workflow worker also runs connector code (action executors), so the same rules apply.
CONNECTOR_RUNTIMES = {"connector-runner", "workflow-worker"}
DATA_STORES = {"postgres", "valkey", "clickhouse", "opensearch"}


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
            if "DATABASE" in key or "CLICKHOUSE" in key or "VALKEY" in key or "OPENSEARCH" in key:
                problems.append(f"{runtime}: has data-store setting {key}")
        for secret in rt.get("secrets") or []:
            source = str(secret.get("source", ""))
            if any(s in source for s in ("database", "clickhouse", "valkey", "postgres", "master_key", "opensearch")):
                problems.append(f"{runtime}: has data-store secret {secret.get('source')}")
    return problems


# The AI gateway may talk to the API only (LLM06, T21): one internal network, one secret.
AI_RUNTIMES = {"ai-gateway"}
# TLS material (hardened profile) grants no data access.
AI_ALLOWED_SECRETS = {"ai_gateway_token", "anthropic_api_key", "tls_ca", "ai_gateway_tls_crt", "ai_gateway_tls_key"}


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


# OpenSearch (P6, SEC-ISO-03): reachable only on the internal 'search' network, never published,
# and each store credential held only by the service that needs it.
SEARCH_MEMBERS = {"opensearch", "opensearch-setup", "api", "ingest-worker"}
SEARCH_SECRETS = {
    "opensearch_admin_password": {"opensearch", "opensearch-setup"},
    "opensearch_reader_password": {"opensearch-setup", "api"},
    "opensearch_indexer_password": {"opensearch-setup", "ingest-worker"},
}


def check_search_isolation(config: dict) -> list[str]:
    services = config.get("services", {})
    if "opensearch" not in services:
        return []
    problems = []
    if not (config.get("networks", {}).get("search") or {}).get("internal"):
        problems.append("network 'search' must be internal (no internet)")
    if _networks(services["opensearch"]) != {"search"}:
        problems.append("opensearch: must be attached only to network 'search'")
    if services["opensearch"].get("ports"):
        problems.append("opensearch: must not publish ports")
    for name, svc in services.items():
        if "search" in _networks(svc) and name not in SEARCH_MEMBERS:
            problems.append(f"{name}: must not join the 'search' network")
        for secret in svc.get("secrets") or []:
            source = str(secret.get("source", ""))
            if source in SEARCH_SECRETS and name not in SEARCH_SECRETS[source]:
                problems.append(f"{name}: must not hold {source}")
    return problems


def render(env_file: Path, *extra: Path) -> dict:
    docker = shutil.which("docker")
    if docker is None:
        raise SystemExit("docker not found on PATH")
    files = [a for f in (COMPOSE_FILE, *extra) for a in ("-f", str(f))]
    out = subprocess.run(  # noqa: S603  # nosec B603: fixed argv, no shell
        [
            docker,
            "compose",
            *files,
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
    env_file = parser.parse_args().env_file
    failed = False
    for label, extra in (("default", ()), ("hardened", (HARDENED_FILE,))):
        config = render(env_file, *extra)
        problems = check(config) + (check_hardened(config) if extra else [])
        for p in problems:
            print(f"FAIL [{label}] {p}")
        failed = failed or bool(problems)
        if not problems:
            print(f"compose policy OK [{label}] ({len(config.get('services', {}))} services)")
    return 1 if failed else 0


# Hardened profile (P7): OpenBao and its AppRole are reachable only by the services that need them,
# and the web app is reachable only through the TLS edge.
SECRETS_MEMBERS = {"openbao", "openbao-setup", "api", "migrate"}


def check_hardened(config: dict) -> list[str]:
    services = config.get("services", {})
    problems = []
    if not (config.get("networks", {}).get("secrets") or {}).get("internal"):
        problems.append("network 'secrets' must be internal (no internet)")
    for name, svc in services.items():
        if "secrets" in _networks(svc) and name not in SECRETS_MEMBERS:
            problems.append(f"{name}: must not join the 'secrets' network")
        for vol in svc.get("volumes") or []:
            if vol.get("source") == "baoinit" and name != "openbao-setup":
                problems.append(f"{name}: must not mount the OpenBao init volume")
            if vol.get("source") == "baoapprole" and name not in SECRETS_MEMBERS - {"openbao"}:
                problems.append(f"{name}: must not mount the OpenBao AppRole volume")
    if services.get("web", {}).get("ports"):
        problems.append("web: must not publish ports in the hardened profile (use the TLS edge)")
    if services.get("web", {}).get("environment", {}).get("NOCSOC_COOKIE_SECURE") != "true":
        problems.append("web: session cookies must be Secure in the hardened profile")
    return problems


if __name__ == "__main__":
    sys.exit(main())
