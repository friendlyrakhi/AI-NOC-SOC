"""Static policy check on the rendered Compose config (threat model T27, T30).

Usage: python scripts/check-compose.py [--env-file PATH]

Renders infrastructure/compose/docker-compose.yml with every profile enabled.

Fails when any service publishes a port on a non-loopback address, runs privileged,
mounts the Docker socket, adds capabilities, or passes secrets as environment values.
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
        if not svc.get("mem_limit") and not svc.get("deploy", {}).get("resources", {}).get(
            "limits", {}
        ).get("memory"):
            problems.append(f"{name}: no memory limit")
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
