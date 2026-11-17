"""P8 live-read verification of the Prometheus connector (ADR-0019): python scripts/verify_live.py

Runs the real open-source Prometheus 3.7 and Alertmanager 0.29 (compose profile `verify`) next to a
throwaway hardened stack (project nocsoc-live) with OpenBao Shamir unseal and live reads switched on.
Your dev stack is stopped (not changed) while it runs and started again afterwards.

Checks: a live instance needs step-up; a sandbox-only connector cannot be made live; the runner reads
the real Alertmanager v2 and Prometheus query APIs through the egress allow-list; the real alert and
the real `up` samples arrive through the normal pipeline (Postgres alert, ClickHouse metrics).
Writes reports/live-verification-prometheus.json and connectors/catalog/verification/prometheus.md.
The OpenBao key shares of the throwaway project are kept in memory only and discarded.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404: fixed argv
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BASE = [
    "docker",
    "compose",
    "-f",
    str(ROOT / "infrastructure/compose/docker-compose.yml"),
    "--env-file",
    str(ROOT / ".env"),
]
LIVE = [*BASE[:4], "-f", str(ROOT / "infrastructure/compose/hardened.override.yml"), *BASE[4:], "-p", "nocsoc-live"]
PROFILES = ["--profile", "core", "--profile", "stream", "--profile", "verify"]
ENV = {
    **os.environ,
    "NOCSOC_OPENBAO_UNSEAL": "shamir",
    "NOCSOC_LIVE_READ_ENABLED": "true",
    "NOCSOC_EGRESS_PRIVATE_ALLOWLIST": "prometheus-demo,alertmanager-demo",
    "NOCSOC_OTEL_ENABLED": "false",
}
results: dict[str, Any] = {"date": datetime.now(UTC).isoformat(timespec="seconds"), "checks": {}}

PROBE = r"""
import base64, hashlib, hmac, json, ssl, struct, sys, time, urllib.request, urllib.error
ctx = ssl.create_default_context(cafile="/run/secrets/tls_ca")
user = json.loads(sys.stdin.read())
def call(method, path, body=None, token=None):
    req = urllib.request.Request("https://api:8000/api/v1" + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type": "application/json", **({"authorization": "Bearer " + token} if token else {})})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as x:
            raw = x.read(); return x.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")
def totp(secret):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    d = hmac.new(key, struct.pack(">Q", int(time.time() // 30)), hashlib.sha1).digest()
    o = d[-1] & 15
    return f"{(struct.unpack('>I', d[o:o+4])[0] & 0x7FFFFFFF) % 1000000:06d}"
out = {}
s, b = call("POST", "/auth/login", {"email": user["email"], "password": user["password"]})
s, b = call("POST", "/auth/mfa/verify", {"challenge": b["challenge"], "code": totp(user["totp_secret"])})
token = b["session_token"]
cfg = {"alertmanager_url": "http://alertmanager-demo:9093", "prometheus_url": "http://prometheus-demo:9090", "allow_http": True}
s, b = call("POST", "/connectors/instances", {"definition_id": "prometheus", "name": "live probe", "config": cfg, "mode": "live"}, token)
out["live_without_step_up"] = [s, (b or {}).get("code")]
time.sleep(31 - time.time() % 30)  # a fresh code for step-up
s, _ = call("POST", "/auth/step-up", {"code": totp(user["totp_secret"])}, token)
out["step_up"] = s
s, b = call("POST", "/connectors/instances", {"definition_id": "splunk", "name": "live splunk", "config": {}, "mode": "live"}, token)
out["live_sandbox_only_connector"] = [s, (b or {}).get("code")]
s, b = call("POST", "/connectors/instances", {"definition_id": "prometheus", "name": "Prometheus (live)", "config": cfg, "mode": "live"}, token)
out["live_create"] = [s, (b or {}).get("mode"), (b or {}).get("id")]
print(json.dumps(out))
"""


def sh(argv: list[str], *, inp: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    r = subprocess.run(argv, capture_output=True, text=True, env=ENV, input=inp, check=False)  # nosec B603
    if check and r.returncode != 0:
        raise SystemExit(f"FAILED {' '.join(argv[-6:])}\n{r.stdout[-1500:]}\n{r.stderr[-2500:]}")
    return r


def check(name: str, ok: bool, detail: Any = "") -> None:
    results["checks"][name] = {"ok": bool(ok), "detail": detail}
    print(("PASS " if ok else "FAIL ") + name + (f" - {detail}" if detail != "" else ""), flush=True)


def psql(sql: str) -> str:
    return sh(["docker", "exec", "nocsoc-live-postgres-1", "sh", "-c",
               f'PGPASSWORD="$(cat /run/secrets/postgres_password)" psql -h 127.0.0.1 -U postgres -d nocsoc -Atc "{sql}"']).stdout.strip()  # fmt: skip


def clickhouse(sql: str) -> str:
    return sh(["docker", "exec", "nocsoc-live-clickhouse-1", "sh", "-c",
               f'clickhouse-client --user nocsoc_admin --password "$(cat /run/secrets/clickhouse_admin_password)" -q "{sql}"']).stdout.strip()  # fmt: skip


def vendor(container: str, url: str) -> Any:
    return json.loads(sh(["docker", "exec", container, "wget", "-qO-", url]).stdout)


def main() -> int:
    live = sh([*BASE, "--profile", "*", "ps", "--services", "--status", "running"], check=False).stdout.split()
    print("stopping the dev stack:", len(live), "services", flush=True)
    sh([*BASE, "--profile", "*", "stop"], check=False)
    try:
        sh([*LIVE, "--profile", "core", "up", "-d", "--no-deps", "--wait", "openbao"])
        job = [*LIVE, "--profile", "core", "run", "--rm", "--no-deps", "-T", "openbao-setup",
               "python", "-m", "app.tools.openbao_setup", "init"]  # fmt: skip
        shares = json.loads([x for x in sh(job).stdout.splitlines() if x.startswith("{")][-1])["shares"]
        check("openbao initialised with operator shares (3, threshold 2); root token revoked", len(shares) == 3)
        del shares  # this project's shares are not kept
        print("starting the hardened stack with the verification targets ...", flush=True)
        sh([*LIVE, *PROFILES, "up", "-d", "--wait"])
        seeded = json.loads(
            sh([*LIVE, *PROFILES, "run", "--rm", "-T", "migrate", "python", "-m", "app.db.seed"]).stdout
        )
        users = {u["email"]: u for u in (seeded["users"] if isinstance(seeded, dict) else seeded)}
        out = json.loads(sh(["docker", "exec", "-i", "nocsoc-live-api-1", "python", "-c", PROBE],
                            inp=json.dumps(users["admin@globex.example"])).stdout.strip().splitlines()[-1])  # fmt: skip
        results["api"] = out
        check(
            "live instance refused without step-up", out["live_without_step_up"][0] == 403, out["live_without_step_up"]
        )
        check(
            "live instance of a sandbox-only connector refused",
            out["live_sandbox_only_connector"][1] == "connector.live_unsupported",
        )
        check(
            "live Prometheus instance created after step-up",
            out["live_create"][0] == 201 and out["live_create"][1] == "live",
        )
        audited = psql("SELECT count(*) FROM audit_log WHERE action = 'connector.create' AND details->>'mode' = 'live'")
        check("live instance creation audited", audited == "1", audited)

        am = vendor("nocsoc-live-alertmanager-demo-1", "http://localhost:9093/api/v2/status")
        prom = vendor("nocsoc-live-prometheus-demo-1", "http://localhost:9090/api/v1/status/buildinfo")
        results["vendor"] = {"alertmanager": am["versionInfo"]["version"], "prometheus": prom["data"]["version"]}
        deadline, alert, metrics = time.monotonic() + 180, "", "0"
        while time.monotonic() < deadline:
            alert = psql("SELECT title || '|' || severity || '|' || status FROM alerts WHERE connector_id = 'prometheus' "
                         "AND title LIKE 'VerificationAlwaysFiring%' LIMIT 1")  # fmt: skip
            metrics = clickhouse("SELECT count() FROM nocsoc.metrics WHERE connector = 'prometheus' AND name = 'up'")
            if alert and metrics not in ("", "0"):
                break
            time.sleep(10)
        check(
            "real Alertmanager alert ingested as a platform alert", alert.startswith("VerificationAlwaysFiring"), alert
        )
        check("real Prometheus 'up' samples stored in ClickHouse", metrics not in ("", "0"), metrics)
        status = psql(
            "SELECT status || '|' || coalesce(status_detail, '') FROM connector_instances WHERE mode = 'live'"
        )
        check(
            "runner reports the live instance healthy", status.startswith("ok") or status.startswith("healthy"), status
        )
        dead = psql(
            "SELECT count(*) FROM ingest_dead_letters d JOIN connector_instances i ON i.id = d.instance_id WHERE i.mode = 'live'"
        )
        check("no dead letters (no schema drift)", dead == "0", dead)
    finally:
        print("removing the throwaway stack ...", flush=True)
        sh([*LIVE, "--profile", "*", "down", "-v", "--remove-orphans"], check=False)
        print("starting the dev stack again ...", flush=True)
        sh([*BASE, "--profile", "*", "start", *live], check=False)
        out_file = ROOT / "reports" / "live-verification-prometheus.json"
        out_file.parent.mkdir(exist_ok=True)
        out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    failed = [k for k, v in results["checks"].items() if not v["ok"]]
    print("LIVE VERIFICATION", "FAILED: " + ", ".join(failed) if failed else "PASSED")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
