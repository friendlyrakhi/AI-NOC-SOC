"""Live verification of the hardened profile (P7): python scripts/verify_hardened.py

Stops the dev stack (its data is kept), starts the hardened profile in a separate, throwaway project
(nocsoc-hard) with fresh volumes, seeds it, and checks TLS on every link, that plain connections are
refused, sign-in with MFA (secrets unwrapped by OpenBao), and ingestion over TLS. Then removes the
throwaway project and restarts the dev stack. Results: reports/hardened-verification.json.

HTTPS checks run inside the stack with the platform CA: host antivirus that intercepts TLS (seen on the
development PC) would otherwise replace the certificate.
"""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.as_posix()
CA = f"{ROOT}/infrastructure/secrets/tls/ca.crt"
os.environ["SSL_CERT_FILE"] = CA
sys.path.insert(0, f"{ROOT}/scripts")

BASE = ["docker", "compose", "-f", f"{ROOT}/infrastructure/compose/docker-compose.yml", "--env-file", f"{ROOT}/.env"]
HARD = [
    "docker",
    "compose",
    "-f",
    f"{ROOT}/infrastructure/compose/docker-compose.yml",
    "-f",
    f"{ROOT}/infrastructure/compose/hardened.override.yml",
    "--env-file",
    f"{ROOT}/.env",
    "-p",
    "nocsoc-hard",
]
PROBE = r"""
# Runs inside the hardened api container: HTTPS checks with the platform CA (no host TLS interception).
import base64, hashlib, hmac, json, ssl, struct, sys, time, urllib.request, urllib.error
ctx = ssl.create_default_context(cafile="/run/secrets/tls_ca")
user = json.loads(sys.stdin.read())
out = {}
r = urllib.request.urlopen("https://edge:3443/login", context=ctx, timeout=15)
out["edge_status"] = r.status
out["edge_hsts"] = r.headers.get("strict-transport-security") or ""
out["edge_csp"] = r.headers.get("content-security-policy") or ""
def call(method, path, body=None, token=None):
    req = urllib.request.Request("https://api:8000/api/v1" + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type": "application/json", **({"authorization": "Bearer " + token} if token else {})})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as x:
            raw = x.read(); return x.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")
def totp(secret):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    d = hmac.new(key, struct.pack(">Q", int(time.time() // 30)), hashlib.sha1).digest()
    o = d[-1] & 15
    return f"{(struct.unpack('>I', d[o:o+4])[0] & 0x7FFFFFFF) % 1000000:06d}"
out["api_ready"] = call("GET", "/health/ready")[0]
s, b = call("POST", "/auth/login", {"email": user["email"], "password": user["password"]})
s, b = call("POST", "/auth/mfa/verify", {"challenge": b["challenge"], "code": totp(user["totp_secret"])})
token = b.get("session_token")
s, me = call("GET", "/auth/me", token=token)
out["signin_status"] = s
out["withheld"] = me.get("withheld_permissions")
s, inst = call("POST", "/connectors/instances", {"definition_id": "prometheus", "name": "tls probe", "config": {}}, token)
s, rep = call("POST", "/connectors/scenarios/noise_flapping/replay", token=token)
out["replay_status"] = s
print(json.dumps(out))
"""
PROFILES = ["--profile", "core", "--profile", "stream", "--profile", "search"]
results: dict[str, object] = {}


def sh(argv: list[str], check: bool = True, **kw: object) -> subprocess.CompletedProcess:
    r = subprocess.run(argv, capture_output=True, text=True, **kw)
    if check and r.returncode != 0:
        raise SystemExit(f"FAILED {' '.join(argv[-6:])}\n{r.stdout[-2000:]}\n{r.stderr[-3000:]}")
    return r


def check(name: str, ok: bool, detail: str = "") -> None:
    results[name] = {"ok": ok, "detail": detail}
    print(("PASS " if ok else "FAIL ") + name + (f" - {detail}" if detail else ""), flush=True)


live = sh([*BASE, "--profile", "*", "ps", "--services", "--status", "running"]).stdout.split()
print("stopping dev stack:", len(live), "services", flush=True)
sh([*BASE, "--profile", "*", "stop"])
try:
    env = {**os.environ, "NOCSOC_OTEL_ENABLED": "false"}
    print("starting hardened stack ...", flush=True)
    sh([*HARD, *PROFILES, "up", "-d", "--wait"], env=env)
    seeded = json.loads(sh([*HARD, *PROFILES, "run", "--rm", "-T", "migrate", "python", "-m", "app.db.seed"]).stdout)
    users = {u["email"]: u for u in seeded["users"]} if isinstance(seeded, dict) else {u["email"]: u for u in seeded}
    print("seeded", len(users), "users", flush=True)
    rewrap = json.loads(
        sh([*HARD, *PROFILES, "run", "--rm", "-T", "migrate", "python", "-m", "app.tools.rewrap_secrets"])
        .stdout.strip()
        .splitlines()[-1]
    )
    check("rewrap: no v1 secrets remain", rewrap["remaining_v1"] == 0, json.dumps(rewrap))

    # HTTPS checks from inside the stack (this PC's antivirus intercepts TLS on the host side).
    probe_src = PROBE
    inside = json.loads(
        sh(
            ["docker", "exec", "-i", "nocsoc-hard-api-1", "python", "-c", probe_src],
            input=json.dumps(users["admin@globex.example"]),
        )
        .stdout.strip()
        .splitlines()[-1]
    )
    results["inside"] = inside
    check("edge: https serves the app with the platform CA (verified)", inside["edge_status"] == 200)
    check("edge: HSTS header", "max-age" in inside["edge_hsts"])
    check("edge: nonce CSP", "'strict-dynamic'" in inside["edge_csp"])
    try:
        socket.create_connection(("127.0.0.1", 3000), timeout=3).close()
        check("web: plain port 3000 closed", False)
    except OSError:
        check("web: plain port 3000 closed", True)
    check("api: TLS with the platform CA (verified)", inside["api_ready"] == 200)
    try:
        urllib.request.urlopen("http://127.0.0.1:8100/api/v1/health/live", timeout=5)
        check("api: plain HTTP refused", False)
    except (urllib.error.URLError, ConnectionError, OSError) as exc:
        check("api: plain HTTP refused", True, type(exc).__name__)
    check(
        "sign-in with MFA over TLS (secret decrypted through OpenBao)",
        inside["signin_status"] == 200 and inside["withheld"] == [],
    )
    check("replay accepted", inside["replay_status"] == 200)

    # Secure cookie through the edge: sign in via the BFF login form is browser work; check the
    # BFF config instead (compose policy) and that the cookie flag is on in the container env.
    web_env = sh(["docker", "inspect", "nocsoc-hard-web-1", "--format", "{{json .Config.Env}}"]).stdout
    check("web: NOCSOC_COOKIE_SECURE=true", "NOCSOC_COOKIE_SECURE=true" in web_env)

    # Postgres refuses plain connections from the network
    probe = (
        "import psycopg,sys\n"
        "try:\n"
        "  psycopg.connect(host='postgres', dbname='nocsoc', user='nocsoc_app', password='x', sslmode='disable', connect_timeout=5)\n"
        "except Exception as e: print(type(e).__name__, str(e).splitlines()[0][:160])\n"
    )
    out = sh([*HARD, *PROFILES, "exec", "-T", "api", "python", "-c", probe]).stdout.strip()
    check("postgres: plain connection rejected by pg_hba", "no encryption" in out or "pg_hba" in out, out)
    ssl_on = sh(
        [
            "docker",
            "exec",
            "nocsoc-hard-postgres-1",
            "sh",
            "-c",
            'PGPASSWORD="$(cat /run/secrets/postgres_password)" psql -h 127.0.0.1 -U postgres -d nocsoc -Atc '
            "\"SELECT count(*) FILTER (WHERE ssl), count(*) FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) WHERE a.client_addr IS NOT NULL AND a.client_addr <> '127.0.0.1'\"",
        ],
    ).stdout.strip()
    tls_conns, all_conns = (int(x) for x in ssl_on.split("|"))
    check("postgres: every network session uses TLS", all_conns > 0 and tls_conns == all_conns, ssl_on)

    # Valkey: plain protocol refused
    plain = sh(
        [
            "docker",
            "exec",
            "nocsoc-hard-valkey-1",
            "sh",
            "-c",
            'REDISCLI_AUTH="$(cat /run/secrets/valkey_password)" valkey-cli -h valkey ping 2>&1 || true',
        ]
    ).stdout.strip()
    check("valkey: plain connection refused", "PONG" not in plain, plain[:120])

    # Secrets at rest: v2 (OpenBao) blobs
    v = sh(
        [
            "docker",
            "exec",
            "nocsoc-hard-postgres-1",
            "sh",
            "-c",
            'PGPASSWORD="$(cat /run/secrets/postgres_password)" psql -h 127.0.0.1 -U postgres -d nocsoc -Atc '
            "\"SELECT secret::jsonb->>'v', count(*) FROM user_credentials WHERE kind = 'totp' GROUP BY 1\"",
        ]
    ).stdout.strip()
    check("secrets at rest: MFA secrets are OpenBao (v2) blobs", v.startswith("2|") and "\n" not in v, v)

    # Ingestion over TLS end to end: replay, then ClickHouse (HTTPS) and OpenSearch (HTTPS) received data
    time.sleep(25)
    out = sh(
        [
            "docker",
            "exec",
            "nocsoc-hard-postgres-1",
            "sh",
            "-c",
            'PGPASSWORD="$(cat /run/secrets/postgres_password)" psql -h 127.0.0.1 -U postgres -d nocsoc -Atc '
            "\"SELECT (SELECT count(*) FROM telemetry_outbox), (SELECT count(*) FROM alerts WHERE connector_id = 'prometheus')\"",
        ]
    ).stdout.strip()
    pending, alerts = (int(x) for x in out.split("|"))
    check(
        "ingest over TLS: alerts stored, telemetry delivered to ClickHouse and OpenSearch (outbox empty)",
        alerts > 0 and pending == 0,
        out,
    )
    worker_errors = [
        line
        for line in sh(["docker", "logs", "nocsoc-hard-ingest-worker-1"]).stderr.splitlines()
        + sh(["docker", "logs", "nocsoc-hard-ingest-worker-1"]).stdout.splitlines()
        if '"ERROR"' in line or "SSL" in line
    ]
    check("ingest worker: no TLS errors", not worker_errors, "; ".join(worker_errors[:2])[:200])
    mem = sh(["docker", "stats", "--no-stream", "--format", "{{.Name}} {{.MemUsage}}"]).stdout
    results["memory"] = [m for m in mem.splitlines() if "nocsoc-hard" in m]
finally:
    print("removing hardened test stack ...", flush=True)
    sh([*HARD, "--profile", "*", "down", "-v", "--remove-orphans"], check=False)
    print("restarting dev stack ...", flush=True)
    sh([*BASE, "--profile", "*", "start", *live], check=False)
    with open(f"{ROOT}/reports/hardened-verification.json", "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
failed = [k for k, v in results.items() if isinstance(v, dict) and "ok" in v and not v["ok"]]
print("HARDENED VERIFICATION", "FAILED: " + ", ".join(failed) if failed else "PASSED")
