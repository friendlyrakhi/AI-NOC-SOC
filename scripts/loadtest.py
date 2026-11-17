"""Load tests for NFR-1 and NFR-2 (P7). Needs the stack running and seeded (scripts/dev up; seed).

    python scripts/loadtest.py api                   # NFR-1: k6, 100k alerts in a SYNTHETIC tenant
    python scripts/loadtest.py ingest --rate 1000    # NFR-2: 1,000 events/s for 60 s through the bus
    python scripts/loadtest.py cleanup               # removes the SYNTHETIC load-test tenant

`api` seeds (once) the standalone tenant `loadtest` with 100,000 synthetic alerts and 2,000
incidents, then runs tests/load/api.js with k6 against the API (compose network, read-only API
key valid for one day). The demo tenants are not touched.

`ingest` creates the scenario's sandbox instances in the DEMO tenant Globex if needed, raises the
per-tenant ingest quota for the run (the worker is recreated, then restored), and produces envelopes
at the target rate with `app.tools.loadgen`. It reports the sustained processing rate and, when the
observability profile runs, the p95 connector-to-stored latency from Prometheus.

Reports go to reports/load/<UTC timestamp>/ (git-ignored).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404: fixed argv, no shell
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from backup import compose, running  # noqa: E402
from dast import Api, env_port  # noqa: E402

# grafana/k6 (2026-11-12), pinned by digest.
K6_IMAGE = "grafana/k6@sha256:3d8e5c7f1d53ec59408c2ffbd9943602a0985ffcbd4a2430ec00f3ffca89796e"
NETWORK = "nocsoc_frontend"
GLOBEX_ADMIN = "admin@globex.example"
# Connectors whose simulators emit security events or metrics (same list as app.tools.loadgen).
TELEMETRY_CONNECTORS = ("splunk", "prometheus", "datadog", "aws.cloudwatch")


def run(argv: list[str], *, env: dict[str, str] | None = None, capture: bool = True) -> str:
    r = subprocess.run(  # noqa: S603  # nosec B603: fixed argv, no shell
        argv, capture_output=capture, text=True, check=False, env={**os.environ, **(env or {})}
    )
    if r.returncode != 0:
        raise SystemExit(f"command failed ({r.returncode}): {' '.join(argv[-5:])}\n{r.stderr if capture else ''}")
    return r.stdout if capture else ""


def out_dir() -> Path:
    d = ROOT / "reports" / "load" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------- NFR-1: API
def api_test(vus: int, duration: str) -> int:
    out = out_dir()
    print("==> seeding the SYNTHETIC load-test tenant (once; about a minute for 100k alerts)")
    seeded = json.loads(
        run([*compose("nocsoc"), "run", "--rm", "-T", "migrate", "python", "-m", "app.tools.seed_load"])
    )
    print(f"    tenant loadtest: {seeded['alerts']} alerts, {seeded['incidents']} incidents")
    docker = shutil.which("docker") or "docker"
    print(f"==> k6: {vus} virtual users for {duration}")
    k6 = subprocess.run(  # noqa: S603  # nosec B603: fixed argv, no shell
        [
            docker, "run", "--rm", "--network", NETWORK,
            "-v", f"{ROOT / 'tests' / 'load'}:/scripts:ro", "-v", f"{out}:/out",
            "-e", "API_KEY", "-e", "API_URL=http://api:8000", "-e", f"VUS={vus}", "-e", f"DURATION={duration}",
            "-u", "0", K6_IMAGE, "run", "--quiet", "--summary-export", "/out/k6-summary.json", "/scripts/api.js",
        ],
        env={**os.environ, "API_KEY": seeded["api_key"]},
        check=False,
    )  # fmt: skip
    summary = json.loads((out / "k6-summary.json").read_text(encoding="utf-8"))
    metrics = summary["metrics"]
    report: dict[str, Any] = {"alerts": seeded["alerts"], "incidents": seeded["incidents"], "vus": vus}
    for key in ("http_req_duration{kind:list}", "http_req_duration{kind:get}", "http_req_duration"):
        m = metrics.get(key, {})
        report[key] = {k: round(v, 1) for k, v in m.items() if k in ("med", "p(95)", "p(99)", "max")}
    report["requests"] = metrics.get("http_reqs", {}).get("count")
    report["rps"] = round(metrics.get("http_reqs", {}).get("rate", 0), 1)
    report["failed_rate"] = metrics.get("http_req_failed", {}).get("value")
    report["thresholds_passed"] = k6.returncode == 0
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"reports: {out}")
    return k6.returncode


# ---------------------------------------------------------------- NFR-2: ingest
def prometheus(query: str) -> float | None:
    if "otel-lgtm" not in running("nocsoc"):
        return None
    raw = run([*compose("nocsoc"), "exec", "-T", "otel-lgtm", "curl", "-s", "http://127.0.0.1:9090/api/v1/query",
               "--data-urlencode", f"query={query}"])  # fmt: skip
    result = json.loads(raw).get("data", {}).get("result", [])
    return float(result[0]["value"][1]) if result else None


def ensure_instances(api: Api, connectors: list[str]) -> dict[str, str]:
    status, existing = api.call("GET", "/connectors/instances")
    have = {}
    for inst in sorted(existing, key=lambda i: i["created_at"]):
        have.setdefault(inst["definition_id"], inst["id"])
    for cid in connectors:
        if cid not in have:
            status, body = api.call(
                "POST", "/connectors/instances", {"definition_id": cid, "name": f"{cid} (load test)", "config": {}}
            )
            if status != 201:
                raise SystemExit(f"could not create a sandbox instance of {cid}: {status} {body}")
            have[cid] = body["id"]
    return {c: have[c] for c in connectors}


def ingest_test(
    rate: float,
    seconds: float,
    scenario: str,
    quota: int,
    mix: str = "realistic",
    workers: int = 1,
    alert_share: float = 0.05,
) -> int:
    from nocsoc_connectors import SCENARIOS

    out = out_dir()
    users = {u["email"]: u for u in json.loads((ROOT / "infrastructure/secrets/dev-users.json").read_text())["users"]}
    api = Api(f"http://127.0.0.1:{env_port('NOCSOC_API_PORT', 8100)}")
    api.sign_in(users[GLOBEX_ADMIN])
    _, me = api.call("GET", "/auth/me")
    if me.get("active_tenant_kind") is None or not me.get("active_tenant_id"):
        raise SystemExit("the Globex admin has no active tenant")
    extra = TELEMETRY_CONNECTORS if mix == "realistic" else ()
    instances = ensure_instances(api, list(dict.fromkeys([*SCENARIOS[scenario].connectors, *extra])))
    pairs = ",".join(f"{c}={i}" for c, i in instances.items())

    # Recreating the worker re-reads compose variables: keep telemetry on when the profile runs.
    otel = {"NOCSOC_OTEL_ENABLED": "true" if "otel-lgtm" in running("nocsoc") else "false"}
    base = [*compose("nocsoc"), "--profile", "*", "up", "-d", "--no-deps"]
    recreate = [*base, "--scale", f"ingest-worker={workers}", "ingest-worker"]
    restore_default = [*base, "--scale", "ingest-worker=1", "ingest-worker"]
    print(f"==> raising the per-tenant ingest quota to {quota}/min for the run")
    run(recreate, env={**otel, "NOCSOC_TENANT_INGEST_RECORDS_PER_MINUTE": str(quota)})
    started = time.time()
    try:
        print(f"==> producing {rate:.0f} events/s for {seconds:.0f} s ({scenario})")
        raw = run(
            [*compose("nocsoc"), "--profile", "*", "run", "--rm", "--no-deps", "-T", "ingest-worker",
             "python", "-m", "app.tools.loadgen",
             "--tenant", me["active_tenant_id"], "--instances", pairs, "--scenario", scenario,
             "--rate", str(rate), "--seconds", str(seconds), "--mix", mix, "--alert-share", str(alert_share)]
        )  # fmt: skip
        report = json.loads(raw)
    finally:
        print("==> restoring the default ingest quota")
        run(restore_default, env=otel)
    window = max(60, int(time.time() - started) + 30)
    p95 = prometheus(
        f"histogram_quantile(0.95, sum by (le) (increase(nocsoc_ingest_latency_seconds_bucket[{window}s])))"
    )
    if p95 is not None:
        report["ingest_latency_p95_seconds"] = round(p95, 2)
    dead = prometheus(f'sum(increase(nocsoc_ingest_messages_total{{result="dead_letter"}}[{window}s]))')
    if dead is not None:
        report["dead_lettered"] = round(dead)
    report["workers"] = workers
    report["alert_share"] = alert_share
    report["meets_nfr2"] = bool(report.get("drained") and report.get("sustained_processing_rate", 0) >= rate * 0.95)
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"reports: {out}")
    return 0 if report["meets_nfr2"] else 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("api")
    a.add_argument("--vus", type=int, default=20)
    a.add_argument("--duration", default="2m")
    i = sub.add_parser("ingest")
    i.add_argument("--rate", type=float, default=1000)
    i.add_argument("--seconds", type=float, default=60)
    i.add_argument("--scenario", default="phishing_credential_misuse")
    i.add_argument("--quota", type=int, default=200_000)
    i.add_argument("--mix", choices=["realistic", "alerts"], default="realistic")
    i.add_argument("--workers", type=int, default=1, help="ingest worker replicas during the run")
    i.add_argument("--alert-share", type=float, default=0.05, help="share of alert messages (0 = telemetry only)")
    sub.add_parser("cleanup")
    args = p.parse_args()
    if args.cmd == "api":
        return api_test(args.vus, args.duration)
    if args.cmd == "ingest":
        return ingest_test(args.rate, args.seconds, args.scenario, args.quota, args.mix, args.workers, args.alert_share)
    print(run([*compose("nocsoc"), "run", "--rm", "-T", "migrate", "python", "-m", "app.tools.seed_load", "--remove"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
