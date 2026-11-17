"""Backup, restore and restore drill for the local stack (P7, docs/08).

Usage:
    python scripts/backup.py backup                     # -> backups/<UTC timestamp>/
    python scripts/backup.py restore backups/<ts> --yes # replaces the stack's data with the backup
    python scripts/backup.py drill                      # backup, then restore into a fresh, separate
                                                        # stack and verify it (dev data is untouched)

What a backup contains (backups/<ts>/, git-ignored):
- audit-anchors.tar  the signed audit anchors (taken FIRST, so every anchored head is in the dump)
- postgres.dump      pg_dump custom format of the `nocsoc` database (authoritative state)
- clickhouse.tar     native ClickHouse BACKUP of the `nocsoc` database (telemetry and facts)
- opensearch.tar     an OpenSearch snapshot repository holding the tenant indices (t-*)
- manifest.json      versions, row/document counts, SHA-256 of every file, and a fingerprint of the
                     master key (not the key)

Not included, by design:
- **Secrets** (infrastructure/secrets). Back them up separately and securely. Without the same
  master key, encrypted connector credentials and MFA secrets cannot be decrypted; restore refuses
  a backup whose master-key fingerprint does not match.
- The event bus (raw topics keep 24 h; it is a buffer, not a record) and the Temporal dev server's
  workflow history (action requests and their state are in Postgres).

ClickHouse and OpenSearch are optional: a backup includes them when their profiles are running.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess  # nosec B404: fixed argv, no shell
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ROOT / "infrastructure" / "compose" / "docker-compose.yml"
SECRETS = ROOT / "infrastructure" / "secrets"
LIVE, DRILL = "nocsoc", "nocsoc-drill"
DRILL_PROFILES = ["core", "stream", "search"]
WRITERS = ["web", "api", "ingest-worker", "audit-anchor", "workflow-worker", "connector-runner"]
# Paused during a backup so every store is captured at the same point (the API stays up).
QUIESCE = ["connector-runner", "ingest-worker"]
PG_TABLES = [
    "tenants",
    "users",
    "connector_instances",
    "assets",
    "alerts",
    "incidents",
    "incident_alerts",
    "action_requests",
    "ai_runs",
    "reports",
    "hunts",
    "audit_log",
]
PG = 'PGPASSWORD="$(cat /run/secrets/postgres_password)"'
CH = 'clickhouse-client --user nocsoc_admin --password "$(cat /run/secrets/clickhouse_admin_password)"'
OS = (
    'curl -sS -u "admin:$(cat /run/secrets/opensearch_admin_password)" '  # gitleaks:allow
    '-H "content-type: application/json"'
)
OS_REPO = "/usr/share/opensearch/data/snapshots"
CH_DIR = "/var/lib/clickhouse/backups"


# ---------------------------------------------------------------- docker compose helpers
def docker() -> str:
    path = shutil.which("docker")
    if path is None:
        raise SystemExit("docker not found on PATH")
    return path


def compose(project: str) -> list[str]:
    env = ROOT / ".env" if (ROOT / ".env").exists() else ROOT / ".env.example"
    return [docker(), "compose", "-f", str(COMPOSE_FILE), "--env-file", str(env), "-p", project]


def run(argv: list[str], *, stdin: bytes | None = None, check: bool = True) -> bytes:
    r = subprocess.run(argv, input=stdin, capture_output=True, check=False)  # noqa: S603  # nosec B603
    if check and r.returncode != 0:
        raise SystemExit(f"command failed ({r.returncode}): {' '.join(argv[-4:])}\n{r.stderr.decode(errors='replace')}")
    return r.stdout


def sh(project: str, service: str, script: str, *, stdin: bytes | None = None, user: str | None = None) -> bytes:
    """Runs a shell snippet inside a running service container; secrets stay inside it."""
    argv = [*compose(project), "exec", "-T"]
    if user:
        argv += ["-u", user]
    return run([*argv, service, "sh", "-c", script], stdin=stdin)


def running(project: str) -> set[str]:
    out = run([*compose(project), "--profile", "*", "ps", "--services", "--status", "running"], check=False)
    return set(out.decode().split())


def step(msg: str) -> None:
    print(f"==> {msg}", flush=True)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def master_key_fingerprint() -> str:
    key = (SECRETS / "master_key").read_text(encoding="utf-8").strip()
    return hashlib.sha256(b"nocsoc-master-key-fingerprint:" + key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------- counts (for verification)
def pg_counts(project: str) -> dict[str, int]:
    query = " UNION ALL ".join(f"SELECT '{t}', count(*) FROM {t}" for t in PG_TABLES)  # nosec B608: fixed names
    out = sh(project, "postgres", f'{PG} psql -h 127.0.0.1 -U postgres -d nocsoc -At -F "|" -c "{query}"')
    return {k: int(v) for k, v in (line.split("|") for line in out.decode().split())}


def pg_revision(project: str) -> str:
    q = "SELECT version_num FROM alembic_version"
    return sh(project, "postgres", f'{PG} psql -h 127.0.0.1 -U postgres -d nocsoc -At -c "{q}"').decode().strip()


def ch_counts(project: str) -> dict[str, int]:
    tables = (
        sh(
            project,
            "clickhouse",
            f"{CH} -q \"SELECT name FROM system.tables WHERE database = 'nocsoc' "
            "AND engine LIKE '%MergeTree' ORDER BY name\"",
        )
        .decode()
        .split()
    )
    counts = {}
    for t in tables:
        final = (
            " FINAL"
            if "Replacing"
            in sh(
                project,
                "clickhouse",
                f"{CH} -q \"SELECT engine FROM system.tables WHERE database = 'nocsoc' AND name = '{t}'\"",
            ).decode()
            else ""
        )
        counts[t] = int(sh(project, "clickhouse", f'{CH} -q "SELECT count() FROM nocsoc.{t}{final}"').decode().strip())
    return counts


def os_counts(project: str) -> dict[str, int]:
    sh(project, "opensearch", f"{OS} -XPOST 'http://127.0.0.1:9200/t-*/_refresh' >/dev/null")
    raw = sh(project, "opensearch", f"{OS} 'http://127.0.0.1:9200/_cat/indices/t-*?format=json&h=index,docs.count'")
    return {i["index"]: int(i["docs.count"]) for i in json.loads(raw or b"[]")}


# ---------------------------------------------------------------- backup
def backup(project: str = LIVE) -> Path:
    up = running(project)
    if "postgres" not in up:
        raise SystemExit("postgres is not running; start the stack first (scripts/dev up)")
    out = ROOT / "backups" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out.mkdir(parents=True)
    name = out.name.lower()
    manifest: dict[str, Any] = {
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "project": project,
        "master_key_fingerprint": master_key_fingerprint(),
        "files": {},
        "counts": {},
    }

    paused = [s for s in QUIESCE if s in up]
    if paused:
        step(f"pausing ingestion for a consistent cut: {', '.join(paused)}")
        run([*compose(project), "--profile", "*", "stop", *paused])
    try:
        _capture(project, up, out, name, manifest)
    finally:
        if paused:
            step("resuming ingestion")
            run([*compose(project), "--profile", "*", "start", *paused])
    for f in sorted(out.iterdir()):
        manifest["files"][f.name] = {"bytes": f.stat().st_size, "sha256": sha256(f)}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    step(f"backup written to {out}")
    return out


def _capture(project: str, up: set[str], out: Path, name: str, manifest: dict[str, Any]) -> None:
    step("audit anchors (first: every anchored head must be in the database dump)")
    tar = run([*compose(project), "run", "--rm", "--no-deps", "-T", "audit-anchor",
               "tar", "-C", "/var/lib/nocsoc/anchors", "-cf", "-", "."])  # fmt: skip
    (out / "audit-anchors.tar").write_bytes(tar)

    step("postgres (pg_dump)")
    manifest["alembic_revision"] = pg_revision(project)
    manifest["counts"]["postgres"] = pg_counts(project)
    dump = sh(project, "postgres", f"{PG} pg_dump -h 127.0.0.1 -U postgres -Fc nocsoc")
    (out / "postgres.dump").write_bytes(dump)

    if "clickhouse" in up:
        step("clickhouse (native BACKUP)")
        manifest["counts"]["clickhouse"] = ch_counts(project)
        sh(project, "clickhouse", f"{CH} -q \"BACKUP DATABASE nocsoc TO File('{CH_DIR}/{name}/')\" >/dev/null")
        tar = sh(project, "clickhouse", f"tar -C {CH_DIR} -cf - {name} && rm -rf {CH_DIR}/{name}")
        (out / "clickhouse.tar").write_bytes(tar)

    if "opensearch" in up:
        step("opensearch (snapshot of t-* indices)")
        manifest["counts"]["opensearch"] = os_counts(project)
        repo = json.dumps({"type": "fs", "settings": {"location": OS_REPO}})
        snap = json.dumps({"indices": "t-*", "include_global_state": False})
        base = "http://127.0.0.1:9200/_snapshot/nocsoc"
        sh(project, "opensearch", f"{OS} -XPUT '{base}' -d '{repo}' >/dev/null")
        result = json.loads(
            sh(project, "opensearch", f"{OS} -XPUT '{base}/{name}?wait_for_completion=true' -d '{snap}'")
        )
        if result.get("snapshot", {}).get("state") != "SUCCESS":
            raise SystemExit(f"opensearch snapshot failed: {result}")
        tar = sh(project, "opensearch", f"tar -C {OS_REPO} -cf - .")
        (out / "opensearch.tar").write_bytes(tar)
        manifest["opensearch_snapshot"] = name
        sh(project, "opensearch", f"{OS} -XDELETE '{base}/{name}' >/dev/null")


# ---------------------------------------------------------------- restore
def check_files(src: Path, manifest: dict[str, Any]) -> None:
    for fname, meta in manifest["files"].items():
        if sha256(src / fname) != meta["sha256"]:
            raise SystemExit(f"{fname}: checksum mismatch, the backup is damaged")


def restore(src: Path, project: str) -> tuple[dict[str, Any], list[str]]:
    """Restores every store, compares counts while the writers are still stopped, restarts them.
    Returns the manifest and the count problems."""
    manifest = json.loads((src / "manifest.json").read_text(encoding="utf-8"))
    check_files(src, manifest)
    if manifest["master_key_fingerprint"] != master_key_fingerprint():
        raise SystemExit("master key fingerprint differs: restore with the master key the backup was taken with")
    up = running(project)
    if "postgres" not in up:
        raise SystemExit(f"postgres is not running in project {project}")
    stopped = [s for s in WRITERS if s in up]
    step(f"stopping writers: {', '.join(stopped)}")
    if stopped:
        run([*compose(project), "--profile", "*", "stop", *stopped])
    try:
        step("postgres: drop, recreate, pg_restore")
        sh(project, "postgres", f"{PG} dropdb -h 127.0.0.1 -U postgres --force --if-exists nocsoc && "
                                f"{PG} createdb -h 127.0.0.1 -U postgres nocsoc")  # fmt: skip
        sh(project, "postgres", f"{PG} pg_restore -h 127.0.0.1 -U postgres -d nocsoc --exit-on-error",
           stdin=(src / "postgres.dump").read_bytes())  # fmt: skip

        if (src / "clickhouse.tar").exists():
            if "clickhouse" not in up:
                raise SystemExit("the backup has ClickHouse data but clickhouse is not running")
            step("clickhouse: RESTORE")
            name = src.name.lower()
            sh(project, "clickhouse", f"mkdir -p {CH_DIR} && tar -C {CH_DIR} -xf -",
               stdin=(src / "clickhouse.tar").read_bytes(), user="clickhouse")  # fmt: skip
            sh(project, "clickhouse", f'{CH} -q "DROP DATABASE IF EXISTS nocsoc SYNC"')
            sh(project, "clickhouse", f"{CH} -q \"RESTORE DATABASE nocsoc FROM File('{CH_DIR}/{name}/')\" >/dev/null")
            sh(project, "clickhouse", f"rm -rf {CH_DIR}/{name}", user="clickhouse")

        if (src / "opensearch.tar").exists():
            if "opensearch" not in up:
                raise SystemExit("the backup has OpenSearch data but opensearch is not running")
            step("opensearch: restore snapshot")
            base = "http://127.0.0.1:9200"
            sh(project, "opensearch", f"mkdir -p {OS_REPO} && tar -C {OS_REPO} -xf -",
               stdin=(src / "opensearch.tar").read_bytes(), user="opensearch")  # fmt: skip
            repo = json.dumps({"type": "fs", "settings": {"location": OS_REPO}})
            sh(project, "opensearch", f"{OS} -XDELETE '{base}/_snapshot/nocsoc' >/dev/null; "
                                      f"{OS} -XPUT '{base}/_snapshot/nocsoc' -d '{repo}' >/dev/null")  # fmt: skip
            existing = json.loads(
                sh(project, "opensearch", f"{OS} '{base}/_cat/indices/t-*?format=json&h=index'") or b"[]"
            )
            for idx in existing:
                sh(project, "opensearch", f"{OS} -XDELETE '{base}/{idx['index']}' >/dev/null")
            body = json.dumps({"indices": "t-*", "include_global_state": False})
            snap = manifest["opensearch_snapshot"]
            url = f"{base}/_snapshot/nocsoc/{snap}/_restore?wait_for_completion=true"
            r = json.loads(sh(project, "opensearch", f"{OS} -XPOST '{url}' -d '{body}'"))
            if r.get("snapshot", {}).get("shards", {}).get("failed", 1) != 0:
                raise SystemExit(f"opensearch restore failed: {r}")

        step("audit anchors")
        run([*compose(project), "run", "--rm", "--no-deps", "-T", "audit-anchor", "sh", "-c",
             "rm -f /var/lib/nocsoc/anchors/* && tar -C /var/lib/nocsoc/anchors -xf -"],
            stdin=(src / "audit-anchors.tar").read_bytes())  # fmt: skip
        step("comparing counts with the manifest (writers still stopped)")
        problems = count_problems(project, manifest)
    finally:
        if stopped:
            step("starting writers again")
            run([*compose(project), "--profile", "*", "start", *stopped])
    return manifest, problems


# ---------------------------------------------------------------- verification
def api_smoke(manifest: dict[str, Any]) -> list[str]:
    """Signs in as a seeded user (password + MFA secret decrypted with the master key) and reads."""
    users_file = SECRETS / "dev-users.json"
    if not users_file.exists():
        return []
    users = {u["email"]: u for u in json.loads(users_file.read_text(encoding="utf-8"))["users"]}
    user = users.get("admin@globex.example")
    if user is None:
        return []
    sys.path.insert(0, str(ROOT / "scripts"))
    from dast import Api  # same sign-in helper as the DAST script

    port = 8100
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines() if (ROOT / ".env").exists() else []:
        if line.startswith("NOCSOC_API_PORT="):
            port = int(line.split("=", 1)[1])
    api = Api(f"http://127.0.0.1:{port}")
    for _ in range(30):
        try:
            if api.call("GET", "/health/ready")[0] == 200:
                break
        except (urllib.error.URLError, ConnectionError):
            pass
        time.sleep(2)
    api.sign_in(user)
    status, _ = api.call("GET", "/incidents?limit=1")
    if status != 200:
        return [f"API smoke: GET /incidents answered {status}"]
    print(f"    API smoke: signed in as {user['email']} (MFA secret decrypted), incidents readable")
    return []


def count_problems(project: str, manifest: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if pg_revision(project) != manifest["alembic_revision"]:
        problems.append("alembic revision differs")
    checks = [("postgres", pg_counts)]
    up = running(project)
    if "clickhouse" in manifest["counts"] and "clickhouse" in up:
        checks.append(("clickhouse", ch_counts))
    if "opensearch" in manifest["counts"] and "opensearch" in up:
        checks.append(("opensearch", os_counts))
    for store, fn in checks:
        now = fn(project)
        for key, expected in manifest["counts"][store].items():
            if now.get(key) != expected:
                problems.append(f"{store}.{key}: expected {expected}, found {now.get(key)}")
        print(f"    {store}: {len(manifest['counts'][store])} counts compared")
    return problems


def verify(project: str, manifest: dict[str, Any]) -> list[str]:
    """After the writers are back: audit chains and anchors, and an API sign-in."""
    problems: list[str] = []
    step("audit chains and anchors (verify-audit)")
    r = subprocess.run([*compose(project), "--profile", "tools", "run", "--rm", "-T", "audit-verify"], check=False)  # noqa: S603  # nosec B603
    if r.returncode != 0:
        problems.append("verify-audit failed")
    problems += api_smoke(manifest)
    return problems


# ---------------------------------------------------------------- drill
def drill() -> int:
    """Backup the live stack, restore it into a brand-new stack with empty volumes, verify, clean up.
    The live stack's data is never touched; it is stopped (not removed) while the drill runs because
    both stacks publish the same local ports."""
    src = backup(LIVE)
    live_services = sorted(running(LIVE))
    report: dict[str, Any] = {"backup": src.name, "started_at": datetime.now(UTC).isoformat(timespec="seconds")}
    step("stopping the live stack (data volumes are kept)")
    run([*compose(LIVE), "--profile", "*", "stop"])
    problems: list[str] = []
    try:
        step(f"starting an empty stack '{DRILL}' ({', '.join(DRILL_PROFILES)})")
        profiles = [a for p in DRILL_PROFILES for a in ("--profile", p)]
        run([*compose(DRILL), *profiles, "up", "-d", "--wait"])
        t0 = time.monotonic()
        manifest, problems = restore(src, DRILL)
        report["restore_seconds"] = round(time.monotonic() - t0, 1)
        step("verifying the restored stack")
        problems += verify(DRILL, manifest)
    finally:
        step(f"removing the drill stack '{DRILL}' and its volumes")
        run([*compose(DRILL), "--profile", "*", "down", "-v", "--remove-orphans"], check=False)
        step("starting the live stack again")
        run([*compose(LIVE), "--profile", "*", "start", *live_services], check=False)
    report["problems"] = problems
    report["result"] = "passed" if not problems else "failed"
    (src / "drill.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    for p in problems:
        print(f"PROBLEM: {p}")
    took = report.get("restore_seconds")
    print(f"restore drill {report['result']} (restore took {took} s); report: {src / 'drill.json'}")
    return 0 if not problems else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("backup", help="back up the live stack")
    r = sub.add_parser("restore", help="restore a backup into a running stack (replaces its data)")
    r.add_argument("path", type=Path)
    r.add_argument("--project", default=LIVE)
    r.add_argument("--yes", action="store_true", help="confirm that the stack's current data is replaced")
    sub.add_parser("drill", help="backup + restore into a fresh separate stack + verify")
    args = parser.parse_args()
    if args.cmd == "backup":
        backup()
        return 0
    if args.cmd == "restore":
        if not args.yes:
            raise SystemExit("restore replaces all data in the target stack; re-run with --yes to confirm")
        manifest, problems = restore(args.path, args.project)
        problems += verify(args.project, manifest)
        for p in problems:
            print(f"PROBLEM: {p}")
        print("restore " + ("verified" if not problems else "FAILED verification"))
        return 0 if not problems else 1
    return drill()


if __name__ == "__main__":
    sys.exit(main())
