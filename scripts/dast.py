"""DAST against the local stack with OWASP ZAP (P7, docs/08).

Usage (stack running with `scripts/dev up`, seeded):
    python scripts/dast.py                 # web baseline + authenticated API scan
    python scripts/dast.py --skip-api      # passive web baseline only (fast)

What runs (ZAP container attached to the compose `frontend` network; nothing is exposed):
1. Baseline (passive) scan of the web app, anonymous and with a signed-in session cookie.
   Form submission is disabled so the spider cannot trigger server actions.
2. API scan (active) of the API from its OpenAPI document, authenticated with a short-lived
   API key for the DEMO tenant Initech. API keys cannot sign out or switch tenants, so the
   scan cannot end its own access. The key is revoked afterwards.

The active scan sends attack payloads and creates throwaway records in the Initech tenant. It
uses mock data only; run `scripts/dev reset` + `seed` afterwards if you want a clean demo.

Exit code 1 when ZAP reports any High-risk alert that is not accepted in
scripts/dast-accepted.json (each acceptance needs a reason). Medium alerts are listed for review.
Reports (HTML + JSON) are written to reports/dast/<timestamp>/ (git-ignored).
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import json
import shutil
import struct
import subprocess  # nosec B404: fixed argv, no shell
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
# OWASP ZAP stable (2026-11-02), pinned by digest.
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af"
NETWORK = "nocsoc_frontend"
WEB, API = "http://web:3000", "http://api:8000"
ADMIN = "admin@initech.example"
RISK = {0: "Info", 1: "Low", 2: "Medium", 3: "High"}


def env_port(name: str, default: int) -> int:
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines() if (ROOT / ".env").exists() else []:
        if line.startswith(f"{name}="):
            return int(line.split("=", 1)[1].strip())
    return default


def totp(secret: str, at: float | None = None) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = struct.pack(">Q", int((at or time.time()) // 30))
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


class Api:
    def __init__(self, base: str) -> None:
        self.base = base
        self.token: str | None = None

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        req = urllib.request.Request(  # noqa: S310 - fixed loopback URL
            f"{self.base}/api/v1{path}",
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "content-type": "application/json",
                **({"authorization": f"Bearer {self.token}"} if self.token else {}),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310  # nosec B310: loopback only
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raw = e.read()
            return e.code, json.loads(raw) if raw else None

    def sign_in(self, user: dict[str, Any]) -> None:
        status, body = self.call("POST", "/auth/login", {"email": user["email"], "password": user["password"]})
        if status != 200 or body["status"] != "mfa_required":
            raise SystemExit(f"sign-in failed for {user['email']}: {status} {body}")
        challenge = body["challenge"]
        status, body = self.call(
            "POST", "/auth/mfa/verify", {"challenge": challenge, "code": totp(user["totp_secret"])}
        )
        if status != 200:
            raise SystemExit(f"MFA failed: {status} {body}")
        self.token = body["session_token"]

    def step_up(self, user: dict[str, Any]) -> None:
        time.sleep(31 - time.time() % 30)  # a fresh TOTP window (codes are single-use)
        status, body = self.call("POST", "/auth/step-up", {"code": totp(user["totp_secret"])})
        if status != 204:
            raise SystemExit(f"step-up failed: {status} {body}")


def zap(args: list[str], out: Path) -> int:
    docker = shutil.which("docker")
    if docker is None:
        raise SystemExit("docker not found")
    argv = [docker, "run", "--rm", "--network", NETWORK, "-v", f"{out}:/zap/wrk:rw", ZAP_IMAGE, *args]
    print("==> zap", " ".join(a if "Bearer" not in a and "nocsoc_session" not in a else "[auth]" for a in args[:2]))
    return subprocess.run(argv, check=False).returncode  # noqa: S603  # nosec B603: fixed argv, no shell


def header_rule(name: str, value: str) -> list[str]:
    """ZAP replacer rule that adds a request header to every request (authentication)."""
    cfg = {
        "description": "auth",
        "enabled": "true",
        "matchtype": "REQ_HEADER",
        "matchstr": name,
        "regex": "false",
        "replacement": value,
    }
    rule = " ".join(f"-config replacer.full_list(0).{k}={v}" for k, v in cfg.items())
    return ["-z", f"{rule} {EXCLUDES} -config scanner.maxScanDurationInMins=30"]


# Never-ending live-update streams (SSE) would hold the spider and scanner open; bound the active scan.
EXCLUDES = " ".join(
    f"-config globalexcludeurl.url_list.url({i}).regex={rx} -config globalexcludeurl.url_list.url({i}).enabled=true "
    f"-config globalexcludeurl.url_list.url({i}).description=stream{i}"
    for i, rx in enumerate([".*/api/live.*", ".*/api/v1/stream.*"])
)
NO_FORMS = "-config spider.processform=false -config spider.postform=false " + EXCLUDES


def alerts(report: Path) -> list[dict[str, Any]]:
    if not report.exists():
        return []
    data = json.loads(report.read_text(encoding="utf-8"))
    out = []
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            out.append({"site": site.get("@name"), **a})
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--skip-api", action="store_true", help="skip the active API scan")
    opts = parser.parse_args()

    users = {u["email"]: u for u in json.loads((ROOT / "infrastructure/secrets/dev-users.json").read_text())["users"]}
    accepted = json.loads((ROOT / "scripts/dast-accepted.json").read_text(encoding="utf-8"))["accepted"]
    accepted_ids = {str(a["pluginId"]) for a in accepted}
    out = ROOT / "reports" / "dast" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):  # the ZAP container runs as uid 1000 and writes its reports here
        out.chmod(0o777)  # nosec B103: local, git-ignored report folder

    api = Api(f"http://127.0.0.1:{env_port('NOCSOC_API_PORT', 8100)}")
    api.sign_in(users[ADMIN])

    reports = []
    zap(["zap-baseline.py", "-t", WEB, "-J", "web-anon.json", "-r", "web-anon.html", "-I", "-z", NO_FORMS], out)
    reports.append(out / "web-anon.json")
    cookie = header_rule("Cookie", f"nocsoc_session={api.token}")
    zap(
        [
            "zap-baseline.py",
            "-t",
            f"{WEB}/",
            "-J",
            "web-auth.json",
            "-r",
            "web-auth.html",
            "-I",
            "-m",
            "3",
            "-z",
            f"{cookie[1]} {NO_FORMS}",
        ],
        out,
    )
    reports.append(out / "web-auth.json")

    key_id = None
    if not opts.skip_api:
        api.step_up(users[ADMIN])
        status, me = api.call("GET", "/auth/me")
        perms = [p for p in me["permissions"] if p not in {"apikey:manage", "user:remove"}]
        status, key = api.call(
            "POST", "/api-keys", {"name": "DAST scan (temporary)", "permissions": perms, "expires_in_days": 1}
        )
        if status != 201:
            raise SystemExit(f"could not create the scan API key: {status} {key}")
        key_id = key["id"]
        try:
            zap(
                [
                    "zap-api-scan.py",
                    "-t",
                    f"{API}/api/v1/openapi.json",
                    "-f",
                    "openapi",
                    "-J",
                    "api.json",
                    "-r",
                    "api.html",
                    "-I",
                    *header_rule("Authorization", f"Bearer {key['key']}"),
                ],
                out,
            )
        finally:
            api.step_up(users[ADMIN])
            api.call("DELETE", f"/api-keys/{key_id}")
        reports.append(out / "api.json")

    findings = [a for r in reports for a in alerts(r)]
    high = [a for a in findings if int(a.get("riskcode", 0)) >= 3 and str(a.get("pluginid")) not in accepted_ids]
    medium = [a for a in findings if int(a.get("riskcode", 0)) == 2]
    summary = {}
    for a in findings:
        k = (RISK[int(a.get("riskcode", 0))], a.get("alert"), str(a.get("pluginid")))
        summary[k] = summary.get(k, 0) + int(a.get("count", 1) or 1)
    for (risk, name, pid), n in sorted(
        summary.items(), key=lambda kv: (["High", "Medium", "Low", "Info"].index(kv[0][0]), kv[0][1])
    ):
        mark = " (accepted)" if pid in accepted_ids else ""
        print(f"{risk:6} {name} [plugin {pid}] x{n}{mark}")
    print(f"reports: {out}")
    if high:
        print(f"DAST FAILED: {len(high)} high-risk alert(s) not accepted")
        return 1
    print(f"DAST passed: no unaccepted high-risk alerts ({len(medium)} medium to review)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
