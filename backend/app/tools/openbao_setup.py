"""OpenBao setup for the `hardened` profile (P7, P8): ``python -m app.tools.openbao_setup [command]``.

Two unseal modes (``NOCSOC_OPENBAO_UNSEAL``):

``auto`` (default, dev-grade)
    On every start: initialise once with 1 key share, keep the unseal key and root token in the
    `baoinit` volume (only this job mounts it), unseal, and configure (below).

``shamir`` (required for live connectors, ADR-0019)
    Nothing on disk can unseal OpenBao.
    ``init``    run once by the operator (scripts/openbao.ps1 init): 3 shares, threshold 2, printed
                once to the operator's terminal; unseals, configures with the root token, then
                revokes the root token.
    ``unseal``  run by the operator after every restart (scripts/openbao.ps1 unseal): reads shares
                from stdin.
    (default)   the stack's setup job: waits until the operator has unsealed OpenBao, then checks
                that the AppRole credentials exist. It never holds a key share or a root token.

Configuration (both modes): the Transit engine and the ``nocsoc-master`` key (aes256-gcm96, not
exportable), and an AppRole for the platform whose policy can only request and unwrap data keys.
Its role id and secret id go to the `baoapprole` volume (read-only for the API and migrate job).
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx

from app.config import Settings, get_settings

INIT_FILE = Path("/var/lib/openbao-init/init.json")
APPROLE_DIR = Path("/run/openbao")
POLICY = """
path "transit/datakey/plaintext/{key}" {{ capabilities = ["update"] }}
path "transit/decrypt/{key}" {{ capabilities = ["update"] }}
"""
SHARES, THRESHOLD = 3, 2
WAIT_FOR_UNSEAL_SECONDS = 30 * 60


def call(c: httpx.Client, method: str, path: str, token: str | None = None, body: Any = None) -> Any:
    r = c.request(method, f"/v1/{path}", headers={"X-Vault-Token": token} if token else {}, json=body)
    if r.status_code >= 400:
        raise SystemExit(f"openbao {method} {path}: {r.status_code} {r.text[:300]}")
    return r.json() if r.content else {}


def client(settings: Settings) -> httpx.Client:
    if not settings.openbao_url:
        raise SystemExit("NOCSOC_OPENBAO_URL is required")
    return httpx.Client(base_url=settings.openbao_url, verify=settings.tls_ca_file or True, timeout=10)


def reachable(c: httpx.Client) -> None:
    for attempt in range(60):
        try:
            c.get("/v1/sys/health", params={"sealedcode": 200, "uninitcode": 200})
            return
        except httpx.HTTPError:
            if attempt == 59:
                raise
            time.sleep(2)


def health(c: httpx.Client) -> dict[str, Any]:
    params = {"sealedcode": 200, "uninitcode": 200, "standbycode": 200}
    return c.get("/v1/sys/health", params=params).json()  # type: ignore[no-any-return]


def wait_active(c: httpx.Client) -> None:
    """Integrated (Raft) storage: a freshly unsealed node elects itself leader after a moment."""
    for _ in range(60):
        if c.get("/v1/sys/health").status_code == 200:  # initialised, unsealed and active
            return
        time.sleep(1)
    raise SystemExit("openbao did not become active")


def configure(c: httpx.Client, root: str, key: str) -> None:
    mounts = call(c, "GET", "sys/mounts", root)
    if "transit/" not in mounts.get("data", mounts):
        call(c, "POST", "sys/mounts/transit", root, {"type": "transit"})
    if c.get(f"/v1/transit/keys/{key}", headers={"X-Vault-Token": root}).status_code == 404:
        call(c, "POST", f"transit/keys/{key}", root, {"type": "aes256-gcm96", "exportable": False})
        print(f"transit key {key} created")
    call(c, "PUT", "sys/policies/acl/nocsoc-app", root, {"policy": POLICY.format(key=key)})
    auths = call(c, "GET", "sys/auth", root)
    if "approle/" not in auths.get("data", auths):
        call(c, "POST", "sys/auth/approle", root, {"type": "approle"})
    role = {"token_policies": ["nocsoc-app"], "token_ttl": "1h", "token_max_ttl": "4h", "secret_id_ttl": "0"}  # nosec B105
    call(c, "POST", "auth/approle/role/nocsoc-app", root, role)
    role_id = call(c, "GET", "auth/approle/role/nocsoc-app/role-id", root)["data"]["role_id"]
    secret_id = call(c, "POST", "auth/approle/role/nocsoc-app/secret-id", root)["data"]["secret_id"]
    APPROLE_DIR.mkdir(parents=True, exist_ok=True)
    (APPROLE_DIR / "role_id").write_text(role_id)
    (APPROLE_DIR / "secret_id").write_text(secret_id)


# ---------------------------------------------------------------- auto (dev-grade)
def auto(settings: Settings) -> int:
    with client(settings) as c:
        reachable(c)
        if not health(c).get("initialized"):
            init = call(c, "PUT", "sys/init", body={"secret_shares": 1, "secret_threshold": 1})  # nosec B105
            INIT_FILE.write_text(json.dumps({"key": init["keys_base64"][0], "root_token": init["root_token"]}))
            INIT_FILE.chmod(0o600)
            print("openbao initialised (dev-grade auto-unseal)")
        creds = json.loads(INIT_FILE.read_text())
        if call(c, "GET", "sys/seal-status").get("sealed"):
            call(c, "PUT", "sys/unseal", body={"key": creds["key"]})
            print("openbao unsealed")
        wait_active(c)
        configure(c, creds["root_token"], settings.openbao_transit_key)
    print("openbao ready: transit key, policy and AppRole for the platform")
    return 0


# ---------------------------------------------------------------- shamir (operator-held shares)
def shamir_init(settings: Settings) -> int:
    with client(settings) as c:
        reachable(c)
        if health(c).get("initialized"):
            raise SystemExit("openbao is already initialised; use 'unseal'")
        body = {"secret_shares": SHARES, "secret_threshold": THRESHOLD}  # nosec B105
        init = call(c, "PUT", "sys/init", body=body)
        shares, root = init["keys_base64"], init["root_token"]
        for share in shares[:THRESHOLD]:
            call(c, "PUT", "sys/unseal", body={"key": share})
        wait_active(c)
        try:
            configure(c, root, settings.openbao_transit_key)
        finally:
            call(c, "POST", "auth/token/revoke-self", root)  # no standing root token
    # The shares go to the operator's terminal only (scripts/openbao.ps1 prints them once).
    print(json.dumps({"shares": shares, "threshold": THRESHOLD}))
    return 0


def shamir_unseal(settings: Settings) -> int:
    shares = [line.strip() for line in sys.stdin.read().splitlines() if line.strip()]
    with client(settings) as c:
        reachable(c)
        for share in shares:
            if not call(c, "PUT", "sys/unseal", body={"key": share}).get("sealed"):
                break
        status = call(c, "GET", "sys/seal-status")
    if status.get("sealed"):
        print(f"still sealed: {status.get('progress', 0)} of {status.get('t', THRESHOLD)} shares accepted")
        return 1
    print("openbao unsealed")
    return 0


def shamir_wait(settings: Settings) -> int:
    """The stack's setup job: wait for the operator, then check the AppRole credentials."""
    with client(settings) as c:
        reachable(c)
        deadline = time.monotonic() + WAIT_FOR_UNSEAL_SECONDS
        announced = False
        while True:
            state = health(c)
            if state.get("initialized") and not state.get("sealed"):
                break
            if not announced:
                what = "unseal" if state.get("initialized") else "init"
                print(f"openbao is {'sealed' if state.get('initialized') else 'not initialised'}: "
                      f"run scripts\\openbao.ps1 {what}", flush=True)  # fmt: skip
                announced = True
            if time.monotonic() > deadline:
                raise SystemExit("openbao was not unsealed in time")
            time.sleep(3)
        wait_active(c)
    if not (APPROLE_DIR / "role_id").exists():
        raise SystemExit("AppRole credentials missing: OpenBao was initialised outside scripts/openbao.ps1 init")
    print("openbao unsealed by the operator; AppRole credentials present")
    return 0


def main(argv: list[str]) -> int:
    settings = get_settings()
    command = argv[0] if argv else ""
    if settings.openbao_unseal == "auto":
        if command:
            raise SystemExit(f"'{command}' needs NOCSOC_OPENBAO_UNSEAL=shamir")
        return auto(settings)
    if command == "init":
        return shamir_init(settings)
    if command == "unseal":
        return shamir_unseal(settings)
    return shamir_wait(settings)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
