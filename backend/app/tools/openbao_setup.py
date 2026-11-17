"""One-shot OpenBao setup for the `hardened` profile (P7): ``python -m app.tools.openbao_setup``.

On every start of the stack:
1. Initialise OpenBao once (1 key share; dev-grade). The unseal key and root token are kept in the
   `baoinit` volume, which only this job mounts.
2. Unseal it (file storage keeps OpenBao sealed after a restart).
3. Ensure the Transit engine and the ``nocsoc-master`` key (aes256-gcm96, not exportable).
4. Ensure an AppRole for the platform whose policy can only request and unwrap data keys with that
   key, and write its role id and a fresh secret id to the `baoapprole` volume, which the API and
   the migrate job mount read-only.

Production would replace step 1-2 with KMS auto-unseal or Shamir shares held by operators.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx

from app.config import get_settings

INIT_FILE = Path("/var/lib/openbao-init/init.json")
APPROLE_DIR = Path("/run/openbao")
POLICY = """
path "transit/datakey/plaintext/{key}" {{ capabilities = ["update"] }}
path "transit/decrypt/{key}" {{ capabilities = ["update"] }}
"""


def call(c: httpx.Client, method: str, path: str, token: str | None = None, body: Any = None) -> Any:
    r = c.request(method, f"/v1/{path}", headers={"X-Vault-Token": token} if token else {}, json=body)
    if r.status_code >= 400:
        raise SystemExit(f"openbao {method} {path}: {r.status_code} {r.text[:300]}")
    return r.json() if r.content else {}


def main() -> int:
    settings = get_settings()
    if not settings.openbao_url:
        raise SystemExit("NOCSOC_OPENBAO_URL is required")
    key = settings.openbao_transit_key
    with httpx.Client(base_url=settings.openbao_url, verify=settings.tls_ca_file or True, timeout=10) as c:
        for attempt in range(60):
            try:
                status = c.get("/v1/sys/health", params={"sealedcode": 200, "uninitcode": 200}).json()
                break
            except httpx.HTTPError:
                if attempt == 59:
                    raise
                time.sleep(2)
        if not status.get("initialized"):
            init = call(c, "PUT", "sys/init", body={"secret_shares": 1, "secret_threshold": 1})  # nosec B105: OpenBao field names, not secrets
            INIT_FILE.write_text(json.dumps({"key": init["keys_base64"][0], "root_token": init["root_token"]}))
            INIT_FILE.chmod(0o600)
            print("openbao initialised")
        creds = json.loads(INIT_FILE.read_text())
        if call(c, "GET", "sys/seal-status").get("sealed"):
            call(c, "PUT", "sys/unseal", body={"key": creds["key"]})
            print("openbao unsealed")
        root = creds["root_token"]
        # Integrated (Raft) storage: a freshly unsealed node elects itself leader after a moment.
        for _ in range(60):
            if c.get("/v1/sys/health").status_code == 200:  # 200 = initialised, unsealed and active
                break
            time.sleep(1)
        else:
            raise SystemExit("openbao did not become active")

        mounts = call(c, "GET", "sys/mounts", root)
        if "transit/" not in mounts.get("data", mounts):
            call(c, "POST", "sys/mounts/transit", root, {"type": "transit"})
        r = c.get(f"/v1/transit/keys/{key}", headers={"X-Vault-Token": root})
        if r.status_code == 404:
            call(c, "POST", f"transit/keys/{key}", root, {"type": "aes256-gcm96", "exportable": False})
            print(f"transit key {key} created")

        call(c, "PUT", "sys/policies/acl/nocsoc-app", root, {"policy": POLICY.format(key=key)})
        auths = call(c, "GET", "sys/auth", root)
        if "approle/" not in auths.get("data", auths):
            call(c, "POST", "sys/auth/approle", root, {"type": "approle"})
        call(
            c,
            "POST",
            "auth/approle/role/nocsoc-app",
            root,
            {"token_policies": ["nocsoc-app"], "token_ttl": "1h", "token_max_ttl": "4h", "secret_id_ttl": "0"},  # nosec B105
        )
        role_id = call(c, "GET", "auth/approle/role/nocsoc-app/role-id", root)["data"]["role_id"]
        secret_id = call(c, "POST", "auth/approle/role/nocsoc-app/secret-id", root)["data"]["secret_id"]
        APPROLE_DIR.mkdir(parents=True, exist_ok=True)
        (APPROLE_DIR / "role_id").write_text(role_id)
        (APPROLE_DIR / "secret_id").write_text(secret_id)
    print("openbao ready: transit key, policy and AppRole for the platform")
    return 0


if __name__ == "__main__":
    sys.exit(main())
