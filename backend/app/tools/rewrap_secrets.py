"""Re-encrypt local-key (v1) secrets with OpenBao Transit (v2): ``python -m app.tools.rewrap_secrets``.

Run once after switching to the `hardened` profile (scripts/dev.ps1 up -Hardened does it). Every
encrypted value is decrypted with its context string (the same ``aad`` the application uses) and
encrypted again by the OpenBao provider:
- connector credentials and webhook secrets (``secrets``), bound to their connector instance;
- MFA secrets (``user_credentials``, kind totp), bound to their user;
- pending MFA enrollments (``auth_challenges``), bound to the challenge.
Idempotent: values that are already v2 are skipped. After it reports 0 remaining v1 values, the local
master key is no longer needed by the hardened stack.
"""

from __future__ import annotations

import json
import sys

from sqlalchemy import create_engine, text

from app.config import get_settings
from app.core.secrets import OpenBaoTransitProvider, build_provider


def _v1(blob: str | None) -> bool:
    try:
        return bool(blob) and json.loads(blob or "{}").get("v") == 1
    except ValueError:
        return False


def main() -> int:
    settings = get_settings()
    provider = build_provider(settings)
    if not isinstance(provider, OpenBaoTransitProvider):
        raise SystemExit("set NOCSOC_SECRETS_PROVIDER=openbao (hardened profile) before rewrapping")
    engine = create_engine(settings.superuser_database_url())
    done = {"secrets": 0, "totp": 0, "enrollments": 0}
    try:
        with engine.begin() as conn:
            rows = conn.execute(
                text(
                    "SELECT s.id, s.ciphertext, "
                    "CASE WHEN s.kind = 'connector_credential' THEN 'connector-credential:' "
                    "ELSE 'connector-webhook:' END || i.id AS aad "
                    "FROM secrets s JOIN connector_instances i ON i.secret_id = s.id OR i.webhook_secret_id = s.id"
                )
            ).all()
            for r in rows:
                if _v1(r.ciphertext):
                    new = provider.encrypt(provider.decrypt(r.ciphertext, r.aad), r.aad)
                    conn.execute(text("UPDATE secrets SET ciphertext = :c WHERE id = :id"), {"c": new, "id": r.id})
                    done["secrets"] += 1
            for r in conn.execute(text("SELECT user_id, secret FROM user_credentials WHERE kind = 'totp'")).all():
                if _v1(r.secret):
                    aad = f"totp:{r.user_id}"
                    new = provider.encrypt(provider.decrypt(r.secret, aad), aad)
                    conn.execute(
                        text("UPDATE user_credentials SET secret = :s WHERE user_id = :u AND kind = 'totp'"),
                        {"s": new, "u": r.user_id},
                    )
                    done["totp"] += 1
            pending = conn.execute(
                text(
                    "SELECT id, pending_secret FROM auth_challenges "
                    "WHERE pending_secret IS NOT NULL AND used_at IS NULL"
                )
            ).all()
            for r in pending:
                if _v1(r.pending_secret):
                    aad = f"enroll:{r.id}"
                    new = provider.encrypt(provider.decrypt(r.pending_secret, aad), aad)
                    conn.execute(
                        text("UPDATE auth_challenges SET pending_secret = :s WHERE id = :id"), {"s": new, "id": r.id}
                    )
                    done["enrollments"] += 1
            remaining = sum(
                1
                for (blob,) in conn.execute(
                    text(
                        "SELECT ciphertext FROM secrets UNION ALL "
                        "SELECT secret FROM user_credentials WHERE kind = 'totp'"
                    )
                )
                if _v1(blob)
            )
    finally:
        engine.dispose()
    print(json.dumps({"rewrapped": done, "remaining_v1": remaining}))
    return 0 if remaining == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
