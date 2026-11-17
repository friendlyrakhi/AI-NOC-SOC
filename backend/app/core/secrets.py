"""Envelope encryption for secrets at rest (ADR-0009, threat model T18/T19).

Each value gets a fresh 256-bit data key (DEK). The value is encrypted with AES-256-GCM
under the DEK, and the DEK is wrapped with the master key (AES-256-GCM). An ``aad``
context string (e.g. ``totp:<user_id>``) is bound to both, so a ciphertext copied to
another record fails to decrypt.

Two providers share this format (the ``v`` field tells them apart, so both can coexist):
- ``LocalEnvelopeProvider`` (v1): the master key comes from a Docker secret file. Dev-grade.
- ``OpenBaoTransitProvider`` (v2, P7 ``hardened`` profile): each data key comes from OpenBao's
  Transit engine and only its wrapped form is stored; the master key never leaves OpenBao. The API
  authenticates with AppRole. v1 values stay readable when a local key is still configured, and
  ``app.tools.rewrap_secrets`` migrates them to v2.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Protocol

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_VERSION = 1


class SecretsProvider(Protocol):
    def encrypt(self, plaintext: str, aad: str) -> str: ...

    def decrypt(self, blob: str, aad: str) -> str: ...


class SecretDecryptionError(ValueError):
    pass


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode())


class LocalEnvelopeProvider:
    def __init__(self, master_key_hex: str, key_version: int = 1) -> None:
        key = bytes.fromhex(master_key_hex.strip())
        if len(key) != 32:
            raise ValueError("master key must be 32 bytes (64 hex characters)")
        self._master = AESGCM(key)
        self._key_version = key_version

    def encrypt(self, plaintext: str, aad: str) -> str:
        dek = AESGCM.generate_key(bit_length=256)
        nonce, wrap_nonce = os.urandom(12), os.urandom(12)
        ad = aad.encode()
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext.encode(), ad)
        wrapped = self._master.encrypt(wrap_nonce, dek, ad)
        return json.dumps(
            {
                "v": _VERSION,
                "kv": self._key_version,
                "wn": _b64(wrap_nonce),
                "wk": _b64(wrapped),
                "n": _b64(nonce),
                "c": _b64(ciphertext),
            },
            separators=(",", ":"),
        )

    def decrypt(self, blob: str, aad: str) -> str:
        try:
            d = json.loads(blob)
            if d["v"] != _VERSION:
                raise SecretDecryptionError("unsupported secret format")
            ad = aad.encode()
            dek = self._master.decrypt(_unb64(d["wn"]), _unb64(d["wk"]), ad)
            return AESGCM(dek).decrypt(_unb64(d["n"]), _unb64(d["c"]), ad).decode()
        except SecretDecryptionError:
            raise
        except Exception as exc:  # any tampering or wrong key/context
            raise SecretDecryptionError("secret could not be decrypted") from exc


class OpenBaoTransitProvider:
    """Envelope encryption with data keys from OpenBao Transit (v2 blobs).

    ``encrypt`` asks Transit for a fresh data key (``datakey/plaintext``), encrypts locally with
    AES-256-GCM bound to ``aad``, and stores only the wrapped key. ``decrypt`` has Transit unwrap
    it. The AppRole token is cached and renewed by logging in again when it expires or is refused.
    """

    def __init__(
        self,
        url: str,
        role_id: str,
        secret_id: str,
        *,
        key: str = "nocsoc-master",
        ca_file: str | None = None,
        legacy: LocalEnvelopeProvider | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._http = httpx.Client(base_url=url.rstrip("/"), verify=ca_file or True, timeout=timeout)
        self._role_id, self._secret_id, self._key = role_id, secret_id, key
        self._legacy = legacy
        self._token: str | None = None
        self._expires = 0.0
        self._lock = threading.Lock()

    @classmethod
    def from_files(
        cls, url: str, approle_dir: str, *, key: str, ca_file: str | None, legacy: LocalEnvelopeProvider | None
    ) -> OpenBaoTransitProvider:
        d = Path(approle_dir)
        return cls(
            url,
            (d / "role_id").read_text(encoding="utf-8").strip(),
            (d / "secret_id").read_text(encoding="utf-8").strip(),
            key=key,
            ca_file=ca_file,
            legacy=legacy,
        )

    def _login(self) -> str:
        r = self._http.post("/v1/auth/approle/login", json={"role_id": self._role_id, "secret_id": self._secret_id})
        r.raise_for_status()
        auth = r.json()["auth"]
        self._token = str(auth["client_token"])
        self._expires = time.monotonic() + max(30, int(auth.get("lease_duration", 600)) - 30)
        return self._token

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            token = self._token if self._token and time.monotonic() < self._expires else self._login()
            r = self._http.post(path, json=body, headers={"X-Vault-Token": token})
            if r.status_code == 403:  # token revoked or expired early: log in once more
                r = self._http.post(path, json=body, headers={"X-Vault-Token": self._login()})
        r.raise_for_status()
        return r.json()["data"]  # type: ignore[no-any-return]

    def encrypt(self, plaintext: str, aad: str) -> str:
        data = self._post(f"/v1/transit/datakey/plaintext/{self._key}", {})
        dek = base64.b64decode(data["plaintext"])
        nonce = os.urandom(12)
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext.encode(), aad.encode())
        return json.dumps(
            {"v": 2, "p": "openbao", "k": self._key, "wk": data["ciphertext"], "n": _b64(nonce), "c": _b64(ciphertext)},
            separators=(",", ":"),
        )

    def decrypt(self, blob: str, aad: str) -> str:
        try:
            d = json.loads(blob)
            version = d.get("v")
        except (ValueError, AttributeError) as exc:
            raise SecretDecryptionError("secret could not be decrypted") from exc
        if version == _VERSION:
            if self._legacy is None:
                raise SecretDecryptionError("a v1 secret needs the local master key (run rewrap_secrets)")
            return self._legacy.decrypt(blob, aad)
        if version != 2:
            raise SecretDecryptionError("unsupported secret format")
        try:
            dek = base64.b64decode(self._post(f"/v1/transit/decrypt/{d['k']}", {"ciphertext": d["wk"]})["plaintext"])
            return AESGCM(dek).decrypt(_unb64(d["n"]), _unb64(d["c"]), aad.encode()).decode()
        except httpx.HTTPError:
            raise  # OpenBao unreachable: an availability problem, not a tampered secret
        except Exception as exc:
            raise SecretDecryptionError("secret could not be decrypted") from exc


def build_provider(settings: Any) -> SecretsProvider:
    """The configured provider (``NOCSOC_SECRETS_PROVIDER``): ``local`` or ``openbao``."""
    legacy = LocalEnvelopeProvider(settings.master_key.get_secret_value()) if settings.master_key else None
    if settings.secrets_provider == "openbao":
        if not settings.openbao_url:
            raise RuntimeError("NOCSOC_OPENBAO_URL is required with the openbao secrets provider")
        return OpenBaoTransitProvider.from_files(
            settings.openbao_url,
            settings.openbao_approle_dir,
            key=settings.openbao_transit_key,
            ca_file=settings.tls_ca_file,
            legacy=legacy,
        )
    if legacy is None:
        raise RuntimeError("master key secret (nocsoc_master_key) is required")
    return legacy
