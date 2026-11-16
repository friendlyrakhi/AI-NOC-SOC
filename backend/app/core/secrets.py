"""Envelope encryption for secrets at rest (ADR-0009, threat model T18/T19).

Each value gets a fresh 256-bit data key (DEK). The value is encrypted with AES-256-GCM
under the DEK, and the DEK is wrapped with the master key (AES-256-GCM). An ``aad``
context string (e.g. ``totp:<user_id>``) is bound to both, so a ciphertext copied to
another record fails to decrypt.

The master key comes from a Docker secret file. This is dev-grade. OpenBao/KMS must
replace it before any real credential is stored (P8 gate).
"""

import base64
import json
import os
from typing import Protocol

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
