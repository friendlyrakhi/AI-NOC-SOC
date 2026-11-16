"""Webhook signatures (docs/05 §3, threat model T14).

X-NocSoc-Signature: v1=hex(HMAC_SHA256(secret, f"{timestamp}.{nonce}.{body}"))
"""

import hashlib
import hmac
import time

MAX_SKEW_SECONDS = 300


def sign(secret: str, timestamp: int, nonce: str, body: bytes) -> str:
    msg = f"{timestamp}.{nonce}.".encode() + body
    return "v1=" + hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def verify(secret: str, timestamp: str, nonce: str, body: bytes, signature: str, now: float | None = None) -> bool:
    """Constant-time check of signature and timestamp skew. Nonce replay is checked by the caller."""
    if not (timestamp.isdigit() and 8 <= len(nonce) <= 128 and signature.startswith("v1=")):
        return False
    ts = int(timestamp)
    if abs((now if now is not None else time.time()) - ts) > MAX_SKEW_SECONDS:
        return False
    return hmac.compare_digest(sign(secret, ts, nonce, body), signature)
