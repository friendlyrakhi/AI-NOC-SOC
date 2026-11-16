"""Password hashing, opaque tokens and TOTP (IAM-1, IAM-5)."""

import hashlib
import hmac
import secrets
import time

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()  # Argon2id with library defaults (RFC 9106 profile)

# A real hash of a random value, verified on unknown users so login timing does not reveal
# whether an account exists.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 12

SESSION_PREFIX = "nss_"
API_KEY_PREFIX = "nsk_"
CHALLENGE_PREFIX = "nsc_"
INVITE_PREFIX = "nsi_"

TOTP_ISSUER = "NOC-SOC Platform"
TOTP_INTERVAL = 30


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_problems(password: str) -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > 256:
        problems.append("must be at most 256 characters")
    if password.strip() != password:
        problems.append("must not start or end with whitespace")
    return problems


def new_token(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def token_hash(token: str) -> bytes:
    """Tokens have 256 bits of entropy, so a fast hash is appropriate."""
    return hashlib.sha256(token.encode()).digest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------- TOTP (RFC 6238)
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, account: str) -> str:
    return pyotp.TOTP(secret, interval=TOTP_INTERVAL).provisioning_uri(name=account, issuer_name=TOTP_ISSUER)


def current_totp(secret: str, at: float | None = None) -> str:
    return pyotp.TOTP(secret, interval=TOTP_INTERVAL).at(at if at is not None else time.time())


def verify_totp(secret: str, code: str, last_used_step: int | None, at: float | None = None) -> int | None:
    """Return the matched time step, or None.

    Accepts one step of clock drift either way. A step at or before ``last_used_step`` is
    rejected so a code cannot be replayed.
    """
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return None
    now = at if at is not None else time.time()
    totp = pyotp.TOTP(secret, interval=TOTP_INTERVAL)
    current_step = int(now // TOTP_INTERVAL)
    for step in (current_step - 1, current_step, current_step + 1):
        if last_used_step is not None and step <= last_used_step:
            continue
        if hmac.compare_digest(totp.at(step * TOTP_INTERVAL), code):
            return step
    return None
