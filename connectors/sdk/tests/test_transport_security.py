"""SEC-CON-01 (SSRF guard) and SEC-CON-03 (webhook signatures)."""

import asyncio
import time

import pytest

from nocsoc_connector_sdk.errors import EgressBlockedError
from nocsoc_connector_sdk.signing import sign, verify
from nocsoc_connector_sdk.transport import check_egress


def resolver(mapping: dict[str, list[str]]):  # type: ignore[no-untyped-def]
    async def resolve(host: str) -> list[str]:
        if host not in mapping:
            raise OSError("NXDOMAIN")
        return mapping[host]

    return resolve


PUBLIC = resolver(
    {
        "api.vendor.example": ["93.184.216.34"],
        "rebind.example": ["93.184.216.34", "10.0.0.5"],
        "meta.example": ["169.254.169.254"],
    }
)


@pytest.mark.parametrize(
    "url",
    [
        "http://api.vendor.example",  # not https
        "https://169.254.169.254/latest/meta-data",  # cloud metadata
        "https://10.1.2.3",  # RFC 1918
        "https://127.0.0.1:8443",  # loopback
        "https://[::1]/",  # IPv6 loopback
        "https://[fd00::1]/",  # IPv6 ULA
        "https://[::ffff:10.0.0.1]/",  # IPv4-mapped private
        "https://0.0.0.0/",  # unspecified
        "https://localhost/",
        "https://postgres.internal/",
        "https://user:pass@api.vendor.example/",  # credentials in URL
        "https://rebind.example/",  # any private address in the answer set
        "https://meta.example/",  # DNS name resolving to metadata address
        "https://does-not-resolve.example/",
    ],
)
def test_blocked_destinations(url: str) -> None:
    with pytest.raises(EgressBlockedError):
        asyncio.run(check_egress(url, PUBLIC))


def test_public_https_allowed() -> None:
    assert asyncio.run(check_egress("https://api.vendor.example/v1/", PUBLIC)) == "https://api.vendor.example/v1"


def test_signature_roundtrip_and_tampering() -> None:
    now = int(time.time())
    body = b'{"alerts": []}'
    sig = sign("s3cret", now, "nonce-12345678", body)
    assert verify("s3cret", str(now), "nonce-12345678", body, sig)
    assert not verify("s3cret", str(now), "nonce-12345678", body + b" ", sig)  # body changed
    assert not verify("wrong", str(now), "nonce-12345678", body, sig)  # wrong secret
    assert not verify("s3cret", str(now), "other-nonce-123", body, sig)  # nonce bound
    assert not verify(
        "s3cret", str(now - 3600), "nonce-12345678", body, sign("s3cret", now - 3600, "nonce-12345678", body)
    )  # stale
    assert not verify("s3cret", "abc", "nonce-12345678", body, sig)  # malformed timestamp
    assert not verify("s3cret", str(now), "short", body, sig)  # nonce too short
