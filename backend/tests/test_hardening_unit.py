"""P7 unit tests: audit anchors, outbox encoding, strict request types, trace headers, OpenBao provider."""

from __future__ import annotations

import base64
import json
import secrets
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from pydantic import BaseModel, ValidationError

from app.core import anchors
from app.core.secrets import LocalEnvelopeProvider, OpenBaoTransitProvider, SecretDecryptionError
from app.core.types import IsoDatetime, StrictBool, StrictInt
from app.ingestion import outbox
from app.telemetry import context_from_headers, kafka_headers

KEY = b"k" * 32


# ---------------------------------------------------------------- anchors
def test_anchor_lines_are_signed_and_chained(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    h1 = [anchors.Head(None, 3, "aa"), anchors.Head(str(uuid.uuid4()), 7, "bb")]
    d1 = anchors.append(path, anchors.Anchor(at="t1", heads=h1), KEY)
    anchors.append(path, anchors.Anchor(at="t2", heads=h1, prev=d1), KEY)
    history = anchors.read_all(path, KEY)
    assert [a.at for a, _ in history] == ["t1", "t2"] and history[0][0].heads == h1


def test_anchor_signature_covers_every_field(tmp_path: Path) -> None:
    line = anchors.encode(anchors.Anchor(at="t", heads=[anchors.Head(None, 1, "aa")]), KEY)
    with pytest.raises(anchors.AnchorFileError):
        anchors.decode(line.replace('"seq":1', '"seq":2'), KEY)
    with pytest.raises(anchors.AnchorFileError):
        anchors.decode(line, b"x" * 32)


def test_broken_anchor_chain_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    anchors.append(path, anchors.Anchor(at="t1", heads=[]), KEY)
    anchors.append(path, anchors.Anchor(at="t2", heads=[], prev="0" * 64), KEY)  # does not follow line 1
    with pytest.raises(anchors.AnchorFileError, match="line 2"):
        anchors.read_all(path, KEY)


# ---------------------------------------------------------------- outbox encoding
def test_outbox_round_trips_typed_rows() -> None:
    tenant = uuid.uuid4()
    when = datetime(2026, 11, 17, 5, 0, tzinfo=UTC)
    rows = {"events": [[tenant, when, "text", 3, 1.5, ["T1110"], None]], "metrics": []}
    decoded = outbox.decode(outbox.encode(rows))
    assert decoded == {"events": [[tenant, when, "text", 3, 1.5, ["T1110"], None]]}


# ---------------------------------------------------------------- strict request types
class Body(BaseModel):
    flag: StrictBool
    count: StrictInt
    at: IsoDatetime | None = None


@pytest.mark.parametrize(
    "payload",
    [
        {"flag": 0, "count": 1},
        {"flag": "true", "count": 1},
        {"flag": True, "count": "10"},
        {"flag": True, "count": 1, "at": 0.5},
        {"flag": True, "count": 1, "at": "1700000000"},
        {"flag": True, "count": 1, "at": "-9.06e-259"},
        {"flag": True, "count": 1, "at": "nan"},
    ],
)
def test_lax_values_are_refused(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Body.model_validate_json(json.dumps(payload))


def test_strict_values_are_accepted() -> None:
    b = Body.model_validate_json('{"flag": false, "count": 3, "at": "2026-11-17T05:00:00Z"}')
    assert b.flag is False and b.count == 3 and b.at is not None and b.at.year == 2026


# ---------------------------------------------------------------- trace context over Kafka
def test_kafka_headers_round_trip_without_a_span() -> None:
    headers = kafka_headers()  # no active span: nothing to inject, and that is fine
    assert isinstance(headers, list)
    assert context_from_headers(headers) is not None
    assert context_from_headers(None) is not None


# ---------------------------------------------------------------- OpenBao Transit provider
class FakeTransit:
    def __init__(self) -> None:
        self.wrapped: dict[str, bytes] = {}
        self.logins = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            self.logins += 1
            return httpx.Response(200, json={"auth": {"client_token": f"t{self.logins}", "lease_duration": 3600}})
        if request.headers.get("x-vault-token") != f"t{self.logins}":
            return httpx.Response(403)
        if request.url.path.startswith("/v1/transit/datakey/plaintext/"):
            dek = secrets.token_bytes(32)
            ct = f"vault:v1:{len(self.wrapped)}"
            self.wrapped[ct] = dek
            return httpx.Response(200, json={"data": {"plaintext": base64.b64encode(dek).decode(), "ciphertext": ct}})
        if request.url.path.startswith("/v1/transit/decrypt/"):
            ct = json.loads(request.content)["ciphertext"]
            return httpx.Response(200, json={"data": {"plaintext": base64.b64encode(self.wrapped[ct]).decode()}})
        return httpx.Response(404)


def provider(fake: FakeTransit, legacy: LocalEnvelopeProvider | None = None) -> OpenBaoTransitProvider:
    p = OpenBaoTransitProvider("https://openbao.test", "role", "secret", legacy=legacy)
    p._http = httpx.Client(base_url="https://openbao.test", transport=httpx.MockTransport(fake.handler))
    return p


def test_openbao_round_trip_binds_context() -> None:
    fake = FakeTransit()
    p = provider(fake)
    blob = p.encrypt("s3cret", "totp:1")
    assert json.loads(blob)["v"] == 2 and "s3cret" not in blob
    assert p.decrypt(blob, "totp:1") == "s3cret"
    with pytest.raises(SecretDecryptionError):
        p.decrypt(blob, "totp:2")  # copied to another record


def test_openbao_reads_v1_only_with_the_local_key() -> None:
    local = LocalEnvelopeProvider(secrets.token_hex(32))
    v1 = local.encrypt("old", "ctx")
    assert provider(FakeTransit(), legacy=local).decrypt(v1, "ctx") == "old"
    with pytest.raises(SecretDecryptionError, match="rewrap"):
        provider(FakeTransit()).decrypt(v1, "ctx")


def test_openbao_logs_in_again_when_the_token_is_refused() -> None:
    fake = FakeTransit()
    p = provider(fake)
    blob = p.encrypt("x", "c")
    fake.logins += 1  # the server forgot the token (restart, revocation)
    assert p.decrypt(blob, "c") == "x" and fake.logins == 3
