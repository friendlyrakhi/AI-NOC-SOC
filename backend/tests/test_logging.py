"""Structured logging: JSON lines carry the request ID and never the query string."""

import json
import logging

import pytest
from pydantic import SecretStr

from app.config import Settings
from app.logging_setup import JsonFormatter, SecretScrubber, configure_logging, request_id_var, scrubber


def test_json_formatter_includes_request_id_and_extra() -> None:
    token = request_id_var.set("req-12345678")
    try:
        record = logging.makeLogRecord(
            {"name": "t", "levelname": "INFO", "msg": "hello %s", "args": ("x",), "route": "/alerts"}
        )
        out = json.loads(JsonFormatter().format(record))
    finally:
        request_id_var.reset(token)
    assert out["message"] == "hello x"
    assert out["request_id"] == "req-12345678"
    assert out["route"] == "/alerts"
    assert out["level"] == "INFO"


@pytest.mark.parametrize(
    ("line", "leaked"),
    [
        ("session nss_AbCdEf123456789 created", "AbCdEf123456789"),
        ("key nsk_ZZZZyyyyXXXX1234 used", "ZZZZyyyyXXXX1234"),
        ("webhook secret whs_q1w2e3r4t5y6u7i8o9", "q1w2e3r4t5y6u7i8o9"),
        ("Authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi.payload.sig"),
        ('{"password": "hunter2-hunter2"}', "hunter2-hunter2"),
        ("connect failed: token=abc123def456 host=x", "abc123def456"),  # gitleaks:allow (fake test value)
    ],
)
def test_scrubber_masks_token_shapes(line: str, leaked: str) -> None:
    assert leaked not in SecretScrubber()(line)


def test_known_secret_values_are_redacted_in_json_lines_and_exceptions() -> None:
    secret = "s3cr3t-master-value-0123456789"
    configure_logging(settings=Settings(master_key=SecretStr(secret), valkey_password=SecretStr("valkey-pass-xyz")))
    try:
        raise RuntimeError(f"cannot connect with {secret}")
    except RuntimeError:
        record = logging.makeLogRecord(
            {"name": "t", "levelname": "ERROR", "msg": "boom valkey-pass-xyz", "exc_info": __import__("sys").exc_info()}
        )
    line = JsonFormatter().format(record)
    assert secret not in line and "valkey-pass-xyz" not in line
    assert "[redacted]" in line
    assert scrubber("plain message") == "plain message"
