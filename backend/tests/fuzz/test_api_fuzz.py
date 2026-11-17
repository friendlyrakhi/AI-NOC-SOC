"""API fuzzing with Schemathesis (P7, docs/08): every operation in the published OpenAPI document,
positive and negative inputs, against the real app with real stores (Postgres, Valkey, Redpanda,
ClickHouse, OpenSearch with the security plugin; the AI gateway in-process; Temporal absent).

Run with ``pytest -m fuzz`` (CI gate ``fuzz``). The default test run excludes it because it writes a
lot of throwaway data into the session's databases.

A finding is any of:
- a server error (5xx), except the documented ``*.disabled`` answer of a profile that is not running;
- a response that does not match its documented schema or content type;
- invalid input (negative mode) that is accepted with a 2xx;
- a protected operation that answers anything but 401 without credentials.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

import pytest
import schemathesis
from hypothesis import HealthCheck, settings
from schemathesis.specs.openapi.checks import (
    content_type_conformance,
    negative_data_rejection,
    response_schema_conformance,
)
from support.insights import InsightsEnv

pytestmark = pytest.mark.fuzz

OPENAPI = Path(__file__).resolve().parents[2] / "openapi" / "openapi.json"
ADMIN = "admin@globex.example"
# Excluded: the SSE stream never ends; logout and tenant switching would end or move the fuzzing
# session itself. They are covered by the auth and live-update integration tests.
EXCLUDED = r"^/api/v1/(stream|auth/logout|auth/switch-tenant)$"

schema = schemathesis.openapi.from_path(OPENAPI).exclude(path_regex=EXCLUDED)
schema.config.generation.update(with_security_parameters=False)


@schemathesis.check
def no_server_error(ctx: Any, response: Any, case: Any) -> bool | None:
    """5xx is a failure, except ``503 *.disabled``: a feature whose profile is not running."""
    if response.status_code < 500:
        return None
    if response.status_code == 503:
        try:
            code = response.json().get("code", "")
        except ValueError:
            code = ""
        if code.endswith(".disabled"):
            return None
    raise AssertionError(f"server error {response.status_code}: {response.text[:300]}")


CHECKS = [no_server_error, response_schema_conformance, content_type_conformance, negative_data_rejection]


class Session:
    """A tenant admin's session with step-up refreshed before it expires (5 minutes)."""

    def __init__(self, data: InsightsEnv) -> None:
        self.data = data
        self.stepped = 0.0

    def headers(self) -> dict[str, str]:
        if time.monotonic() - self.stepped > 240:
            self.data.api.login(ADMIN, fresh=True)
            self.data.api.switch(ADMIN, "globex")
            self.data.api.step_up(ADMIN)
            self.stepped = time.monotonic()
        return self.data.api.headers(ADMIN)


@pytest.fixture(scope="module")
def session(insights: InsightsEnv) -> Session:
    return Session(insights)


def call(data: InsightsEnv, case: Any, headers: dict[str, str]) -> Any:
    kwargs = case.as_transport_kwargs(base_url="http://api.example", headers=headers)
    kwargs.pop("cookies", None)
    for key in ("timeout", "allow_redirects", "verify"):
        kwargs.pop(key, None)
    return data.api.client.request(**kwargs)


@schema.parametrize()
@settings(
    max_examples=12,
    deadline=None,
    suppress_health_check=list(HealthCheck),
    derandomize=True,
)
def test_api_fuzz(case: Any, session: Session, insights: InsightsEnv) -> None:
    response = call(insights, case, session.headers())
    case.validate_response(response, checks=CHECKS)


def test_every_protected_operation_refuses_anonymous_calls(insights: InsightsEnv) -> None:
    """Without credentials, every operation that declares a security requirement answers 401."""
    failures = []
    for result in schema.get_all_operations():
        op = result.ok()
        if not op.definition.raw.get("security"):
            continue
        path = op.path
        for name in [p.name for p in op.path_parameters]:
            path = path.replace("{" + name + "}", str(uuid.uuid4()) if "id" in name else "x")
        r = insights.api.client.request(op.method.upper(), path)
        if r.status_code not in (401, 503):
            failures.append(f"{op.method.upper()} {op.path} -> {r.status_code}")
        elif r.status_code == 503 and not r.json().get("code", "").endswith(".disabled"):
            failures.append(f"{op.method.upper()} {op.path} -> 503 {r.json().get('code')}")
    assert failures == []
