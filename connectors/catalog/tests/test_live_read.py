"""P8 live reads (ADR-0019): egress rules, LiveHttp, and Prometheus against real-API-shaped responses."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from nocsoc_connector_sdk import (
    AlertV1,
    ConfigError,
    ConnectorContext,
    EgressBlockedError,
    FetchBudget,
    LiveHttp,
    MetricPointV1,
    SchemaDriftError,
    check_egress,
)
from nocsoc_connectors import REGISTRY

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


async def resolve_private(host: str) -> list[str]:
    return ["10.20.30.40"]


async def resolve_public(host: str) -> list[str]:
    return ["93.184.216.34"]


def run(coro: Any) -> Any:
    return asyncio.run(coro)


# ---------------------------------------------------------------- egress
@pytest.mark.parametrize(
    ("url", "kw", "resolver"),
    [
        ("http://am.example.com", {}, resolve_public),  # plain http to a public host
        ("https://am.corp", {}, resolve_private),  # private address, not allow-listed
        ("http://am.corp", {"private_allowlist": frozenset({"am.corp"})}, resolve_private),  # http without opt-in
        ("https://postgres", {"private_allowlist": frozenset({"postgres"})}, resolve_private),  # platform service
        ("https://169.254.169.254", {"private_allowlist": frozenset({"169.254.169.254"})}, resolve_private),
        ("https://localhost", {"private_allowlist": frozenset({"localhost"})}, resolve_private),
    ],
    ids=["http-public", "private-unlisted", "http-no-optin", "platform-host", "metadata", "loopback-name"],
)
def test_egress_refuses(url: str, kw: dict[str, Any], resolver: Any) -> None:
    with pytest.raises(EgressBlockedError):
        run(check_egress(url, resolver, **kw))


def test_egress_allows_listed_private_host_and_opt_in_http() -> None:
    listed = frozenset({"alertmanager.corp"})
    assert run(check_egress("https://alertmanager.corp:9093", resolve_private, private_allowlist=listed))
    url = run(
        check_egress("http://alertmanager.corp:9093/", resolve_private, private_allowlist=listed, allow_http=True)
    )
    assert url == "http://alertmanager.corp:9093"


def test_live_http_never_sends_credentials_over_http() -> None:
    http = LiveHttp({"Authorization": "Bearer x"}, private_allowlist=frozenset({"am.corp"}), allow_http=True,
                    resolver=resolve_private)  # fmt: skip
    with pytest.raises(EgressBlockedError, match="credentials"):
        run(http.get_json("http://am.corp", "/api/v2/alerts"))


# ---------------------------------------------------------------- Prometheus live read
AM_ALERT = {
    "annotations": {"summary": "Disk almost full", "description": "Filesystem /var below 10%"},
    "endsAt": "2026-11-17T12:10:00.000Z",
    "fingerprint": "6c5c3bd5b1a0a0c1",
    "receivers": [{"name": "default"}],
    "startsAt": "2026-11-17T11:50:00.000Z",
    "status": {"inhibitedBy": [], "silencedBy": [], "state": "active"},
    "updatedAt": "2026-11-17T11:59:00.000Z",
    "generatorURL": "http://prometheus:9090/graph?g0.expr=...",
    "labels": {"alertname": "NodeFilesystemAlmostFull", "instance": "web-01:9100", "severity": "warning"},
}
QUERY = {
    "status": "success",
    "data": {
        "resultType": "vector",
        "result": [
            {"metric": {"__name__": "up", "instance": "web-01:9100", "job": "node"}, "value": [1794902400.1, "1"]}
        ],
    },
}


def connector(handler: Any) -> Any:
    http = LiveHttp(resolver=resolve_public, transport=httpx.MockTransport(handler))
    cfg = {"alertmanager_url": "https://am.example.com", "prometheus_url": "https://prom.example.com"}
    ctx = ConnectorContext(tenant_id="t", instance_id="i", mode="live", clock=lambda: NOW)
    return REGISTRY["prometheus"](ctx, cfg, http=http)


def test_prometheus_live_reads_real_api_shapes() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.url.host}{request.url.path}?{request.url.query.decode()}")
        if request.url.path == "/api/v2/alerts":
            return httpx.Response(200, json=[AM_ALERT])
        return httpx.Response(200, json=QUERY)

    conn = connector(handler)
    alerts = run(conn.fetch("alerts", None, FetchBudget()))
    metrics = run(conn.fetch("metrics", None, FetchBudget()))
    assert seen[0].startswith("am.example.com/api/v2/alerts?active=true")
    assert seen[1].startswith("prom.example.com/api/v1/query?query=up")
    [alert] = REGISTRY["prometheus"].normalize("alerts", alerts.records[0])
    assert isinstance(alert, AlertV1) and alert.title.startswith("NodeFilesystemAlmostFull")
    assert alert.dedup_key == "prometheus:6c5c3bd5b1a0a0c1"
    [point] = REGISTRY["prometheus"].normalize("metrics", metrics.records[0])
    assert isinstance(point, MetricPointV1) and point.name == "up" and point.value == 1.0


def test_prometheus_live_detects_drift_and_never_writes() -> None:
    conn = connector(lambda r: httpx.Response(200, json={"data": []}))  # not an array
    with pytest.raises(SchemaDriftError):
        run(conn.fetch("alerts", None, FetchBudget()))
    with pytest.raises(ConfigError, match="live actions are disabled"):
        run(conn.transport.post_json("/api/v2/silences", {}))


def test_live_mode_needs_live_read_support() -> None:
    ctx = ConnectorContext(tenant_id="t", instance_id="i", mode="live")
    with pytest.raises(ConfigError, match="does not support live reads"):
        REGISTRY["splunk"](ctx, {}, http=LiveHttp())
