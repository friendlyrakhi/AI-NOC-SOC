"""Transports (docs/06 §4-6, threat model T12/T15).

Connectors talk to vendors only through a Transport. ``SandboxTransport`` routes requests to
an in-process vendor simulator (no network at all) and can inject faults.
``HttpTransport`` is the live path. It is guarded against SSRF and is unreachable in this
build, because live mode requires a live-verified connector and a platform setting that
cannot be enabled (see execution.py).
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

from nocsoc_connector_sdk.errors import (
    AuthError,
    EgressBlockedError,
    RateLimitedError,
    SchemaDriftError,
    TransientError,
)

MAX_RESPONSE_BYTES = 5 * 1024 * 1024


class Transport(Protocol):
    async def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any: ...

    async def post_json(self, path: str, body: dict[str, Any]) -> Any: ...


# ------------------------------------------------------------------ sandbox
@dataclass(frozen=True)
class FaultConfig:
    """Sandbox fault injection (FaultHarness). All rates are 0..1."""

    latency_ms: int = 0
    error_rate: float = 0.0
    rate_limit_rate: float = 0.0
    auth_failure: bool = False
    schema_drift_rate: float = 0.0

    @classmethod
    def from_config(cls, cfg: dict[str, Any] | None) -> FaultConfig:
        cfg = cfg or {}
        return cls(
            latency_ms=max(0, min(10_000, int(cfg.get("latency_ms", 0)))),
            error_rate=max(0.0, min(1.0, float(cfg.get("error_rate", 0.0)))),
            rate_limit_rate=max(0.0, min(1.0, float(cfg.get("rate_limit_rate", 0.0)))),
            auth_failure=bool(cfg.get("auth_failure", False)),
            schema_drift_rate=max(0.0, min(1.0, float(cfg.get("schema_drift_rate", 0.0)))),
        )


Route = Callable[[dict[str, Any]], Any]


@dataclass
class SandboxTransport:
    """Serves vendor-shaped responses from a simulator. Never opens a socket."""

    routes: dict[str, Route]
    faults: FaultConfig = field(default_factory=FaultConfig)
    rng: random.Random = field(default_factory=lambda: random.Random(0))  # noqa: S311  # nosec B311 - fault simulation
    calls: int = 0

    async def _apply_faults(self) -> None:
        self.calls += 1
        if self.faults.latency_ms:
            await asyncio.sleep(self.faults.latency_ms / 1000)
        if self.faults.auth_failure:
            raise AuthError("sandbox: credentials rejected (injected fault)")
        roll = self.rng.random()
        if roll < self.faults.rate_limit_rate:
            raise RateLimitedError("sandbox: HTTP 429 (injected fault)", retry_after=5)
        if roll < self.faults.rate_limit_rate + self.faults.error_rate:
            raise TransientError("sandbox: HTTP 503 (injected fault)")

    def _route(self, path: str) -> Route:
        route = self.routes.get(path)
        if route is None:
            raise TransientError(f"sandbox: HTTP 404 for {path}")
        return route

    def _drift(self, data: Any) -> Any:
        if self.faults.schema_drift_rate and isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict) and self.rng.random() < self.faults.schema_drift_rate:
                            item["__schema_drift__"] = True
                            for key in list(item)[:1]:
                                item.pop(key)
        return data

    async def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        await self._apply_faults()
        return self._drift(self._route(path)(params or {}))

    async def post_json(self, path: str, body: dict[str, Any]) -> Any:
        await self._apply_faults()
        return self._route(path)(body)


# ------------------------------------------------------------------ live (SSRF-guarded)
def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None and not _is_public(ip.ipv4_mapped))
    )


Resolver = Callable[[str], Awaitable[list[str]]]


async def _default_resolver(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


# Platform services: never a vendor destination, even if an operator lists them (ADR-0019).
PLATFORM_HOSTS = frozenset(
    {
        "postgres", "valkey", "clickhouse", "opensearch", "opensearch-setup", "redpanda", "api", "web", "edge",
        "openbao", "temporal", "ai-gateway", "otel-lgtm", "keycloak", "mailpit", "ingest-worker", "workflow-worker",
    }
)  # fmt: skip


def _never(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Addresses no allow-list can open: loopback, link-local (cloud metadata), unspecified, multicast."""
    return ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast


async def check_egress(
    url: str,
    resolver: Resolver = _default_resolver,
    *,
    private_allowlist: frozenset[str] = frozenset(),
    allow_http: bool = False,
) -> str:
    """Validates a vendor URL before any request (T12). Returns the normalized base URL.

    Default rules: https only; no userinfo; host must resolve; every resolved address must be
    public (blocks loopback, RFC 1918, link-local/metadata 169.254.0.0/16, ULA, multicast, ...).

    P8 (ADR-0019): hosts in the operator's ``private_allowlist`` (``NOCSOC_EGRESS_PRIVATE_ALLOWLIST``)
    may resolve to private addresses, for on-premises tools. Loopback, link-local/metadata and the
    platform's own services stay blocked. Plain http is allowed only for an allow-listed host and
    only when ``allow_http`` is set (callers never send credentials over it).
    """
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    loopback_name = host == "localhost" or host.endswith(".localhost")
    listed = bool(host) and host in private_allowlist and host not in PLATFORM_HOSTS and not loopback_name
    if parts.scheme != "https" and not (parts.scheme == "http" and listed and allow_http):
        raise EgressBlockedError("only https:// vendor URLs are allowed")
    if parts.username or parts.password:
        raise EgressBlockedError("credentials in URLs are not allowed")
    if not host:
        raise EgressBlockedError("URL has no host")
    if host in PLATFORM_HOSTS:
        raise EgressBlockedError("platform services are not vendor destinations")
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        if not listed and (host.endswith((".local", ".internal", ".localhost")) or host == "localhost"):
            raise EgressBlockedError("internal host names are not allowed") from None
        try:
            addresses = await resolver(host)
        except OSError as exc:
            raise EgressBlockedError("host does not resolve") from exc
    if not addresses:
        raise EgressBlockedError("host does not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if _never(ip) or not (_is_public(ip) or listed):
            raise EgressBlockedError("destination address is not public")
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host}{port}{parts.path.rstrip('/')}"


class LiveHttp:
    """HTTP for live reads (P8): every request re-validates its destination (``check_egress``),
    never follows redirects, caps response size, and maps vendor errors to SDK errors. Connectors
    with several endpoints (e.g. Prometheus and Alertmanager) pass the base URL per request."""

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        *,
        private_allowlist: frozenset[str] = frozenset(),
        allow_http: bool = False,
        resolver: Resolver = _default_resolver,
        timeout: float = 15.0,
        transport: Any = None,
    ) -> None:
        self._headers = dict(headers or {})
        self._allowlist = private_allowlist
        self._allow_http = allow_http
        self._resolver = resolver
        self._timeout = timeout
        self._transport = transport  # tests inject httpx.MockTransport

    async def get_json(self, base_url: str, path: str, params: dict[str, Any] | None = None) -> Any:
        import httpx

        base = await check_egress(
            base_url, self._resolver, private_allowlist=self._allowlist, allow_http=self._allow_http
        )
        if base.startswith("http://") and self._headers:
            raise EgressBlockedError("credentials are never sent over plain http")
        async with httpx.AsyncClient(
            timeout=self._timeout, follow_redirects=False, headers=self._headers, transport=self._transport
        ) as client:
            try:
                resp = await client.get(f"{base}{path}", params=params)
            except httpx.TransportError as exc:
                raise TransientError(f"vendor unreachable: {type(exc).__name__}") from exc
        if resp.status_code in (401, 403):
            raise AuthError(f"vendor returned HTTP {resp.status_code}")
        if resp.status_code == 429:
            raise RateLimitedError(retry_after=float(resp.headers.get("retry-after", "30") or 30))
        if 300 <= resp.status_code < 400:
            raise EgressBlockedError("redirects are not followed")
        if resp.status_code >= 500:
            raise TransientError(f"vendor returned HTTP {resp.status_code}")
        if resp.status_code >= 400:
            raise SchemaDriftError(f"vendor returned HTTP {resp.status_code}")
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise SchemaDriftError("response too large")
        return resp.json()


class HttpTransport:
    """Live transport. Every request re-validates the destination (DNS rebinding) and never
    follows redirects. Constructed only by the runner for live-verified connectors."""

    def __init__(
        self, base_url: str, headers: dict[str, str], resolver: Resolver = _default_resolver, timeout: float = 15.0
    ) -> None:
        self._base_url = base_url
        self._headers = headers
        self._resolver = resolver
        self._timeout = timeout

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        import httpx

        base = await check_egress(self._base_url, self._resolver)
        async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=False, headers=self._headers) as client:
            resp = await client.request(method, f"{base}{path}", **kwargs)
        if resp.status_code in (401, 403):
            raise AuthError(f"vendor returned HTTP {resp.status_code}")
        if resp.status_code == 429:
            raise RateLimitedError(retry_after=float(resp.headers.get("retry-after", "30") or 30))
        if 300 <= resp.status_code < 400:
            raise EgressBlockedError("redirects are not followed")
        if resp.status_code >= 500:
            raise TransientError(f"vendor returned HTTP {resp.status_code}")
        if resp.status_code >= 400:
            raise SchemaDriftError(f"vendor returned HTTP {resp.status_code}")
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise SchemaDriftError("response too large")
        return resp.json()

    async def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self._request("GET", path, params=params)

    async def post_json(self, path: str, body: dict[str, Any]) -> Any:
        return await self._request("POST", path, json=body)
