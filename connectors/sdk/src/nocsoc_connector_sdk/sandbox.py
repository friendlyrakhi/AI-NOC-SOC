"""Deterministic vendor simulators for sandbox mode (docs/06 §6).

A simulator answers the same paths a live vendor API would, with vendor-shaped JSON. Items
are generated on a fixed time grid, so the same (tenant, stream, time slot) always yields the
same item: fetches are reproducible and checkpoints are meaningful. All data is synthetic:
reserved .example domains and documentation IP ranges (RFC 5737) for anything external.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

MAX_WINDOW = timedelta(hours=24)


def seeded(*parts: object) -> random.Random:
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))  # noqa: S311  # nosec B311 - synthetic data only


def iso(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_ts(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 10**11 else value
        return datetime.fromtimestamp(seconds, UTC)
    text = str(value).replace("Z", "+00:00")
    ts = datetime.fromisoformat(text)
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


@dataclass(frozen=True)
class World:
    """A tenant's synthetic estate, shared by every connector of that tenant so that
    different tools describe the same hosts, users and services (enables correlation)."""

    prefix: str
    hosts: list[str]
    windows_hosts: list[str]
    network_devices: list[str]
    databases: list[str]
    cloud_instances: list[str]
    applications: list[str]
    services: list[str]
    users: list[str]
    ips: dict[str, str] = field(default_factory=dict)

    @classmethod
    def for_tenant(cls, tenant_id: str) -> World:
        r = seeded("world", tenant_id)
        prefix = "t" + hashlib.sha256(tenant_id.encode()).hexdigest()[:4]
        hosts = [f"{prefix}-lnx-{i:02d}" for i in range(1, 13)]
        win = [f"{prefix}-win-{i:02d}" for i in range(1, 9)]
        net = [
            f"{prefix}-core-sw-01",
            f"{prefix}-core-sw-02",
            f"{prefix}-dist-sw-01",
            f"{prefix}-fw-01",
            f"{prefix}-rtr-wan-01",
            f"{prefix}-lb-01",
        ]
        dbs = [f"{prefix}-pg-01", f"{prefix}-pg-02", f"{prefix}-mssql-01", f"{prefix}-redis-01"]
        cloud = [f"i-{r.getrandbits(64):016x}"[:19] for _ in range(6)]
        apps = ["payments-api", "customer-portal", "orders-worker", "identity-sso"]
        services = ["Payments", "Customer Portal", "Order Management", "Identity (SSO)"]
        users = ["j.doe", "a.smith", "m.garcia", "s.chen", "svc-backup", "k.novak", "r.ali", "admin.ops"]
        ips = {h: f"10.{r.randint(10, 60)}.{r.randint(0, 255)}.{r.randint(2, 254)}" for h in hosts + win + net + dbs}
        return cls(prefix, hosts, win, net, dbs, cloud, apps, services, users, ips)

    def topology(self) -> list[dict[str, Any]]:
        """The CMDB view of this estate: business services, the hosts that run them and the
        infrastructure they depend on, as (identifier kind, value) pairs. Derived from the fields
        above without new randomness, so existing simulator output is unchanged."""
        h, w, d, p = self.hosts, self.windows_hosts, self.databases, self.prefix
        core1, core2, dist, fw, wan, lb = self.network_devices

        def hn(*names: str) -> list[tuple[str, str]]:
            return [("hostname", n) for n in names]

        return [
            {
                "key": "payments",
                "name": "Payments",
                "tier": 1,
                "team": "Payments Platform",
                "aliases": ["payments-api"],
                "members": hn(*h[0:2]),
                "depends_on": hn(core1, dist, d[1], lb),
            },
            {
                "key": "orders",
                "name": "Order Management",
                "tier": 2,
                "team": "Commerce",
                "aliases": ["orders-worker"],
                "members": hn(*h[2:4]),
                "depends_on": [*hn(core1, dist, d[0]), ("cloud_id", f"{p}-orders-db")],
            },
            {
                "key": "portal",
                "name": "Customer Portal",
                "tier": 1,
                "team": "Digital",
                "aliases": ["customer-portal"],
                "members": hn(*h[4:6]),
                "depends_on": hn(core2, lb, d[3]),
            },
            {
                "key": "sso",
                "name": "Identity (SSO)",
                "tier": 1,
                "team": "Identity",
                "aliases": ["identity-sso", "sso"],
                "members": hn(*h[6:8], "sso"),
                "depends_on": hn(core2, fw),
            },
            {
                "key": "files",
                "name": "File Services",
                "tier": 3,
                "team": "Workplace",
                "aliases": ["file-share"],
                "members": hn(*w[0:1]),
                "depends_on": hn(core2, wan),
            },
        ]


@dataclass(frozen=True)
class GridStream:
    """One simulated list endpoint: an item every ``period`` seconds."""

    path: str
    items_key: str
    period_seconds: int


class Simulator:
    """Base simulator. Subclasses set ``grid`` and implement ``make_item``."""

    grid: ClassVar[dict[str, GridStream]] = {}

    def __init__(self, tenant_id: str, instance_id: str) -> None:
        self.tenant_id = tenant_id
        self.instance_id = instance_id
        self.world = World.for_tenant(tenant_id)
        self.state: dict[str, Any] = {}

    # -- to implement
    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        raise NotImplementedError

    def scenario_items(self, scenario: str, step: int, ts: datetime) -> list[tuple[str, dict[str, Any]]]:
        """Vendor-shaped items for a scenario step: [(stream, item), ...]."""
        return []

    def extra_routes(self) -> dict[str, Any]:
        return {}

    # -- generic grid + pagination
    def items_between(self, stream: str, start: datetime, end: datetime) -> list[dict[str, Any]]:
        g = self.grid[stream]
        start = max(start, end - MAX_WINDOW)
        first = int(start.timestamp()) // g.period_seconds + 1
        last = int(end.timestamp()) // g.period_seconds
        items = []
        for slot in range(first, last + 1):
            ts = datetime.fromtimestamp(slot * g.period_seconds, UTC)
            items.append(self.make_item(stream, ts, seeded(self.tenant_id, stream, slot), slot))
        return items

    def _list_route(self, stream: str):  # type: ignore[no-untyped-def]
        g = self.grid[stream]

        def handler(params: dict[str, Any]) -> dict[str, Any]:
            since = parse_ts(params["since"])
            until = parse_ts(params["until"])
            limit = max(1, min(500, int(params.get("limit", 100))))
            offset = int(params.get("page_token") or 0)
            items = self.items_between(stream, since, until)
            page = items[offset : offset + limit]
            more = offset + limit < len(items)
            return {g.items_key: page, "next_page_token": str(offset + limit) if more else None}

        return handler

    def routes(self) -> dict[str, Any]:
        routes: dict[str, Any] = {g.path: self._list_route(name) for name, g in self.grid.items()}
        routes["/__sandbox/ping"] = lambda _params: {"ok": True}
        routes.update(self.extra_routes())
        return routes
