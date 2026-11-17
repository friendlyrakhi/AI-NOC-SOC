"""Observability connectors: SolarWinds Orion, Datadog, Prometheus/Alertmanager, Grafana."""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any, ClassVar

from nocsoc_connector_sdk import (
    AlertV1,
    AssetRef,
    AssetV1,
    Checkpoint,
    ConfigError,
    Connector,
    FetchBudget,
    FetchResult,
    GridStream,
    MetricPointV1,
    NormalizedRecord,
    Paged,
    RawRecord,
    SchemaDriftError,
    Simulator,
    iso,
    load_manifest,
    parse_ts,
)
from nocsoc_connectors._kit import (
    CORE_SWITCH,
    DB_SATURATION,
    MANIFESTS,
    NOISE,
    RANSOMWARE,
    at,
    clip,
    host_ref,
    ip_ref,
    require,
    stable_int,
)


# ======================================================================= SolarWinds Orion
class SolarWindsSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "alerts": GridStream("/SolarWinds/InformationService/v3/Json/Query/Orion.AlertActive", "results", 240),
        "nodes": GridStream("/SolarWinds/InformationService/v3/Json/Query/Orion.Nodes", "results", 300),
    }
    PROBLEMS: ClassVar[list[tuple[str, int, str]]] = [
        ("Interface utilization above 85%", 1, "Orion.NPM.Interfaces"),
        ("Node response time high", 1, "Orion.Nodes"),
        ("High CPU load", 3, "Orion.Nodes"),
        ("Interface errors and discards", 4, "Orion.NPM.Interfaces"),
        ("Node is down", 2, "Orion.Nodes"),
    ]

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        w = self.world
        devices = w.network_devices + w.hosts[:4]
        if stream == "nodes":
            name = devices[slot % len(devices)]
            return {
                "NodeID": 1000 + devices.index(name),
                "Caption": name,
                "IPAddress": w.ips.get(name, "10.0.0.1"),
                "MachineType": "Cisco Catalyst 9300"
                if "sw" in name
                else "Fortinet FortiGate"
                if "fw" in name
                else "Linux",
                "Vendor": "Cisco" if "sw" in name or "rtr" in name else "Fortinet" if "fw" in name else "Net-SNMP",
                "Status": 1,
                "LastSystemUpTimePollUtc": at(ts),
            }
        name = rng.choice(devices[:6])
        title, sev, entity = rng.choice(self.PROBLEMS[:4])
        return self._alert(name, title, sev, entity, ts, slot)

    def _alert(self, node: str, title: str, sev: int, entity: str, ts: datetime, slot: int) -> dict[str, Any]:
        return {
            "AlertActiveID": slot,
            "AlertObjectID": stable_int(node, title, mod=100_000),
            "Name": title,
            "Severity": sev,
            "TriggeredDateTime": at(ts),
            "TriggeredMessage": f"{title} on {node}",
            "EntityCaption": node,
            "EntityType": entity,
            "IPAddress": self.world.ips.get(node, "10.0.0.1"),
            "Acknowledged": False,
        }

    def scenario_items(self, scenario: str, step: int, ts: datetime) -> list[tuple[str, dict[str, Any]]]:
        if scenario != CORE_SWITCH:
            return []
        core = self.world.network_devices[0]
        return [
            ("alerts", self._alert(core, "Node is down", 2, "Orion.Nodes", ts, 900_000_001)),
            ("alerts", self._alert(core, "Interface Gi1/0/48 down", 1, "Orion.NPM.Interfaces", ts, 900_000_002)),
            (
                "alerts",
                self._alert(self.world.network_devices[2], "BGP neighbor down", 2, "Orion.Nodes", ts, 900_000_003),
            ),
        ]


class SolarWindsOrion(Connector):
    manifest = load_manifest(MANIFESTS / "solarwinds.orion.yaml")
    simulator_cls = SolarWindsSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "alerts": Paged(
            SolarWindsSimulator.grid["alerts"].path,
            "results",
            "AlertActiveID",
            "TriggeredDateTime",
            "solarwinds.alert_active@1",
        ),
        "nodes": Paged(
            SolarWindsSimulator.grid["nodes"].path, "results", "NodeID", "LastSystemUpTimePollUtc", "solarwinds.node@1"
        ),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        if stream == "nodes":
            require(p, "NodeID", "Caption", "IPAddress")
            is_net = p.get("Vendor") in {"Cisco", "Fortinet", "Juniper", "Arista"}
            return [
                AssetV1(
                    type="network_device" if is_net else "host",
                    name=str(p["Caption"]),
                    identifiers=[host_ref(str(p["Caption"])), ip_ref(str(p["IPAddress"]))],
                    attributes={"vendor": p.get("Vendor"), "model": p.get("MachineType"), "orion_node_id": p["NodeID"]},
                    observed_at=record.observed_at,
                )
            ]
        require(p, "AlertObjectID", "Name", "Severity", "EntityCaption")
        sev = SolarWindsOrion.manifest.severity_map.get(str(p["Severity"]), "medium")
        return [
            AlertV1(
                domain="noc",
                source_alert_id=str(p.get("AlertActiveID")),
                title=clip(p["Name"], 500),
                description=clip(p.get("TriggeredMessage"), 8000),
                severity=sev,
                category="network"
                if "NPM" in str(p.get("EntityType")) or "BGP" in str(p["Name"])
                else "infrastructure",
                observed_at=record.observed_at,
                asset_refs=[host_ref(str(p["EntityCaption"])), ip_ref(str(p.get("IPAddress", "")))]
                if p.get("IPAddress")
                else [host_ref(str(p["EntityCaption"]))],
                labels={"entity_type": str(p.get("EntityType", ""))},
                dedup_key=f"solarwinds:{p['EntityCaption']}:{p['Name']}",
            )
        ]


# ======================================================================= Datadog
class DatadogSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "events": GridStream("/api/v1/events", "events", 180),
        "hosts": GridStream("/api/v1/hosts", "host_list", 300),
        "metrics": GridStream("/api/v1/query", "series", 120),
    }
    MONITORS: ClassVar[list[tuple[str, str, int]]] = [
        ("[P2] p95 latency above SLO on {app}", "error", 2101),
        ("[P3] Error rate above 1% on {app}", "warning", 2102),
        ("[P3] Disk usage above 85% on {host}", "warning", 2103),
        ("[P1] Service check failing on {host}", "error", 2104),
    ]

    def _event(
        self, title: str, alert_type: str, monitor_id: int, host: str, ts: datetime, eid: int, tags: list[str]
    ) -> dict[str, Any]:
        return {
            "id": eid,
            "title": title,
            "text": f"%%% \n{title}\n %%%",
            "date_happened": int(ts.timestamp()),
            "alert_type": alert_type,
            "priority": "normal",
            "host": host,
            "tags": tags,
            "monitor_id": monitor_id,
            "source_type_name": "Monitor Alert",
        }

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        w = self.world
        if stream == "hosts":
            host = w.hosts[slot % len(w.hosts)]
            return {
                "id": 5000 + w.hosts.index(host),
                "name": host,
                "host_name": host,
                "apps": ["agent", "nginx"],
                "sources": ["agent"],
                "up": True,
                "last_reported_time": int(ts.timestamp()),
                "meta": {"platform": "linux"},
            }
        if stream == "metrics":
            host = w.hosts[slot % len(w.hosts)]
            return {
                "id": f"m-{slot}",
                "metric": "system.cpu.user",
                "scope": f"host:{host}",
                "host": host,
                "ts": int(ts.timestamp()),
                "value": round(rng.uniform(5, 85), 2),
                "unit": "percent",
            }
        title, alert_type, mid = rng.choice(self.MONITORS)
        app, host = rng.choice(w.applications), rng.choice(w.hosts[:6])
        if rng.random() < 0.25:
            alert_type = "success"
        return self._event(
            title.format(app=app, host=host), alert_type, mid, host, ts, slot, [f"service:{app}", "env:prod"]
        )

    def scenario_items(self, scenario: str, step: int, ts: datetime) -> list[tuple[str, dict[str, Any]]]:
        w = self.world
        if scenario == CORE_SWITCH:
            return [
                (
                    "events",
                    self._event(
                        "[P1] Error rate above 5% on payments-api",
                        "error",
                        2199,
                        w.hosts[0],
                        ts,
                        910_000_001,
                        ["service:payments-api", "env:prod"],
                    ),
                )
            ]
        if scenario == DB_SATURATION:
            return [
                (
                    "events",
                    self._event(
                        "[P2] p95 latency above SLO on orders-worker",
                        "error",
                        2198,
                        w.hosts[2],
                        ts,
                        910_000_002,
                        ["service:orders-worker", "env:prod"],
                    ),
                )
            ]
        if scenario == RANSOMWARE:
            return [
                (
                    "events",
                    self._event(
                        "[P1] File share latency above 2 s on fileserver",
                        "error",
                        2197,
                        w.windows_hosts[0],
                        ts,
                        910_000_003,
                        ["service:file-share", "env:prod"],
                    ),
                )
            ]
        if scenario == NOISE:
            return [
                (
                    "events",
                    self._event(
                        "[P3] Disk usage above 85% on " + w.hosts[5],
                        "warning",
                        2103,
                        w.hosts[5],
                        ts,
                        910_000_100 + i,
                        ["env:prod"],
                    ),
                )
                for i in range(6)
            ]
        return []

    def extra_routes(self) -> dict[str, Any]:
        return {"/api/v1/monitor/mute": lambda body: {"muted": True, "monitor_id": body.get("monitor_id")}}


class Datadog(Connector):
    manifest = load_manifest(MANIFESTS / "datadog.yaml")
    simulator_cls = DatadogSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "events": Paged("/api/v1/events", "events", "id", "date_happened", "datadog.event@1"),
        "hosts": Paged("/api/v1/hosts", "host_list", "id", "last_reported_time", "datadog.host@1"),
        "metrics": Paged("/api/v1/query", "series", "id", "ts", "datadog.metric_point@1"),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        if stream == "hosts":
            require(p, "host_name")
            return [
                AssetV1(
                    type="host",
                    name=p["host_name"],
                    identifiers=[host_ref(p["host_name"])],
                    attributes={"datadog_apps": p.get("apps", [])},
                    observed_at=record.observed_at,
                )
            ]
        if stream == "metrics":
            require(p, "metric", "host", "value")
            return [
                MetricPointV1(
                    name=p["metric"],
                    value=float(p["value"]),
                    unit=str(p.get("unit", "")),
                    asset_ref=host_ref(p["host"]),
                    observed_at=record.observed_at,
                )
            ]
        require(p, "title", "alert_type", "monitor_id")
        if p["alert_type"] == "info":
            return []
        tags = {t.split(":", 1)[0]: t.split(":", 1)[1] for t in p.get("tags", []) if ":" in t}
        return [
            AlertV1(
                domain="noc",
                source_alert_id=str(p.get("id")),
                title=clip(p["title"], 500),
                description=clip(p.get("text"), 8000),
                severity=Datadog.manifest.severity_map[p["alert_type"]] if p["alert_type"] != "success" else "info",
                status="resolved" if p["alert_type"] == "success" else "new",
                category="application",
                observed_at=record.observed_at,
                asset_refs=[host_ref(p["host"])] if p.get("host") else [],
                service_hint=tags.get("service"),
                labels={k: v for k, v in tags.items() if k in {"service", "env"}},
                dedup_key=f"datadog:monitor:{p['monitor_id']}:{p.get('host', '')}",
            )
        ]

    def parse_webhook(self, body: dict[str, Any]) -> list[tuple[str, RawRecord]]:
        """Datadog webhook integration payload (custom template mirroring the event fields)."""
        require(body, "id", "title", "alert_type")
        return [("events", self._raw(self.streams["events"], body, self.ctx.clock()))]


# ======================================================================= Prometheus / Alertmanager
def _am_alert(
    name: str, instance: str, severity: str, summary: str, starts: datetime, extra: dict[str, str] | None = None
) -> dict[str, Any]:
    labels = {"alertname": name, "instance": instance, "job": "node", "severity": severity, **(extra or {})}
    fingerprint = format(stable_int(*sorted(labels.items()), mod=16**16), "016x")
    return {
        "fingerprint": fingerprint,
        "labels": labels,
        "annotations": {"summary": summary, "description": summary},
        "startsAt": at(starts),
        "endsAt": "0001-01-01T00:00:00Z",
        "status": {"state": "active", "silencedBy": [], "inhibitedBy": []},
    }


class PrometheusSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "alerts": GridStream("/api/v2/alerts", "data", 180),
        "metrics": GridStream("/api/v1/query_range", "result", 120),
    }
    RULES: ClassVar[list[tuple[str, str, str]]] = [
        ("NodeFilesystemAlmostFull", "warning", "Filesystem /var on {i} has less than 10% space"),
        ("NodeHighLoad", "warning", "Load average on {i} above 2x CPU count"),
        ("TargetDown", "critical", "Scrape target {i} is down"),
        ("NodeMemoryPressure", "warning", "Memory available on {i} below 5%"),
    ]

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        w = self.world
        host = rng.choice(w.hosts[:8])
        if stream == "metrics":
            return {
                "id": f"p-{slot}",
                "metric": {"__name__": "node_load1", "instance": f"{host}:9100"},
                "ts": int(ts.timestamp()),
                "value": round(rng.uniform(0.1, 6), 2),
            }
        name, sev, summary = rng.choice(self.RULES)
        return _am_alert(name, f"{host}:9100", sev, summary.format(i=host), ts)

    def scenario_items(self, scenario: str, step: int, ts: datetime) -> list[tuple[str, dict[str, Any]]]:
        w = self.world
        if scenario == CORE_SWITCH:
            return [
                (
                    "alerts",
                    _am_alert(
                        "TargetDown", f"{h}:9100", "critical", f"Scrape target {h} is down", ts, {"zone": "dc1-row-a"}
                    ),
                )
                for h in w.hosts[:4]
            ]
        if scenario == DB_SATURATION:
            db = w.databases[0]
            return [
                (
                    "alerts",
                    _am_alert(
                        "PostgresTooManyConnections",
                        f"{db}:9187",
                        "critical",
                        f"{db} is using 96% of max_connections",
                        ts,
                        {"job": "postgres"},
                    ),
                )
            ]
        if scenario == NOISE:
            # The same alert flapping: identical fingerprint, must de-duplicate.
            return [
                (
                    "alerts",
                    _am_alert(
                        "NodeHighLoad",
                        f"{w.hosts[6]}:9100",
                        "warning",
                        f"Load average on {w.hosts[6]} above 2x CPU count",
                        ts,
                    ),
                )
                for _ in range(8)
            ]
        return []

    def extra_routes(self) -> dict[str, Any]:
        return {"/api/v2/silences": lambda body: {"silenceID": "sandbox-silence", "matchers": body.get("matchers", [])}}


def _normalize_am(
    p: dict[str, Any], observed: datetime, source: str, severity_map: dict[str, Any]
) -> list[NormalizedRecord]:
    require(p, "fingerprint", "labels", "startsAt")
    labels = p["labels"]
    if "alertname" not in labels:
        raise SchemaDriftError("alert without alertname label")
    instance = str(labels.get("instance", "")).split(":")[0]
    ann = p.get("annotations", {})
    state = (p.get("status") or {}).get("state", "active")
    return [
        AlertV1(
            domain="noc",
            source_alert_id=str(p["fingerprint"]),
            title=clip(f"{labels['alertname']}: {ann.get('summary', '')}".rstrip(": "), 500),
            description=clip(ann.get("description"), 8000),
            severity=severity_map.get(str(labels.get("severity", "warning")), "medium"),
            status="new" if state in ("active", "firing") else "resolved",
            category="infrastructure",
            observed_at=parse_ts(p["startsAt"]) if p.get("startsAt") else observed,
            asset_refs=[host_ref(instance)] if instance else [],
            labels={k: str(v) for k, v in labels.items() if k in {"job", "severity", "zone", "grafana_folder"}},
            dedup_key=f"{source}:{p['fingerprint']}",
        )
    ]


class Prometheus(Connector):
    manifest = load_manifest(MANIFESTS / "prometheus.yaml")
    simulator_cls = PrometheusSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "alerts": Paged("/api/v2/alerts", "data", "fingerprint", "startsAt", "alertmanager.alert@2"),
        "metrics": Paged("/api/v1/query_range", "result", "id", "ts", "prometheus.sample@1"),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        if stream == "metrics":
            require(p, "metric", "value")
            inst = str(p["metric"].get("instance", "")).split(":")[0]
            return [
                MetricPointV1(
                    name=str(p["metric"].get("__name__", "unknown")),
                    value=float(p["value"]),
                    asset_ref=host_ref(inst or "unknown"),
                    observed_at=record.observed_at,
                )
            ]
        return _normalize_am(p, record.observed_at, "prometheus", Prometheus.manifest.severity_map)

    async def fetch_live(self, stream: str, checkpoint: Checkpoint | None, budget: FetchBudget) -> FetchResult:
        """Real APIs (P8, ADR-0019), read-only:
        - alerts: Alertmanager ``GET /api/v2/alerts`` (active, not silenced or inhibited). It returns a
          JSON array of alert objects; the same shape the simulator produces. Pulls are idempotent:
          the ingest ledger keys pulled records by fingerprint and start time.
        - metrics: Prometheus ``GET /api/v1/query`` (instant vector, default query ``up``). Each series
          becomes one sample: ``{"metric": labels, "ts": seconds, "value": float}``.
        """
        if self.http is None:
            raise ConfigError("live mode requires the runner's live HTTP client")
        now = self.ctx.clock()
        records: list[RawRecord] = []
        if stream == "alerts":
            data = await self.http.get_json(
                self.live_url("alertmanager_url"),
                "/api/v2/alerts",
                {"active": "true", "silenced": "false", "inhibited": "false"},
            )
            if not isinstance(data, list):
                raise SchemaDriftError("alertmanager /api/v2/alerts: expected a JSON array")
            records = [self._raw(self.streams["alerts"], item, now) for item in data[: budget.max_records]]
        elif stream == "metrics":
            query = str(self.config.get("metrics_query") or "up")
            data = await self.http.get_json(self.live_url("prometheus_url"), "/api/v1/query", {"query": query})
            if not isinstance(data, dict) or data.get("status") != "success":
                raise SchemaDriftError("prometheus /api/v1/query: unexpected response")
            result = (data.get("data") or {}).get("result")
            if not isinstance(result, list):
                raise SchemaDriftError("prometheus /api/v1/query: missing data.result")
            for series in result[: budget.max_records]:
                try:
                    ts, value = series["value"]
                    labels = dict(series.get("metric") or {})
                    item = {
                        "id": f"{stable_int(*sorted(labels.items()), mod=16**12):012x}-{int(float(ts))}",
                        "metric": labels,
                        "ts": int(float(ts)),
                        "value": float(value),
                    }
                except (KeyError, TypeError, ValueError) as exc:
                    raise SchemaDriftError("prometheus: malformed sample") from exc
                records.append(self._raw(self.streams["metrics"], item, now))
        else:
            raise ConfigError(f"unknown stream {stream}")
        return FetchResult(records=records, checkpoint=Checkpoint(cursor={"last_pull": iso(now)}), has_more=False)

    def parse_webhook(self, body: dict[str, Any]) -> list[tuple[str, RawRecord]]:
        """Alertmanager webhook_config payload: {"version": "4", "alerts": [...]}."""
        require(body, "alerts")
        out = []
        for a in body["alerts"]:
            item = {**a, "status": {"state": "active" if a.get("status") == "firing" else "resolved"}}
            out.append(("alerts", self._raw(self.streams["alerts"], item, self.ctx.clock())))
        return out


# ======================================================================= Grafana
class GrafanaSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "alert_instances": GridStream("/api/alertmanager/grafana/api/v2/alerts", "data", 300)
    }

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        app = rng.choice(self.world.applications)
        name, sev = rng.choice(
            [("HighRequestLatency", "warning"), ("ErrorBudgetBurnFast", "critical"), ("PodRestartLoop", "warning")]
        )
        return _am_alert(name, app, sev, f"{name} for {app}", ts, {"grafana_folder": "Production SLOs"})

    def extra_routes(self) -> dict[str, Any]:
        return {
            "/api/alertmanager/grafana/api/v2/silences": lambda body: {"silenceID": "sandbox"},
            "/api/annotations": lambda body: {"id": 1, "message": "Annotation added"},
        }


class Grafana(Connector):
    manifest = load_manifest(MANIFESTS / "grafana.yaml")
    simulator_cls = GrafanaSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "alert_instances": Paged(
            "/api/alertmanager/grafana/api/v2/alerts", "data", "fingerprint", "startsAt", "grafana.alert_instance@1"
        ),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        out = _normalize_am(record.payload, record.observed_at, "grafana", Grafana.manifest.severity_map)
        # Grafana instances are services, not hosts.
        return [
            a.model_copy(update={"asset_refs": [], "service_hint": a.asset_refs[0].value if a.asset_refs else None})
            if isinstance(a, AlertV1)
            else a
            for a in out
        ]

    def parse_webhook(self, body: dict[str, Any]) -> list[tuple[str, RawRecord]]:
        require(body, "alerts")
        out = []
        for a in body["alerts"]:
            item = {**a, "status": {"state": "active" if a.get("status") == "firing" else "resolved"}}
            out.append(("alert_instances", self._raw(self.streams["alert_instances"], item, self.ctx.clock())))
        return out


__all__ = ["AssetRef", "Datadog", "Grafana", "Prometheus", "SolarWindsOrion"]
