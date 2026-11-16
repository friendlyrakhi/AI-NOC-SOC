"""Vulnerability (Qualys VMDR, Tenable), ITSM (ServiceNow) and the generic webhook connector."""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any, ClassVar, Literal

from nocsoc_connector_sdk import (
    ActionInvocation,
    ActionResult,
    AlertV1,
    AssetRef,
    AssetV1,
    Connector,
    GridStream,
    NormalizedRecord,
    Paged,
    RawRecord,
    SchemaDriftError,
    ServiceV1,
    Simulator,
    TicketV1,
    VulnFindingV1,
    dig,
    load_manifest,
    parse_ts,
)
from nocsoc_connectors._kit import CORE_SWITCH, KEV, MANIFESTS, at, clip, host_ref, require, stable_int

# Vulnerability IDs are synthetic: CVE-DEMO-… so they can never be mistaken for real CVEs.
VULNS: list[tuple[str, str, float, bool]] = [
    ("Remote code execution in VPN appliance web portal", "CVE-DEMO-2026-1001", 9.8, True),
    ("Privilege escalation in kernel netfilter", "CVE-DEMO-2026-1002", 7.8, False),
    ("OpenSSL denial of service", "CVE-DEMO-2026-1003", 5.9, False),
    ("TLS 1.0 enabled", "CVE-DEMO-2026-1004", 4.3, False),
    ("SMB remote code execution", "CVE-DEMO-2026-1005", 8.8, True),
    ("SQL injection in reporting module", "CVE-DEMO-2026-1006", 8.1, False),
]


def _sev_from_cvss(cvss: float) -> str:
    return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"


# ======================================================================= Qualys VMDR
class QualysSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "detections": GridStream("/api/2.0/fo/asset/host/vm/detection", "detections", 300),
        "hosts": GridStream("/api/2.0/fo/asset/host", "hosts", 600),
    }

    def _det(
        self, host: str, vuln: tuple[str, str, float, bool], ts: datetime, status: str = "Active"
    ) -> dict[str, Any]:
        title, cve, cvss, _kev = vuln
        return {
            "unique_vuln_id": stable_int(host, cve, mod=10**9),
            "qid": 38000 + VULNS.index(vuln),
            "title": title,
            "severity": 5 if cvss >= 9 else 4 if cvss >= 7 else 3 if cvss >= 4 else 2,
            "status": status,
            "first_found_datetime": at(ts, -60 * 24 * 7),
            "last_found_datetime": at(ts),
            "cvss3_base": cvss,
            "cve_ids": [cve],
            "host": {
                "id": stable_int(host, mod=10**7),
                "ip": self.world.ips.get(host, "10.0.0.1"),
                "dns": f"{host}.corp.example",
            },
        }

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        w = self.world
        hosts = w.hosts + w.windows_hosts + w.network_devices
        host = hosts[slot % len(hosts)]
        if stream == "hosts":
            return {
                "id": stable_int(host, mod=10**7),
                "ip": w.ips.get(host, "10.0.0.1"),
                "dns": f"{host}.corp.example",
                "os": "Linux" if "lnx" in host else "Windows",
                "last_scan_datetime": at(ts),
            }
        return self._det(host, rng.choice(VULNS), ts, rng.choice(["New", "Active", "Active", "Fixed"]))

    def scenario_items(self, scenario: str, step: int, ts: datetime) -> list[tuple[str, dict[str, Any]]]:
        if scenario != KEV:
            return []
        return [("detections", self._det(h, VULNS[0], ts, "New")) for h in self.world.network_devices[3:5]]


class QualysVmdr(Connector):
    manifest = load_manifest(MANIFESTS / "qualys.vmdr.yaml")
    simulator_cls = QualysSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "detections": Paged(
            "/api/2.0/fo/asset/host/vm/detection",
            "detections",
            "unique_vuln_id",
            "last_found_datetime",
            "qualys.vm.detection@2",
        ),
        "hosts": Paged("/api/2.0/fo/asset/host", "hosts", "id", "last_scan_datetime", "qualys.asset.host@2"),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        if stream == "hosts":
            require(p, "id", "dns")
            name = str(p["dns"]).split(".")[0]
            return [
                AssetV1(
                    type="host",
                    name=name,
                    # No placeholder IP: a shared fake identifier would merge unrelated hosts.
                    identifiers=[
                        host_ref(name),
                        AssetRef(kind="fqdn", value=p["dns"]),
                        *([AssetRef(kind="ip", value=str(p["ip"]))] if p.get("ip") else []),
                    ],
                    attributes={"os": p.get("os")},
                    observed_at=record.observed_at,
                )
            ]
        require(p, "unique_vuln_id", "title", "severity", "host")
        host = p["host"]
        cves = p.get("cve_ids") or []
        cvss = p.get("cvss3_base")
        kev = any(c == v[1] and v[3] for c in cves for v in VULNS)
        return [
            VulnFindingV1(
                external_id=f"qualys:{p['unique_vuln_id']}",
                vuln_id=cves[0] if cves else f"QID-{p.get('qid')}",
                title=clip(p["title"], 500),
                severity=QualysVmdr.manifest.severity_map.get(str(p["severity"]), "medium"),
                cvss=float(cvss) if cvss is not None else None,
                kev=kev,
                status="fixed" if p.get("status") == "Fixed" else "open",
                asset_refs=[
                    host_ref(str(host.get("dns", "")).split(".")[0]),
                    AssetRef(kind="ip", value=str(host.get("ip", ""))),
                ],
                observed_at=record.observed_at,
            )
        ]


# ======================================================================= Tenable
class TenableSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "findings": GridStream("/vulns/export/chunks", "findings", 300),
        "assets": GridStream("/assets/export/chunks", "assets", 600),
    }

    def _finding(
        self, host: str, vuln: tuple[str, str, float, bool], ts: datetime, state: str = "OPEN"
    ) -> dict[str, Any]:
        title, cve, cvss, _kev = vuln
        return {
            "finding_id": f"{stable_int(host, cve, 'tenable', mod=16**32):032x}",
            "plugin": {
                "id": 150000 + VULNS.index(vuln),
                "name": title,
                "cvss3_base_score": cvss,
                "cve": [cve],
                "epss_score": 0.92 if vuln[3] else 0.04,
            },
            "severity": _sev_from_cvss(cvss),
            "state": state,
            "first_found": at(ts, -60 * 24 * 10),
            "last_found": at(ts),
            "asset": {
                "uuid": f"{stable_int(host, 'asset', mod=16**32):032x}",
                "hostname": host,
                "ipv4": self.world.ips.get(host, "10.0.0.1"),
            },
        }

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        w = self.world
        hosts = w.hosts + w.databases
        host = hosts[slot % len(hosts)]
        if stream == "assets":
            return {
                "id": f"{stable_int(host, 'asset', mod=16**32):032x}",
                "hostnames": [host],
                "ipv4s": [w.ips.get(host, "10.0.0.1")],
                "operating_systems": ["Linux"],
                "updated_at": at(ts),
            }
        return self._finding(host, rng.choice(VULNS), ts, rng.choice(["OPEN", "OPEN", "REOPENED", "FIXED"]))

    def scenario_items(self, scenario: str, step: int, ts: datetime) -> list[tuple[str, dict[str, Any]]]:
        if scenario != KEV:
            return []
        return [("findings", self._finding(h, VULNS[4], ts)) for h in self.world.hosts[:3]]


class Tenable(Connector):
    manifest = load_manifest(MANIFESTS / "tenable.yaml")
    simulator_cls = TenableSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "findings": Paged("/vulns/export/chunks", "findings", "finding_id", "last_found", "tenable.vuln_export@1"),
        "assets": Paged("/assets/export/chunks", "assets", "id", "updated_at", "tenable.asset_export@1"),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        if stream == "assets":
            require(p, "id", "hostnames")
            name = p["hostnames"][0] if p["hostnames"] else p["id"]
            refs = [host_ref(name), *[AssetRef(kind="ip", value=ip) for ip in p.get("ipv4s", [])][:5]]
            return [
                AssetV1(
                    type="host",
                    name=name,
                    identifiers=refs,
                    attributes={"os": (p.get("operating_systems") or [None])[0]},
                    observed_at=record.observed_at,
                )
            ]
        require(p, "finding_id", "plugin", "severity", "asset")
        plugin, asset = p["plugin"], p["asset"]
        if "name" not in plugin:
            raise SchemaDriftError("plugin without name")
        cves = plugin.get("cve") or []
        return [
            VulnFindingV1(
                external_id=f"tenable:{p['finding_id']}",
                vuln_id=cves[0] if cves else f"PLUGIN-{plugin.get('id')}",
                title=clip(plugin["name"], 500),
                severity=Tenable.manifest.severity_map.get(str(p["severity"]), "medium"),
                cvss=plugin.get("cvss3_base_score"),
                epss=plugin.get("epss_score"),
                kev=any(c == v[1] and v[3] for c in cves for v in VULNS),
                status="fixed" if p.get("state") == "FIXED" else "open",
                asset_refs=[
                    host_ref(str(asset.get("hostname", ""))),
                    AssetRef(kind="ip", value=str(asset.get("ipv4", ""))),
                ],
                observed_at=record.observed_at,
            )
        ]


# ======================================================================= ServiceNow ITSM
class ServiceNowSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "incidents": GridStream("/api/now/table/incident", "result", 600),
        "cmdb_servers": GridStream("/api/now/table/cmdb_ci_server", "result", 600),
        "cmdb_services": GridStream("/api/now/table/cmdb_ci_service", "result", 600),
    }

    @staticmethod
    def _sn_time(ts: datetime) -> str:
        return ts.strftime("%Y-%m-%d %H:%M:%S")

    def _incident(self, number: int, desc: str, state: str, priority: str, ci: str, ts: datetime) -> dict[str, Any]:
        return {
            "sys_id": f"{stable_int(number, 'sn', mod=16**32):032x}",
            "number": f"INC{number:07d}",
            "short_description": desc,
            "state": state,
            "priority": priority,
            "cmdb_ci": {"display_value": ci},
            "sys_updated_on": self._sn_time(ts),
        }

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        w = self.world
        if stream == "cmdb_services":
            svc = w.topology()[slot % len(w.topology())]

            def ci(kind: str, value: str, rel: str) -> dict[str, Any]:
                child = {
                    "display_value": value,
                    "sys_class_name": "cmdb_ci_cloud_database" if kind == "cloud_id" else "cmdb_ci",
                }
                if kind == "cloud_id":
                    child["object_id"] = value
                return {"type": rel, "child": child}

            return {
                "sys_id": f"{stable_int(w.prefix, svc['key'], 'svc', mod=16**32):032x}",
                "name": svc["name"],
                "busines_criticality": f"{svc['tier']} - {['most critical', 'somewhat critical', 'less critical', 'not critical'][svc['tier'] - 1]}",
                "owned_by": {"display_value": svc["team"]},
                "u_app_aliases": ",".join(svc["aliases"]),
                "relations": [ci(k, v, "Runs on::Runs") for k, v in svc["members"]]
                + [ci(k, v, "Depends on::Used by") for k, v in svc["depends_on"]],
                "sys_updated_on": self._sn_time(ts),
            }
        if stream == "cmdb_servers":
            host = (w.hosts + w.windows_hosts)[slot % 20]
            return {
                "sys_id": f"{stable_int(host, 'ci', mod=16**32):032x}",
                "name": host,
                "ip_address": w.ips.get(host, "10.0.0.1"),
                "os": "Linux Red Hat" if "lnx" in host else "Windows 2022 Standard",
                "sys_class_name": "cmdb_ci_server",
                "environment": "Production",
                "sys_updated_on": self._sn_time(ts),
            }
        return self._incident(
            10000 + slot % 9000,
            rng.choice(["User cannot access VPN", "Printer offline on floor 3", "Slow application response"]),
            rng.choice(["1", "2", "6"]),
            rng.choice(["3", "4"]),
            rng.choice(w.hosts),
            ts,
        )

    def scenario_items(self, scenario: str, step: int, ts: datetime) -> list[tuple[str, dict[str, Any]]]:
        if scenario != CORE_SWITCH:
            return []
        return [
            (
                "incidents",
                self._incident(
                    99001,
                    "Multiple users report payments failing (core network)",
                    "1",
                    "1",
                    self.world.network_devices[0],
                    ts,
                ),
            )
        ]

    def extra_routes(self) -> dict[str, Any]:
        return {
            "/api/now/table/incident/create": lambda body: {"result": {"number": "INC0099999", "state": "1"}},
            "/api/now/table/incident/update": lambda body: {"result": {"state": body.get("state", "2")}},
            "/api/now/table/change_request/create": lambda body: {"result": {"number": "CHG0099999"}},
        }


SN_STATE = {"1": "new", "2": "in_progress", "3": "on_hold", "6": "resolved", "7": "closed", "8": "canceled"}


class ServiceNowItsm(Connector):
    manifest = load_manifest(MANIFESTS / "servicenow.itsm.yaml")
    simulator_cls = ServiceNowSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "incidents": Paged("/api/now/table/incident", "result", "sys_id", "sys_updated_on", "servicenow.incident@1"),
        "cmdb_servers": Paged(
            "/api/now/table/cmdb_ci_server", "result", "sys_id", "sys_updated_on", "servicenow.cmdb_ci_server@1"
        ),
        "cmdb_services": Paged(
            "/api/now/table/cmdb_ci_service", "result", "sys_id", "sys_updated_on", "servicenow.cmdb_ci_service@1"
        ),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        if stream == "cmdb_services":
            require(p, "sys_id", "name", "relations")
            members: list[AssetRef] = []
            depends: list[AssetRef] = []
            for rel in p["relations"]:
                child = rel.get("child") or {}
                value = child.get("object_id") or child.get("display_value")
                if not value:
                    continue
                ref = AssetRef(kind="cloud_id", value=value) if child.get("object_id") else host_ref(value)
                (members if str(rel.get("type", "")).startswith("Runs on") else depends).append(ref)
            tier_text = str(p.get("busines_criticality", "3"))[:1]
            return [
                ServiceV1(
                    external_id=p["sys_id"],
                    name=clip(p["name"], 200),
                    tier=int(tier_text) if tier_text in "1234" else 3,
                    owner_team=(p.get("owned_by") or {}).get("display_value"),
                    aliases=[a.strip() for a in str(p.get("u_app_aliases", "")).split(",") if a.strip()][:20],
                    members=members[:200],
                    depends_on=depends[:100],
                    observed_at=record.observed_at,
                )
            ]
        if stream == "cmdb_servers":
            require(p, "sys_id", "name")
            refs = [host_ref(p["name"])] + ([AssetRef(kind="ip", value=p["ip_address"])] if p.get("ip_address") else [])
            environments: dict[str, Literal["prod", "stage", "dev"]] = {
                "Production": "prod",
                "Staging": "stage",
                "Development": "dev",
            }
            env: Literal["prod", "stage", "dev", "unknown"] = environments.get(p.get("environment", "")) or "unknown"
            return [
                AssetV1(
                    type="host",
                    name=p["name"],
                    identifiers=refs,
                    environment=env,
                    attributes={"os": p.get("os"), "cmdb_class": p.get("sys_class_name")},
                    observed_at=record.observed_at,
                )
            ]
        require(p, "sys_id", "number", "state", "short_description")
        return [
            TicketV1(
                external_id=p["sys_id"],
                number=p["number"],
                state=SN_STATE.get(str(p["state"]), str(p["state"])),
                short_description=clip(p["short_description"], 500),
                observed_at=record.observed_at,
            )
        ]

    def simulate_action(self, invocation: ActionInvocation) -> ActionResult:
        """Sandbox ITSM: a created ticket gets a stable sys_id and number derived from the platform
        reference, so repeated simulations agree and inbound echoes can be matched."""
        if invocation.key == "itsm.create_incident":
            ref = str(invocation.target.get("ref", ""))
            n = 9_000_000 + stable_int(self.ctx.tenant_id, ref, "sn-create", mod=999_999)
            after = {
                "sys_id": f"{stable_int(self.ctx.tenant_id, ref, 'sn-sys', mod=16**32):032x}",
                "number": f"INC{n:07d}",
                "state": "1",
            }
            return ActionResult(
                status="succeeded",
                mode="simulate",
                simulated=True,
                after=after,
                message=f"Simulated ServiceNow {after['number']}",
            )
        if invocation.key == "itsm.update_incident":
            after = {
                "sys_id": str(invocation.target.get("sys_id", "")),
                "state": str(invocation.params.get("state", "2")),
            }
            return ActionResult(
                status="succeeded", mode="simulate", simulated=True, after=after, message="Simulated ServiceNow update"
            )
        return super().simulate_action(invocation)

    def parse_webhook(self, body: dict[str, Any]) -> list[tuple[str, RawRecord]]:
        require(body, "sys_id", "number")
        return [("incidents", self._raw(self.streams["incidents"], body, self.ctx.clock()))]


# ======================================================================= Generic webhook
class GenericWebhookSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {}

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        raise NotImplementedError


class GenericWebhook(Connector):
    """Maps arbitrary JSON to the canonical alert shape with configurable dotted paths."""

    manifest = load_manifest(MANIFESTS / "generic.webhook.yaml")
    simulator_cls = GenericWebhookSimulator
    streams: ClassVar[dict[str, Paged]] = {}
    CANONICAL = Paged("", "", "id", "time", "generic.canonical_alert@1")

    def parse_webhook(self, body: dict[str, Any]) -> list[tuple[str, RawRecord]]:
        c = {
            "id_path": "id",
            "title_path": "title",
            "severity_path": "severity",
            "host_path": "host",
            "time_path": "time",
            "domain": "noc",
            **self.config,
        }
        title = dig(body, c["title_path"])
        if not title:
            raise SchemaDriftError(f"no value at {c['title_path']}")
        sid = dig(body, c["id_path"]) or f"gen-{stable_int(sorted(map(str, body.items())))}"
        item = {
            "id": str(sid),
            "title": clip(title, 500),
            "severity": str(dig(body, c["severity_path"]) or "medium").lower(),
            "host": dig(body, c["host_path"]),
            "time": dig(body, c["time_path"]) or at(self.ctx.clock()),
            "domain": c["domain"],
        }
        return [("webhook", self._raw(self.CANONICAL, item, self.ctx.clock()))]

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        require(p, "id", "title", "severity", "domain")
        return [
            AlertV1(
                domain=p["domain"],
                source_alert_id=str(p["id"]),
                title=clip(p["title"], 500),
                severity=GenericWebhook.manifest.severity_map.get(p["severity"], "medium"),
                category="webhook",
                observed_at=parse_ts(p["time"]) if p.get("time") else record.observed_at,
                asset_refs=[host_ref(str(p["host"]))] if p.get("host") else [],
                dedup_key=f"generic:{p['id']}",
            )
        ]
