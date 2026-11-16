"""Security connectors: Microsoft Sentinel, Splunk, Wazuh, CrowdStrike Falcon, Microsoft Defender."""

from __future__ import annotations

import random
import re
from datetime import datetime
from typing import Any, ClassVar

from nocsoc_connector_sdk import (
    AlertV1,
    AssetRef,
    AssetV1,
    Connector,
    GridStream,
    NormalizedRecord,
    Observable,
    Paged,
    RawRecord,
    SchemaDriftError,
    SecurityEventV1,
    Simulator,
    load_manifest,
)
from nocsoc_connectors._kit import (
    INJECTION,
    INJECTION_TEXT,
    MANIFESTS,
    PHISHING,
    RANSOMWARE,
    at,
    clip,
    host_ref,
    require,
    stable_int,
)

TECHNIQUE = r"^T\d{4}(\.\d{3})?$"


def _techniques(values: Any) -> list[str]:
    out = []
    for v in values or []:
        tid = str(v).split(" ")[0].upper()
        if re.match(TECHNIQUE, tid) and tid not in out:
            out.append(tid)
    return out[:20]


def _doc_ip(rng: random.Random) -> str:
    return f"{rng.choice(['198.51.100', '203.0.113', '192.0.2'])}.{rng.randint(1, 254)}"


# ======================================================================= Microsoft Sentinel
class SentinelSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "incidents": GridStream("/providers/Microsoft.SecurityInsights/incidents", "value", 300)
    }
    TITLES: ClassVar[list[tuple[str, str, list[str], list[str]]]] = [
        ("Sign-in from an unfamiliar location", "Medium", ["InitialAccess"], ["T1078"]),
        ("Password spray against multiple accounts", "Medium", ["CredentialAccess"], ["T1110"]),
        ("Suspicious inbox forwarding rule", "Low", ["Collection"], ["T1114"]),
        ("Privileged role assigned outside change window", "High", ["Persistence"], ["T1098"]),
    ]

    def _incident(
        self,
        title: str,
        sev: str,
        tactics: list[str],
        techniques: list[str],
        user: str,
        ts: datetime,
        num: int,
        description: str = "",
    ) -> dict[str, Any]:
        return {
            "id": f"/subscriptions/x/providers/Microsoft.SecurityInsights/incidents/{num:08d}-0000-4000-8000-{num:012d}",
            "name": f"{num:08d}-0000-4000-8000-{num:012d}",
            "properties": {
                "title": title,
                "description": description or f"{title} for {user}",
                "severity": sev,
                "status": "New",
                "incidentNumber": num,
                "createdTimeUtc": at(ts),
                "additionalData": {
                    "alertsCount": 1,
                    "tactics": tactics,
                    "techniques": techniques,
                    "alertProductNames": ["Azure Active Directory Identity Protection"],
                },
                "relatedEntities": [
                    {"kind": "Account", "properties": {"accountName": user, "upnSuffix": "corp.example"}}
                ],
            },
        }

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        title, sev, tactics, tech = rng.choice(self.TITLES)
        return self._incident(title, sev, tactics, tech, rng.choice(self.world.users), ts, slot % 10_000_000)

    def scenario_items(self, scenario: str, step: int, ts: datetime) -> list[tuple[str, dict[str, Any]]]:
        u = self.world.users[0]
        if scenario == PHISHING:
            return [
                (
                    "incidents",
                    self._incident(
                        "Phishing link clicked followed by suspicious sign-in",
                        "High",
                        ["InitialAccess"],
                        ["T1566", "T1078"],
                        u,
                        ts,
                        99_000_001,
                    ),
                ),
                (
                    "incidents",
                    self._incident(
                        "MFA fatigue: repeated push requests",
                        "High",
                        ["CredentialAccess"],
                        ["T1621"],
                        u,
                        ts,
                        99_000_002,
                    ),
                ),
            ]
        if scenario == INJECTION:
            return [
                (
                    "incidents",
                    self._incident(
                        INJECTION_TEXT[0][:120],
                        "Medium",
                        ["Discovery"],
                        ["T1087"],
                        u,
                        ts,
                        99_000_003,
                        INJECTION_TEXT[1],
                    ),
                )
            ]
        return []

    def extra_routes(self) -> dict[str, Any]:
        return {
            "/providers/Microsoft.SecurityInsights/incidents/update": lambda body: {
                "properties": {"status": body.get("status", "Active")}
            }
        }


class MicrosoftSentinel(Connector):
    manifest = load_manifest(MANIFESTS / "microsoft.sentinel.yaml")
    simulator_cls = SentinelSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "incidents": Paged(
            "/providers/Microsoft.SecurityInsights/incidents",
            "value",
            "name",
            "properties.createdTimeUtc",
            "microsoft.sentinel.incident@2023-11",
        ),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        require(p, "name", "properties")
        props = p["properties"]
        if not isinstance(props, dict) or "title" not in props or "severity" not in props:
            raise SchemaDriftError("incident without title/severity")
        add = props.get("additionalData") or {}
        users = [
            e["properties"]["accountName"]
            for e in props.get("relatedEntities", [])
            if e.get("kind") == "Account" and "accountName" in e.get("properties", {})
        ]
        return [
            AlertV1(
                domain="soc",
                source_alert_id=str(p["name"]),
                title=clip(props["title"], 500),
                description=clip(props.get("description"), 8000),
                severity=MicrosoftSentinel.manifest.severity_map.get(props["severity"], "medium"),
                status="resolved" if props.get("status") == "Closed" else "new",
                category=", ".join(add.get("tactics", []))[:100],
                observed_at=record.observed_at,
                asset_refs=[AssetRef(kind="upn", value=f"{u}@corp.example") for u in users][:5],
                observables=[Observable(type="user", value=u) for u in users][:10],
                mitre_techniques=_techniques(add.get("techniques")),
                labels={"incident_number": str(props.get("incidentNumber", ""))},
                dedup_key=f"sentinel:incident:{p['name']}",
            )
        ]


# ======================================================================= Splunk
class SplunkSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "notables": GridStream("/services/search/v2/jobs/export/notable", "results", 300),
        "auth_events": GridStream("/services/search/v2/jobs/export/authentication", "results", 60),
    }

    def _notable(
        self,
        rule: str,
        urgency: str,
        user: str,
        src: str,
        dest: str,
        ts: datetime,
        eid: str,
        technique: str,
        description: str = "",
    ) -> dict[str, Any]:
        return {
            "event_id": eid,
            "rule_name": rule,
            "rule_description": description or rule,
            "urgency": urgency,
            "security_domain": "access" if technique in ("T1078", "T1110") else "endpoint",
            "_time": int(ts.timestamp()),
            "src": src,
            "dest": dest,
            "user": user,
            "status_label": "New",
            "annotations.mitre_attack": [technique],
        }

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        w = self.world
        if stream == "auth_events":
            ok = rng.random() > 0.2
            return {
                "event_id": f"auth-{slot}",
                "_time": int(ts.timestamp()),
                "action": "success" if ok else "failure",
                "app": rng.choice(["vpn", "sso", "rdp"]),
                "user": rng.choice(w.users),
                "src": _doc_ip(rng) if rng.random() < 0.3 else w.ips[w.windows_hosts[slot % 8]],
                "dest": rng.choice(w.hosts[:4]),
            }
        rule, urgency, tech = rng.choice(
            [
                ("Excessive Failed Logins", "medium", "T1110"),
                ("Brute Force Access Behavior Detected", "high", "T1110"),
                ("Geographically Improbable Access", "medium", "T1078"),
                ("Suspicious Command-Line Arguments", "high", "T1059"),
            ]
        )
        return self._notable(
            rule, urgency, rng.choice(w.users), _doc_ip(rng), rng.choice(w.windows_hosts), ts, f"notable-{slot}", tech
        )

    def scenario_items(self, scenario: str, step: int, ts: datetime) -> list[tuple[str, dict[str, Any]]]:
        w = self.world
        if scenario == PHISHING:
            return [
                (
                    "notables",
                    self._notable(
                        "Geographically Improbable Access",
                        "high",
                        w.users[0],
                        "203.0.113.77",
                        "sso",
                        ts,
                        "notable-scn-phish-1",
                        "T1078",
                    ),
                )
            ]
        if scenario == INJECTION:
            return [
                (
                    "notables",
                    self._notable(
                        INJECTION_TEXT[2][:100],
                        "medium",
                        w.users[3],
                        "198.51.100.9",
                        w.windows_hosts[1],
                        ts,
                        "notable-scn-inject-1",
                        "T1059",
                        INJECTION_TEXT[0],
                    ),
                )
            ]
        return []

    def extra_routes(self) -> dict[str, Any]:
        return {"/services/notable_update": lambda body: {"success": True}}


class Splunk(Connector):
    manifest = load_manifest(MANIFESTS / "splunk.yaml")
    simulator_cls = SplunkSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "notables": Paged(
            "/services/search/v2/jobs/export/notable", "results", "event_id", "_time", "splunk.es.notable@1"
        ),
        "auth_events": Paged(
            "/services/search/v2/jobs/export/authentication",
            "results",
            "event_id",
            "_time",
            "splunk.cim.authentication@1",
        ),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        if stream == "auth_events":
            require(p, "action", "user")
            return [
                SecurityEventV1(
                    class_uid=3002,
                    activity=f"Logon ({p.get('app', 'unknown')})",
                    severity="low" if p["action"] == "failure" else "info",
                    observed_at=record.observed_at,
                    message=f"{p['action']} logon for {p['user']}",
                    actor_user=str(p["user"]),
                    device_hostname=str(p.get("dest") or "") or None,
                    src_ip=str(p.get("src") or "") or None,
                    outcome="success" if p["action"] == "success" else "failure",
                    mitre_techniques=["T1110"] if p["action"] == "failure" else [],
                )
            ]
        require(p, "event_id", "rule_name", "urgency")
        obs = [Observable(type="user", value=str(p["user"]))] if p.get("user") else []
        if p.get("src"):
            obs.append(Observable(type="ip", value=str(p["src"])))
        return [
            AlertV1(
                domain="soc",
                source_alert_id=str(p["event_id"]),
                title=clip(p["rule_name"], 500),
                description=clip(p.get("rule_description"), 8000),
                severity=Splunk.manifest.severity_map.get(str(p["urgency"]), "medium"),
                category=str(p.get("security_domain", "")),
                observed_at=record.observed_at,
                asset_refs=[host_ref(str(p["dest"]))] if p.get("dest") else [],
                observables=obs,
                mitre_techniques=_techniques(p.get("annotations.mitre_attack")),
                dedup_key=f"splunk:{p['rule_name']}:{p.get('user', '')}:{p.get('dest', '')}",
            )
        ]

    def parse_webhook(self, body: dict[str, Any]) -> list[tuple[str, RawRecord]]:
        """Splunk alert action webhook: {"result": {...}, "search_name": ...}."""
        require(body, "result")
        result = dict(body["result"])
        result.setdefault("rule_name", body.get("search_name", "Splunk alert"))
        result.setdefault("event_id", f"wh-{stable_int(sorted(result.items()))}")
        result.setdefault("urgency", "medium")
        return [("notables", self._raw(self.streams["notables"], result, self.ctx.clock()))]


# ======================================================================= Wazuh
def _wazuh_severity(level: int) -> str:
    return (
        "critical"
        if level >= 12
        else "high"
        if level >= 10
        else "medium"
        if level >= 7
        else "low"
        if level >= 4
        else "info"
    )


class WazuhSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "alerts": GridStream("/alerts", "affected_items", 120),
        "agents": GridStream("/agents", "affected_items", 300),
    }
    RULES: ClassVar[list[tuple[int, int, str, list[str]]]] = [
        (5710, 5, "sshd: Attempt to login using a non-existent user", ["T1110"]),
        (5503, 5, "PAM: User login failed", ["T1110"]),
        (550, 7, "Integrity checksum changed", ["T1565"]),
        (92052, 10, "Suspicious Windows command shell execution", ["T1059"]),
        (510, 7, "Host-based anomaly detection event (rootcheck)", []),
    ]

    def _alert(
        self, rule: tuple[int, int, str, list[str]], agent: str, ts: datetime, aid: str, srcip: str | None = None
    ) -> dict[str, Any]:
        rid, level, desc, mitre = rule
        return {
            "id": aid,
            "timestamp": at(ts),
            "rule": {
                "id": str(rid),
                "level": level,
                "description": desc,
                "mitre": {"id": mitre},
                "groups": ["syscheck"] if rid == 550 else ["authentication_failed"],
            },
            "agent": {
                "id": f"{stable_int(agent, mod=1000):03d}",
                "name": agent,
                "ip": self.world.ips.get(agent, "10.0.0.1"),
            },
            "data": {"srcip": srcip} if srcip else {},
        }

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        w = self.world
        agents = w.hosts[:8] + w.windows_hosts[:4]
        if stream == "agents":
            a = agents[slot % len(agents)]
            return {
                "id": f"{stable_int(a, mod=1000):03d}",
                "name": a,
                "ip": w.ips.get(a, "10.0.0.1"),
                "os": {"name": "Ubuntu" if "lnx" in a else "Microsoft Windows Server 2022"},
                "status": "active",
                "lastKeepAlive": at(ts),
            }
        return self._alert(
            rng.choice(self.RULES), rng.choice(agents), ts, f"{int(ts.timestamp())}.{slot}", _doc_ip(rng)
        )

    def scenario_items(self, scenario: str, step: int, ts: datetime) -> list[tuple[str, dict[str, Any]]]:
        if scenario != RANSOMWARE:
            return []
        host = self.world.windows_hosts[0]
        return [
            (
                "alerts",
                self._alert(
                    (100201, 13, "Multiple files renamed with a new extension in a short time", ["T1486"]),
                    host,
                    ts,
                    "scn-ransom-1",
                ),
            ),
            ("alerts", self._alert((100202, 12, "Volume shadow copies deleted", ["T1490"]), host, ts, "scn-ransom-2")),
        ]

    def extra_routes(self) -> dict[str, Any]:
        return {"/active-response": lambda body: {"data": {"affected_items": body.get("agents_list", [])}}}


class Wazuh(Connector):
    manifest = load_manifest(MANIFESTS / "wazuh.yaml")
    simulator_cls = WazuhSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "alerts": Paged("/alerts", "affected_items", "id", "timestamp", "wazuh.alert@4"),
        "agents": Paged("/agents", "affected_items", "id", "lastKeepAlive", "wazuh.agent@4"),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        if stream == "agents":
            require(p, "id", "name")
            refs = [host_ref(p["name"]), AssetRef(kind="agent_id", value=f"wazuh:{p['id']}")] + (
                [AssetRef(kind="ip", value=p["ip"])] if p.get("ip") else []
            )
            return [
                AssetV1(
                    type="host",
                    name=p["name"],
                    identifiers=refs,
                    attributes={"os": (p.get("os") or {}).get("name"), "agent_status": p.get("status")},
                    observed_at=record.observed_at,
                )
            ]
        require(p, "id", "rule", "agent")
        rule, agent = p["rule"], p["agent"]
        if "level" not in rule or "description" not in rule:
            raise SchemaDriftError("rule without level/description")
        level = int(rule["level"])
        obs = [Observable(type="ip", value=str(p["data"]["srcip"]))] if (p.get("data") or {}).get("srcip") else []
        return [
            AlertV1(
                domain="soc",
                source_alert_id=str(p["id"]),
                title=clip(rule["description"], 500),
                severity=_wazuh_severity(level),  # type: ignore[arg-type]
                category=",".join(rule.get("groups", []))[:100],
                observed_at=record.observed_at,
                asset_refs=[host_ref(str(agent.get("name")))] if agent.get("name") else [],
                observables=obs,
                mitre_techniques=_techniques((rule.get("mitre") or {}).get("id")),
                labels={"rule_id": str(rule.get("id", "")), "rule_level": str(level)},
                dedup_key=f"wazuh:{rule.get('id')}:{agent.get('name')}",
            )
        ]

    def parse_webhook(self, body: dict[str, Any]) -> list[tuple[str, RawRecord]]:
        require(body, "id", "rule", "agent")
        return [("alerts", self._raw(self.streams["alerts"], body, self.ctx.clock()))]


# ======================================================================= CrowdStrike Falcon
class FalconSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "alerts": GridStream("/alerts/combined/alerts/v1", "resources", 300),
        "hosts": GridStream("/devices/combined/devices/v1", "resources", 300),
    }

    def _alert(
        self,
        host: str,
        user: str,
        sev: str,
        tactic: str,
        tid: str,
        technique: str,
        name: str,
        cmd: str,
        ts: datetime,
        cid: str,
        file: str = "powershell.exe",
    ) -> dict[str, Any]:
        return {
            "composite_id": cid,
            "created_timestamp": at(ts),
            "severity_name": sev,
            "severity": {"Critical": 90, "High": 70, "Medium": 50, "Low": 30}.get(sev, 10),
            "tactic": tactic,
            "technique_id": tid,
            "technique": technique,
            "display_name": name,
            "description": f"{name} on {host}",
            "status": "new",
            "device": {
                "device_id": f"{stable_int(host, mod=16**32):032x}",
                "hostname": host,
                "local_ip": self.world.ips.get(host, "10.0.0.1"),
                "platform_name": "Windows",
            },
            "user_name": user,
            "filename": file,
            "sha256": f"{stable_int(file, cid, mod=16**32):032x}" * 2,
            "cmdline": cmd,
        }

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        w = self.world
        host = w.windows_hosts[slot % len(w.windows_hosts)]
        if stream == "hosts":
            return {
                "device_id": f"{stable_int(host, mod=16**32):032x}",
                "hostname": host,
                "local_ip": w.ips.get(host, "10.0.0.1"),
                "platform_name": "Windows",
                "os_version": "Windows 11",
                "status": "normal",
                "last_seen": at(ts),
            }
        sev, tactic, tid, technique, name, cmd = rng.choice(
            [
                (
                    "High",
                    "Execution",
                    "T1059",
                    "Command and Scripting Interpreter",
                    "Suspicious PowerShell",
                    "powershell.exe -nop -w hidden -enc SQBFAFgA... (sandbox)",
                ),
                ("Medium", "Discovery", "T1087", "Account Discovery", "Account enumeration", "net user /domain"),
                (
                    "Low",
                    "Defense Evasion",
                    "T1218",
                    "System Binary Proxy Execution",
                    "Suspicious rundll32",
                    "rundll32.exe shell32.dll,Control_RunDLL (sandbox)",
                ),
            ]
        )
        return self._alert(host, rng.choice(w.users), sev, tactic, tid, technique, name, cmd, ts, f"sandbox:ind:{slot}")

    def scenario_items(self, scenario: str, step: int, ts: datetime) -> list[tuple[str, dict[str, Any]]]:
        if scenario != RANSOMWARE:
            return []
        h, u = self.world.windows_hosts[0], self.world.users[1]
        return [
            (
                "alerts",
                self._alert(
                    h,
                    u,
                    "High",
                    "Execution",
                    "T1059",
                    "Command and Scripting Interpreter",
                    "Encoded PowerShell from Office macro",
                    "powershell.exe -enc ... (sandbox)",
                    ts,
                    "sandbox:ind:scn-r1",
                ),
            ),
            (
                "alerts",
                self._alert(
                    h,
                    u,
                    "Critical",
                    "Impact",
                    "T1490",
                    "Inhibit System Recovery",
                    "Shadow copy deletion",
                    "vssadmin.exe delete shadows /all /quiet",
                    ts,
                    "sandbox:ind:scn-r2",
                    "vssadmin.exe",
                ),
            ),
        ]

    def extra_routes(self) -> dict[str, Any]:
        return {
            "/devices/entities/devices-actions/v2": lambda body: {
                "resources": [{"id": i, "path": "contain"} for i in body.get("ids", [])]
            }
        }


class CrowdStrikeFalcon(Connector):
    manifest = load_manifest(MANIFESTS / "crowdstrike.falcon.yaml")
    simulator_cls = FalconSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "alerts": Paged(
            "/alerts/combined/alerts/v1", "resources", "composite_id", "created_timestamp", "crowdstrike.alert@1"
        ),
        "hosts": Paged("/devices/combined/devices/v1", "resources", "device_id", "last_seen", "crowdstrike.device@2"),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        if stream == "hosts":
            require(p, "device_id", "hostname")
            refs = [host_ref(p["hostname"]), AssetRef(kind="agent_id", value=f"falcon:{p['device_id']}")] + (
                [AssetRef(kind="ip", value=p["local_ip"])] if p.get("local_ip") else []
            )
            return [
                AssetV1(
                    type="host",
                    name=p["hostname"],
                    identifiers=refs,
                    attributes={"os": p.get("os_version"), "containment": p.get("status")},
                    observed_at=record.observed_at,
                )
            ]
        require(p, "composite_id", "display_name", "severity_name", "device")
        dev = p["device"]
        obs = [Observable(type="sha256", value=str(p["sha256"]))] if p.get("sha256") else []
        if p.get("user_name"):
            obs.append(Observable(type="user", value=str(p["user_name"])))
        if p.get("cmdline"):
            obs.append(Observable(type="process", value=clip(p["cmdline"], 2048)))
        return [
            AlertV1(
                domain="soc",
                source_alert_id=str(p["composite_id"]),
                title=clip(p["display_name"], 500),
                description=clip(p.get("description"), 8000),
                severity=CrowdStrikeFalcon.manifest.severity_map.get(p["severity_name"], "medium"),
                category=str(p.get("tactic", "")),
                observed_at=record.observed_at,
                asset_refs=[
                    host_ref(str(dev.get("hostname"))),
                    AssetRef(kind="agent_id", value=f"falcon:{dev.get('device_id')}"),
                ],
                observables=obs,
                mitre_techniques=_techniques([p.get("technique_id")]),
                dedup_key=f"falcon:{p['composite_id']}",
            )
        ]


# ======================================================================= Microsoft Defender for Endpoint
class DefenderSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "alerts": GridStream("/api/alerts", "value", 300),
        "machines": GridStream("/api/machines", "value", 300),
    }

    def _alert(
        self,
        title: str,
        sev: str,
        category: str,
        techniques: list[str],
        host: str,
        user: str,
        ts: datetime,
        aid: str,
        file: str | None = None,
    ) -> dict[str, Any]:
        return {
            "id": aid,
            "title": title,
            "severity": sev,
            "status": "New",
            "category": category,
            "alertCreationTime": at(ts),
            "mitreTechniques": techniques,
            "computerDnsName": f"{host}.corp.example",
            "machineId": f"{stable_int(host, 'mde', mod=16**40):040x}",
            "relatedUser": {"userName": user, "domainName": "CORP"},
            "evidence": [
                {"entityType": "File", "fileName": file, "sha256": f"{stable_int(file, aid, mod=16**32):032x}" * 2}
            ]
            if file
            else [],
        }

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        w = self.world
        host = w.windows_hosts[slot % len(w.windows_hosts)]
        if stream == "machines":
            return {
                "id": f"{stable_int(host, 'mde', mod=16**40):040x}",
                "computerDnsName": f"{host}.corp.example",
                "osPlatform": "Windows11",
                "lastSeen": at(ts),
                "healthStatus": "Active",
                "riskScore": rng.choice(["None", "Low", "Medium", "High"]),
                "lastIpAddress": w.ips.get(host, "10.0.0.1"),
            }
        title, sev, cat, tech = rng.choice(
            [
                ("Suspicious process injection observed", "Medium", "DefenseEvasion", ["T1055"]),
                ("Anomalous scheduled task created", "Low", "Persistence", ["T1053"]),
                ("Credential theft tool detected", "High", "CredentialAccess", ["T1003"]),
            ]
        )
        return self._alert(
            title,
            sev,
            cat,
            tech,
            host,
            rng.choice(w.users),
            ts,
            f"da{slot:018d}",
            "tool.exe" if "Credential" in cat else None,
        )

    def scenario_items(self, scenario: str, step: int, ts: datetime) -> list[tuple[str, dict[str, Any]]]:
        if scenario != PHISHING:
            return []
        h, u = self.world.windows_hosts[2], self.world.users[0]
        return [
            (
                "alerts",
                self._alert(
                    "User clicked a malicious link in an email",
                    "High",
                    "InitialAccess",
                    ["T1566.002"],
                    h,
                    u,
                    ts,
                    "da-scn-phish-1",
                ),
            )
        ]

    def extra_routes(self) -> dict[str, Any]:
        return {
            "/api/machines/isolate": lambda body: {"type": "Isolate", "status": "Pending"},
            "/api/machines/runAntiVirusScan": lambda body: {"type": "RunAntiVirusScan", "status": "Pending"},
        }


class MicrosoftDefender(Connector):
    manifest = load_manifest(MANIFESTS / "microsoft.defender.yaml")
    simulator_cls = DefenderSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "alerts": Paged("/api/alerts", "value", "id", "alertCreationTime", "microsoft.mde.alert@1"),
        "machines": Paged("/api/machines", "value", "id", "lastSeen", "microsoft.mde.machine@1"),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        if stream == "machines":
            require(p, "id", "computerDnsName")
            host = str(p["computerDnsName"]).split(".")[0]
            refs = [
                host_ref(host),
                AssetRef(kind="fqdn", value=p["computerDnsName"]),
                AssetRef(kind="agent_id", value=f"mde:{p['id']}"),
            ]
            return [
                AssetV1(
                    type="host",
                    name=host,
                    identifiers=refs,
                    attributes={"os": p.get("osPlatform"), "risk": p.get("riskScore")},
                    observed_at=record.observed_at,
                )
            ]
        require(p, "id", "title", "severity", "computerDnsName")
        host = str(p["computerDnsName"]).split(".")[0]
        user = (p.get("relatedUser") or {}).get("userName")
        obs = [Observable(type="user", value=str(user))] if user else []
        obs += [Observable(type="sha256", value=str(e["sha256"])) for e in p.get("evidence", []) if e.get("sha256")]
        return [
            AlertV1(
                domain="soc",
                source_alert_id=str(p["id"]),
                title=clip(p["title"], 500),
                severity=MicrosoftDefender.manifest.severity_map.get(p["severity"], "medium"),
                status="resolved" if p.get("status") == "Resolved" else "new",
                category=str(p.get("category", "")),
                observed_at=record.observed_at,
                asset_refs=[host_ref(host), AssetRef(kind="fqdn", value=p["computerDnsName"])],
                observables=obs,
                mitre_techniques=_techniques(p.get("mitreTechniques")),
                dedup_key=f"mde:{p['id']}",
            )
        ]
