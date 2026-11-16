"""Cloud monitoring connectors: AWS CloudWatch, Azure Monitor, Google Cloud Operations."""

from __future__ import annotations

import json
import random
from datetime import datetime
from typing import Any, ClassVar

from nocsoc_connector_sdk import (
    AlertV1,
    AssetRef,
    AssetV1,
    Connector,
    GridStream,
    MetricPointV1,
    NormalizedRecord,
    Paged,
    RawRecord,
    SchemaDriftError,
    Simulator,
    load_manifest,
    parse_ts,
)
from nocsoc_connectors._kit import DB_SATURATION, MANIFESTS, at, clip, require


def cloud_ref(resource_id: str) -> AssetRef:
    return AssetRef(kind="cloud_id", value=resource_id)


# ======================================================================= AWS CloudWatch
class CloudWatchSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "alarms": GridStream("/cloudwatch/DescribeAlarmHistory", "AlarmHistoryItems", 240),
        "instances": GridStream("/ec2/DescribeInstances", "Instances", 300),
        "metrics": GridStream("/cloudwatch/GetMetricData", "MetricDataResults", 120),
    }
    ALARMS: ClassVar[list[tuple[str, str]]] = [
        ("CPUUtilization-high", "CPUUtilization"),
        ("StatusCheckFailed", "StatusCheckFailed"),
        ("ALB-5XX-rate", "HTTPCode_ELB_5XX_Count"),
        ("RDS-FreeStorage-low", "FreeStorageSpace"),
    ]

    def _alarm(self, name: str, metric: str, instance: str, state: str, ts: datetime, reason: str) -> dict[str, Any]:
        return {
            "AlarmName": f"{name}-{instance}",
            "Timestamp": at(ts),
            "HistoryItemType": "StateUpdate",
            "HistorySummary": f"Alarm updated from OK to {state}",
            "HistoryData": json.dumps(
                {
                    "newState": {"stateValue": state, "stateReason": reason},
                    "metric": metric,
                    "dimensions": [{"name": "InstanceId", "value": instance}],
                }
            ),
            "AlarmId": f"{name}-{instance}@{at(ts)}",
        }

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        w = self.world
        inst = w.cloud_instances[slot % len(w.cloud_instances)]
        if stream == "instances":
            return {
                "InstanceId": inst,
                "InstanceType": rng.choice(["m6i.large", "c6g.xlarge", "t3.medium"]),
                "State": {"Name": "running"},
                "PrivateIpAddress": f"10.80.{slot % 250}.{(slot * 7) % 250 + 2}",
                "Tags": [
                    {"Key": "Name", "Value": f"{w.prefix}-app-{slot % len(w.cloud_instances):02d}"},
                    {"Key": "env", "Value": "prod"},
                ],
                "ObservedAt": at(ts),
            }
        if stream == "metrics":
            return {
                "Id": f"cw-{slot}",
                "MetricName": "CPUUtilization",
                "InstanceId": inst,
                "Timestamp": at(ts),
                "Value": round(rng.uniform(3, 80), 2),
                "Unit": "Percent",
            }
        name, metric = rng.choice(self.ALARMS)
        state = "ALARM" if rng.random() > 0.3 else "OK"
        return self._alarm(
            name, metric, rng.choice(w.cloud_instances), state, ts, f"Threshold crossed: 1 datapoint for {metric}"
        )

    def scenario_items(self, scenario: str, step: int, ts: datetime) -> list[tuple[str, dict[str, Any]]]:
        if scenario != DB_SATURATION:
            return []
        db = f"{self.world.prefix}-orders-db"
        return [
            (
                "alarms",
                self._alarm(
                    "RDS-CPUUtilization-high",
                    "CPUUtilization",
                    db,
                    "ALARM",
                    ts,
                    "Threshold crossed: CPUUtilization 97% > 90% for 3 datapoints",
                ),
            )
        ]

    def extra_routes(self) -> dict[str, Any]:
        return {"/ec2/RebootInstances": lambda body: {"Return": True}}


class AwsCloudWatch(Connector):
    manifest = load_manifest(MANIFESTS / "aws.cloudwatch.yaml")
    simulator_cls = CloudWatchSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "alarms": Paged(
            "/cloudwatch/DescribeAlarmHistory",
            "AlarmHistoryItems",
            "AlarmId",
            "Timestamp",
            "aws.cloudwatch.alarm_history@1",
        ),
        "instances": Paged("/ec2/DescribeInstances", "Instances", "InstanceId", "ObservedAt", "aws.ec2.instance@1"),
        "metrics": Paged(
            "/cloudwatch/GetMetricData", "MetricDataResults", "Id", "Timestamp", "aws.cloudwatch.datapoint@1"
        ),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        if stream == "instances":
            require(p, "InstanceId", "State")
            tags = {t["Key"]: t["Value"] for t in p.get("Tags", [])}
            refs = [cloud_ref(p["InstanceId"])] + (
                [AssetRef(kind="ip", value=p["PrivateIpAddress"])] if p.get("PrivateIpAddress") else []
            )
            return [
                AssetV1(
                    type="cloud_resource",
                    name=tags.get("Name", p["InstanceId"]),
                    identifiers=refs,
                    environment=tags.get("env", "unknown")
                    if tags.get("env") in ("prod", "stage", "dev")
                    else "unknown",
                    attributes={
                        "provider": "aws",
                        "instance_type": p.get("InstanceType"),
                        "state": p["State"].get("Name"),
                    },
                    observed_at=record.observed_at,
                )
            ]
        if stream == "metrics":
            require(p, "MetricName", "InstanceId", "Value")
            return [
                MetricPointV1(
                    name=f"aws.{p['MetricName']}",
                    value=float(p["Value"]),
                    unit=str(p.get("Unit", "")),
                    asset_ref=cloud_ref(p["InstanceId"]),
                    observed_at=record.observed_at,
                )
            ]
        require(p, "AlarmName", "HistoryData")
        try:
            data = json.loads(p["HistoryData"])
            state = data["newState"]["stateValue"]
        except (ValueError, KeyError, TypeError) as exc:
            raise SchemaDriftError("unparseable HistoryData") from exc
        dims = {d["name"]: d["value"] for d in data.get("dimensions", [])}
        target = dims.get("InstanceId") or dims.get("DBInstanceIdentifier")
        return [
            AlertV1(
                domain="noc",
                source_alert_id=str(p.get("AlarmId", p["AlarmName"])),
                title=clip(f"CloudWatch alarm {p['AlarmName']} is {state}", 500),
                description=clip(data["newState"].get("stateReason"), 8000),
                severity=AwsCloudWatch.manifest.severity_map.get(state, "medium"),
                status="resolved" if state == "OK" else "new",
                category="cloud",
                observed_at=record.observed_at,
                asset_refs=[cloud_ref(target)] if target else [],
                labels={"metric": str(data.get("metric", ""))},
                dedup_key=f"aws.cloudwatch:{p['AlarmName']}",
            )
        ]

    def parse_webhook(self, body: dict[str, Any]) -> list[tuple[str, RawRecord]]:
        """SNS notification whose Message is the CloudWatch alarm JSON."""
        require(body, "Message")
        try:
            msg = json.loads(body["Message"])
        except ValueError as exc:
            raise SchemaDriftError("SNS Message is not JSON") from exc
        item = {
            "AlarmName": msg.get("AlarmName"),
            "Timestamp": msg.get("StateChangeTime"),
            "AlarmId": f"{msg.get('AlarmName')}@{msg.get('StateChangeTime')}",
            "HistoryData": json.dumps(
                {
                    "newState": {"stateValue": msg.get("NewStateValue"), "stateReason": msg.get("NewStateReason")},
                    "metric": (msg.get("Trigger") or {}).get("MetricName"),
                    "dimensions": (msg.get("Trigger") or {}).get("Dimensions", []),
                }
            ),
        }
        return [("alarms", self._raw(self.streams["alarms"], item, self.ctx.clock()))]


# ======================================================================= Azure Monitor
class AzureMonitorSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "alerts": GridStream("/providers/Microsoft.AlertsManagement/alerts", "value", 240),
        "resources": GridStream("/providers/Microsoft.Compute/virtualMachines", "value", 600),
    }

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        w = self.world
        vm = f"{w.prefix}-azvm-{slot % 5:02d}"
        rid = f"/subscriptions/00000000-0000-4000-8000-000000000000/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/{vm}"
        if stream == "resources":
            return {
                "id": rid,
                "name": vm,
                "location": "westeurope",
                "properties": {"hardwareProfile": {"vmSize": "Standard_D4s_v5"}, "provisioningState": "Succeeded"},
                "tags": {"env": "prod"},
                "observedAt": at(ts),
            }
        rule, sev = rng.choice(
            [("VM CPU above 90%", "Sev2"), ("VM heartbeat missing", "Sev1"), ("Low available memory", "Sev3")]
        )
        return {
            "id": f"{rid}/providers/Microsoft.AlertsManagement/alerts/{slot:08x}",
            "name": rule,
            "properties": {
                "essentials": {
                    "severity": sev,
                    "signalType": "Metric",
                    "alertState": "New",
                    "monitorCondition": "Fired" if rng.random() > 0.25 else "Resolved",
                    "targetResource": rid,
                    "targetResourceName": vm,
                    "alertRule": rule,
                    "startDateTime": at(ts),
                }
            },
        }


class AzureMonitor(Connector):
    manifest = load_manifest(MANIFESTS / "azure.monitor.yaml")
    simulator_cls = AzureMonitorSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "alerts": Paged(
            "/providers/Microsoft.AlertsManagement/alerts",
            "value",
            "id",
            "properties.essentials.startDateTime",
            "azure.alerts_management.alert@1",
        ),
        "resources": Paged(
            "/providers/Microsoft.Compute/virtualMachines", "value", "id", "observedAt", "azure.compute.vm@1"
        ),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        if stream == "resources":
            require(p, "id", "name")
            env = (p.get("tags") or {}).get("env", "unknown")
            return [
                AssetV1(
                    type="vm",
                    name=p["name"],
                    identifiers=[cloud_ref(p["id"]), AssetRef(kind="hostname", value=p["name"])],
                    environment=env if env in ("prod", "stage", "dev") else "unknown",
                    attributes={"provider": "azure", "location": p.get("location")},
                    observed_at=record.observed_at,
                )
            ]
        require(p, "id", "properties")
        e = (p["properties"] or {}).get("essentials")
        if not isinstance(e, dict) or "severity" not in e:
            raise SchemaDriftError("missing properties.essentials")
        resolved = e.get("monitorCondition") == "Resolved"
        return [
            AlertV1(
                domain="noc",
                source_alert_id=str(p["id"]),
                title=clip(f"{e.get('alertRule', p.get('name'))} on {e.get('targetResourceName', '?')}", 500),
                severity=AzureMonitor.manifest.severity_map.get(e["severity"], "medium"),
                status="resolved" if resolved else "new",
                category="cloud",
                observed_at=record.observed_at,
                asset_refs=[cloud_ref(e["targetResource"])] if e.get("targetResource") else [],
                labels={"signal_type": str(e.get("signalType", ""))},
                dedup_key=f"azure.monitor:{e.get('alertRule')}:{e.get('targetResource')}",
            )
        ]

    def parse_webhook(self, body: dict[str, Any]) -> list[tuple[str, RawRecord]]:
        """Common alert schema: {"schemaId": "azureMonitorCommonAlertSchema", "data": {"essentials": {...}}}."""
        require(body, "data")
        e = body["data"].get("essentials", {})
        item = {
            "id": e.get("alertId"),
            "name": e.get("alertRule"),
            "properties": {
                "essentials": {
                    **e,
                    "targetResource": (e.get("alertTargetIDs") or [None])[0],
                    "startDateTime": e.get("firedDateTime"),
                }
            },
        }
        return [("alerts", self._raw(self.streams["alerts"], item, self.ctx.clock()))]


# ======================================================================= Google Cloud Operations
class GcpSimulator(Simulator):
    grid: ClassVar[dict[str, GridStream]] = {
        "incidents": GridStream("/v3/projects/sandbox/incidents", "incidents", 300),
        "instances": GridStream("/compute/v1/projects/sandbox/aggregated/instances", "items", 600),
    }

    def make_item(self, stream: str, ts: datetime, rng: random.Random, slot: int) -> dict[str, Any]:
        name = f"{self.world.prefix}-gce-{slot % 4:02d}"
        if stream == "instances":
            return {
                "id": str(7_000_000_000 + slot % 4),
                "name": name,
                "zone": "europe-west4-a",
                "status": "RUNNING",
                "machineType": "e2-standard-4",
                "labels": {"env": "prod"},
                "observedAt": at(ts),
            }
        policy, sev = rng.choice(
            [("GKE node not ready", "ERROR"), ("Cloud SQL CPU > 85%", "WARNING"), ("Uptime check failed", "CRITICAL")]
        )
        return {
            "incident_id": f"0.{slot:010d}",
            "policy_name": policy,
            "condition_name": policy,
            "state": "open" if rng.random() > 0.25 else "closed",
            "started_at": int(ts.timestamp()),
            "resource_name": name,
            "resource": {"type": "gce_instance", "labels": {"instance_id": str(7_000_000_000 + slot % 4)}},
            "summary": f"{policy} for {name}",
            "severity": sev,
        }


class GcpCloudOps(Connector):
    manifest = load_manifest(MANIFESTS / "gcp.cloud_ops.yaml")
    simulator_cls = GcpSimulator
    streams: ClassVar[dict[str, Paged]] = {
        "incidents": Paged(
            "/v3/projects/sandbox/incidents", "incidents", "incident_id", "started_at", "gcp.monitoring.incident@1.2"
        ),
        "instances": Paged(
            "/compute/v1/projects/sandbox/aggregated/instances", "items", "id", "observedAt", "gcp.compute.instance@1"
        ),
    }

    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]:
        p = record.payload
        if stream == "instances":
            require(p, "id", "name")
            return [
                AssetV1(
                    type="vm",
                    name=p["name"],
                    identifiers=[cloud_ref(f"gce:{p['id']}"), AssetRef(kind="hostname", value=p["name"])],
                    environment="prod" if (p.get("labels") or {}).get("env") == "prod" else "unknown",
                    attributes={"provider": "gcp", "zone": p.get("zone")},
                    observed_at=record.observed_at,
                )
            ]
        require(p, "incident_id", "policy_name", "state")
        instance_id = ((p.get("resource") or {}).get("labels") or {}).get("instance_id")
        return [
            AlertV1(
                domain="noc",
                source_alert_id=str(p["incident_id"]),
                title=clip(p.get("summary") or p["policy_name"], 500),
                severity=GcpCloudOps.manifest.severity_map.get(
                    str(p.get("severity", "SEVERITY_UNSPECIFIED")), "medium"
                ),
                status="resolved" if p["state"] == "closed" else "new",
                category="cloud",
                observed_at=parse_ts(p["started_at"]) if p.get("started_at") else record.observed_at,
                asset_refs=[cloud_ref(f"gce:{instance_id}")] if instance_id else [],
                dedup_key=f"gcp:{p['policy_name']}:{p.get('resource_name', '')}",
            )
        ]

    def parse_webhook(self, body: dict[str, Any]) -> list[tuple[str, RawRecord]]:
        """Webhook notification channel, schema version 1.2: {"version": "1.2", "incident": {...}}."""
        require(body, "incident")
        return [("incidents", self._raw(self.streams["incidents"], body["incident"], self.ctx.clock()))]
