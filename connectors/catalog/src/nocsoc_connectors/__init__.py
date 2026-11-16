"""Connector catalog: 15 target tools + generic webhook, all sandbox-first (docs/06 §8)."""

from __future__ import annotations

from dataclasses import dataclass

from nocsoc_connector_sdk import Connector
from nocsoc_connectors._kit import CORE_SWITCH, DB_SATURATION, INJECTION, KEV, NOISE, PHISHING, RANSOMWARE
from nocsoc_connectors.cloud import AwsCloudWatch, AzureMonitor, GcpCloudOps
from nocsoc_connectors.observability import Datadog, Grafana, Prometheus, SolarWindsOrion
from nocsoc_connectors.other import GenericWebhook, QualysVmdr, ServiceNowItsm, Tenable
from nocsoc_connectors.security import CrowdStrikeFalcon, MicrosoftDefender, MicrosoftSentinel, Splunk, Wazuh

REGISTRY: dict[str, type[Connector]] = {
    c.manifest.id: c
    for c in (
        SolarWindsOrion,
        Datadog,
        Prometheus,
        Grafana,
        AwsCloudWatch,
        AzureMonitor,
        GcpCloudOps,
        MicrosoftSentinel,
        Splunk,
        Wazuh,
        CrowdStrikeFalcon,
        MicrosoftDefender,
        QualysVmdr,
        Tenable,
        ServiceNowItsm,
        GenericWebhook,
    )
}


@dataclass(frozen=True)
class Scenario:
    key: str
    title: str
    description: str
    connectors: tuple[str, ...]


SCENARIOS: dict[str, Scenario] = {
    s.key: s
    for s in (
        Scenario(
            CORE_SWITCH,
            "Core switch failure",
            "Core switch goes down: network, host and application alerts cascade, and a ServiceNow incident is opened.",
            ("solarwinds.orion", "prometheus", "datadog", "servicenow.itsm"),
        ),
        Scenario(
            DB_SATURATION,
            "Database CPU saturation",
            "Cloud database CPU saturates: CloudWatch alarm, connection exhaustion and API latency.",
            ("aws.cloudwatch", "prometheus", "datadog"),
        ),
        Scenario(
            PHISHING,
            "Phishing to credential misuse",
            "A user clicks a phishing link, then improbable sign-ins and MFA fatigue follow.",
            ("microsoft.defender", "microsoft.sentinel", "splunk"),
        ),
        Scenario(
            RANSOMWARE,
            "Ransomware precursor",
            "Encoded PowerShell, shadow-copy deletion and mass renames on a file server that also slows down (joint NOC/SOC).",
            ("crowdstrike.falcon", "wazuh", "datadog"),
        ),
        Scenario(
            KEV,
            "Known-exploited vulnerability exposure",
            "Critical, known-exploited vulnerabilities appear on internet-facing assets.",
            ("qualys.vmdr", "tenable"),
        ),
        Scenario(
            NOISE,
            "Flapping and duplicate alerts",
            "The same alerts repeat; de-duplication must fold them into single alerts.",
            ("prometheus", "datadog"),
        ),
        Scenario(
            INJECTION,
            "Adversarial content",
            "Alert text contains prompt-injection strings. They must be stored and shown as data, never followed.",
            ("microsoft.sentinel", "splunk"),
        ),
    )
}

__all__ = ["REGISTRY", "SCENARIOS", "Scenario"]
