/**
 * Connector catalog (docs/06-connector-sdk.md §8). This is product metadata, not status.
 * Instance status comes only from the connector API, which arrives in P2. Until then every
 * connector reports "Not configured". Nothing here claims a live connection.
 */
export type ConnectorCategory = "observability" | "cloud_monitoring" | "siem" | "edr" | "vuln" | "itsm" | "generic";

export interface ConnectorDefinition {
  id: string;
  name: string;
  vendor: string;
  category: ConnectorCategory;
  domain: "noc" | "soc" | "both";
  streams: string[];
  push: string | null;
  actions: { key: string; tier: "T1" | "T2" | "T3" }[];
  certification: "planned";
}

export const CATEGORY_LABEL: Record<ConnectorCategory, string> = {
  observability: "Observability",
  cloud_monitoring: "Cloud monitoring",
  siem: "SIEM",
  edr: "EDR / XDR",
  vuln: "Vulnerability management",
  itsm: "ITSM",
  generic: "Generic",
};

const c = (d: Omit<ConnectorDefinition, "certification">): ConnectorDefinition => ({ ...d, certification: "planned" });

export const CONNECTORS: ConnectorDefinition[] = [
  c({ id: "solarwinds.orion", name: "SolarWinds Orion", vendor: "SolarWinds", category: "observability", domain: "noc", streams: ["alerts", "nodes", "interface status"], push: null, actions: [{ key: "nms.ack_alert", tier: "T1" }, { key: "nms.unmanage_node", tier: "T2" }] }),
  c({ id: "datadog", name: "Datadog", vendor: "Datadog", category: "observability", domain: "noc", streams: ["monitors/events", "metrics", "hosts"], push: "webhook", actions: [{ key: "dd.mute_monitor", tier: "T1" }] }),
  c({ id: "prometheus", name: "Prometheus / Alertmanager", vendor: "CNCF", category: "observability", domain: "noc", streams: ["alerts", "metrics (PromQL)"], push: "Alertmanager webhook", actions: [{ key: "am.create_silence", tier: "T1" }] }),
  c({ id: "grafana", name: "Grafana", vendor: "Grafana Labs", category: "observability", domain: "noc", streams: ["alert instances", "annotations"], push: "contact point webhook", actions: [{ key: "grafana.silence", tier: "T1" }, { key: "grafana.annotate", tier: "T1" }] }),
  c({ id: "aws.cloudwatch", name: "AWS CloudWatch", vendor: "Amazon Web Services", category: "cloud_monitoring", domain: "noc", streams: ["alarms", "metrics", "resource inventory"], push: "SNS → webhook", actions: [{ key: "aws.reboot_instance", tier: "T2" }] }),
  c({ id: "azure.monitor", name: "Azure Monitor", vendor: "Microsoft", category: "cloud_monitoring", domain: "noc", streams: ["alerts", "metrics", "resources"], push: "action group webhook", actions: [{ key: "azure.restart_vm", tier: "T2" }] }),
  c({ id: "gcp.cloud_ops", name: "Google Cloud Operations", vendor: "Google Cloud", category: "cloud_monitoring", domain: "noc", streams: ["incidents", "metrics", "assets"], push: "Pub/Sub push", actions: [{ key: "gcp.restart_instance", tier: "T2" }] }),
  c({ id: "microsoft.sentinel", name: "Microsoft Sentinel", vendor: "Microsoft", category: "siem", domain: "soc", streams: ["incidents", "alerts", "entities"], push: null, actions: [{ key: "sentinel.update_incident", tier: "T1" }] }),
  c({ id: "splunk", name: "Splunk", vendor: "Splunk", category: "siem", domain: "soc", streams: ["notable events", "saved-search results"], push: "HEC-style webhook", actions: [{ key: "splunk.update_notable", tier: "T1" }] }),
  c({ id: "wazuh", name: "Wazuh", vendor: "Wazuh", category: "siem", domain: "soc", streams: ["alerts", "agents"], push: "integration webhook", actions: [{ key: "wazuh.active_response", tier: "T3" }] }),
  c({ id: "crowdstrike.falcon", name: "CrowdStrike Falcon", vendor: "CrowdStrike", category: "edr", domain: "soc", streams: ["detections", "hosts"], push: null, actions: [{ key: "edr.isolate_host", tier: "T3" }, { key: "edr.release_host", tier: "T2" }] }),
  c({ id: "microsoft.defender", name: "Microsoft Defender for Endpoint", vendor: "Microsoft", category: "edr", domain: "soc", streams: ["alerts/incidents", "devices"], push: null, actions: [{ key: "mde.isolate_device", tier: "T3" }, { key: "mde.run_av_scan", tier: "T2" }] }),
  c({ id: "qualys.vmdr", name: "Qualys VMDR", vendor: "Qualys", category: "vuln", domain: "soc", streams: ["host detections", "assets"], push: null, actions: [] }),
  c({ id: "tenable", name: "Tenable", vendor: "Tenable", category: "vuln", domain: "soc", streams: ["findings", "assets"], push: null, actions: [] }),
  c({ id: "servicenow.itsm", name: "ServiceNow ITSM", vendor: "ServiceNow", category: "itsm", domain: "both", streams: ["incidents (bi-directional)", "CMDB CIs"], push: "business-rule webhook", actions: [{ key: "itsm.create_incident", tier: "T1" }, { key: "itsm.update_incident", tier: "T1" }, { key: "itsm.create_change", tier: "T1" }] }),
  c({ id: "generic.webhook", name: "Generic webhook", vendor: "Any", category: "generic", domain: "both", streams: [], push: "signed webhook with JSONPath mapping", actions: [] }),
];

export type ConnectorStatus = "not_configured";

/** Honest status: there is no connector backend yet, so nothing is configured or connected. */
export function connectorStatus(): { status: ConnectorStatus; label: string; detail: string } {
  return {
    status: "not_configured",
    label: "Not configured",
    detail: "Connector instances arrive with the connector SDK in phase P2 (sandbox mode first).",
  };
}
