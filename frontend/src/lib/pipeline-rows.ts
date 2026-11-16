/**
 * Maps pipeline (sandbox-sourced) records to DataTable rows. Column keys match the DEMO row
 * mappers in rows.ts so the same column specs work for both; provenance is always explicit.
 */
import type { ColumnSpec, Row } from "@/components/data-table";
import type { components } from "@/lib/api/schema";
import { formatTime } from "@/lib/format";

type AlertOut = components["schemas"]["AlertOut"];
type VulnOut = components["schemas"]["VulnOut"];
type InstanceOut = components["schemas"]["InstanceOut"];
type DefinitionOut = components["schemas"]["DefinitionOut"];

export const SANDBOX_SOURCE = "sandbox connector";

export function pipelineAlertRow(a: AlertOut): Row {
  return {
    _id: a.id,
    title: a.title,
    severity: a.severity,
    status: a.status,
    asset: a.asset?.name ?? null,
    service: a.service_hint ?? null,
    technique: a.mitre_techniques.join(", ") || null,
    source: a.connector_id,
    count: a.occurrence_count,
    createdAt: a.last_seen,
    _details: {
      "Alert ID": a.id,
      Title: a.title,
      Severity: a.severity,
      Status: a.status.replace(/_/g, " "),
      Asset: a.asset ? `${a.asset.name} (${a.asset.type})` : null,
      Service: a.service_hint ?? null,
      Source: `${a.connector_id} (${SANDBOX_SOURCE}; simulated vendor data)`,
      "Source alert ID": a.source_alert_id,
      "ATT&CK techniques": a.mitre_techniques.join(", ") || null,
      Occurrences: a.occurrence_count,
      "First seen": formatTime(a.first_seen),
      "Last seen": formatTime(a.last_seen),
      // Alert text comes from an external system: it is displayed as text, never interpreted.
      Description: a.description || null,
    },
  };
}

export const pipelineVulnColumns: ColumnSpec[] = [
  { key: "cve", header: "Vulnerability", type: "mono" },
  { key: "title", header: "Title" },
  { key: "severity", header: "Severity", type: "severity", filter: true },
  { key: "cvss", header: "CVSS", type: "number", align: "right" },
  { key: "kev", header: "Known exploited", filter: true },
  { key: "asset", header: "Asset", type: "mono" },
  { key: "source", header: "Scanner", filter: true, hideOnMobile: true },
  { key: "lastFound", header: "Last found", type: "relative" },
];

export function pipelineVulnRow(v: VulnOut): Row {
  return {
    _id: v.id,
    cve: v.vuln_id,
    title: v.title,
    severity: v.severity,
    cvss: v.cvss ?? null,
    kev: v.kev ? "Yes" : "No",
    asset: v.asset?.name ?? null,
    source: v.connector_id,
    lastFound: v.last_found,
    _details: {
      ID: `${v.vuln_id} (sandbox identifier, not a real CVE)`,
      Title: v.title,
      Asset: v.asset?.name ?? null,
      "CVSS base": v.cvss ?? null,
      EPSS: v.epss ?? null,
      "Known exploited": v.kev ? "Yes" : "No",
      Status: v.status,
      Scanner: `${v.connector_id} (${SANDBOX_SOURCE})`,
      "First found": formatTime(v.first_found),
      "Last found": formatTime(v.last_found),
    },
  };
}

/** Health label for an instance. "pending" means no run has been reported yet: never "healthy". */
export const INSTANCE_STATUS: Record<InstanceOut["status"], { label: string; health: "healthy" | "degraded" | "down" | "maintenance" }> = {
  healthy: { label: "Healthy", health: "healthy" },
  degraded: { label: "Degraded", health: "degraded" },
  failing: { label: "Failing", health: "down" },
  pending: { label: "Awaiting first run", health: "maintenance" },
  disabled: { label: "Disabled", health: "maintenance" },
};

export const instanceColumns: ColumnSpec[] = [
  { key: "name", header: "Integration" },
  { key: "connector", header: "Connector", filter: true },
  { key: "mode", header: "Mode", filter: true, hideOnMobile: true },
  { key: "status", header: "Status", filter: true },
  { key: "lastSuccess", header: "Last successful run", type: "relative", hideOnMobile: true },
  { key: "detail", header: "Detail", hideOnMobile: true },
];

export function instanceRow(i: InstanceOut, definitions: DefinitionOut[]): Row {
  const def = definitions.find((d) => d.id === i.definition_id);
  return {
    _id: i.id,
    _href: `/connectors/${i.id}`,
    name: i.name,
    connector: def?.name ?? i.definition_id,
    mode: i.mode.toUpperCase(),
    status: INSTANCE_STATUS[i.status].label,
    lastSuccess: i.last_success_at ?? null,
    detail: i.status_detail ?? null,
  };
}
