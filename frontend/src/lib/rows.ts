/** Maps DEMO domain records to DataTable rows and column specs (shared across pages). */
import type { ColumnSpec, Row } from "@/components/data-table";
import { TECHNIQUES } from "@/lib/demo/reference";
import type {
  Alert,
  Asset,
  AssetType,
  EdrDetection,
  Incident,
  Indicator,
  ProcessNode,
  SiemEvent,
  Vulnerability,
} from "@/lib/demo/types";
import { formatTime } from "@/lib/format";

export const customerCol = (aggregate: boolean): ColumnSpec[] =>
  aggregate ? [{ key: "customer", header: "Customer", filter: true }] : [];

const technique = (id: string | null) => (id ? `${id} ${TECHNIQUES[id]?.name ?? ""}`.trim() : null);

// ---------------------------------------------------------------- incidents
export const incidentColumns = (aggregate: boolean): ColumnSpec[] => [
  { key: "number", header: "Incident", type: "mono" },
  { key: "title", header: "Title" },
  ...customerCol(aggregate),
  { key: "domain", header: "Domain", filter: true, hideOnMobile: true },
  { key: "severity", header: "Severity", type: "severity", filter: true },
  { key: "priority", header: "Priority", filter: true },
  { key: "status", header: "Status", type: "state", filter: true },
  { key: "commander", header: "Commander", hideOnMobile: true },
  { key: "detectedAt", header: "Detected", type: "relative" },
];

export function incidentRow(i: Incident): Row {
  return {
    _id: i.id,
    _href: `/incidents/${i.id}`,
    number: i.number,
    title: i.title,
    customer: i.tenant.name,
    domain: i.domain.toUpperCase(),
    severity: i.severity,
    priority: i.priority,
    status: i.status,
    commander: i.commander,
    detectedAt: i.detectedAt,
  };
}

// ---------------------------------------------------------------- alerts
export const alertColumns = (aggregate: boolean, soc = false): ColumnSpec[] => [
  { key: "title", header: "Alert" },
  ...customerCol(aggregate),
  { key: "severity", header: "Severity", type: "severity", filter: true },
  { key: "status", header: "Status", type: "state", filter: true },
  { key: "asset", header: soc ? "Host" : "Asset", type: "mono" },
  ...(soc ? [{ key: "technique", header: "ATT&CK", filter: true, hideOnMobile: true } as ColumnSpec] : [{ key: "service", header: "Service", filter: true, hideOnMobile: true } as ColumnSpec]),
  { key: "source", header: "Source", filter: true, hideOnMobile: true },
  { key: "count", header: "Count", type: "number", align: "right", hideOnMobile: true },
  { key: "createdAt", header: "Raised", type: "relative" },
];

export function alertRow(a: Alert, incidentNumber?: string): Row {
  return {
    _id: a.id,
    title: a.title,
    customer: a.tenant.name,
    severity: a.severity,
    status: a.status,
    asset: a.assetName,
    service: a.service,
    technique: technique(a.technique),
    source: a.source,
    count: a.count,
    createdAt: a.createdAt,
    _details: {
      "Alert ID": a.id,
      Title: a.title,
      Severity: a.severity,
      Status: a.status.replace(/_/g, " "),
      Asset: a.assetName,
      Service: a.service,
      Source: `${a.source} (DEMO data; no connector configured)`,
      "ATT&CK technique": technique(a.technique),
      Occurrences: a.count,
      "Correlation group": a.groupId,
      Incident: incidentNumber ?? null,
      Raised: formatTime(a.createdAt),
    },
  };
}

// ---------------------------------------------------------------- assets
export function assetColumns(type: AssetType, aggregate: boolean): ColumnSpec[] {
  const metric: Record<AssetType, ColumnSpec[]> = {
    server: [
      { key: "cpu", header: "CPU", type: "percent", align: "right" },
      { key: "memory", header: "Memory", type: "percent", align: "right" },
      { key: "disk", header: "Disk", type: "percent", align: "right", hideOnMobile: true },
    ],
    network: [
      { key: "bandwidth", header: "Bandwidth", type: "percent", align: "right" },
      { key: "loss", header: "Packet loss %", type: "number", align: "right" },
      { key: "latency", header: "Latency ms", type: "number", align: "right", hideOnMobile: true },
    ],
    cloud: [
      { key: "utilisation", header: "Utilisation", type: "percent", align: "right" },
      { key: "cost", header: "Cost / month (€)", type: "number", align: "right" },
    ],
    application: [
      { key: "p95", header: "p95 ms", type: "number", align: "right" },
      { key: "errors", header: "Errors %", type: "number", align: "right" },
      { key: "apdex", header: "Apdex", type: "number", align: "right", hideOnMobile: true },
    ],
    database: [
      { key: "connections", header: "Connections", type: "number", align: "right" },
      { key: "lag", header: "Repl. lag s", type: "number", align: "right" },
      { key: "qps", header: "QPS", type: "number", align: "right", hideOnMobile: true },
    ],
  };
  return [
    { key: "name", header: "Name", type: "mono" },
    ...customerCol(aggregate),
    { key: "status", header: "Health", type: "health", filter: true },
    { key: "kind", header: "Kind", filter: true, hideOnMobile: true },
    { key: "environment", header: "Env", filter: true, hideOnMobile: true },
    { key: "location", header: type === "cloud" ? "Region" : "Site", filter: true, hideOnMobile: true },
    ...metric[type],
    { key: "availability", header: "Avail. 30d", type: "percent", align: "right" },
    { key: "service", header: "Service", filter: true, hideOnMobile: true },
  ];
}

export function assetRow(a: Asset): Row {
  const m = a.metrics;
  return {
    _id: a.id,
    _href: `/noc/assets/${a.id}`,
    name: a.name,
    customer: a.tenant.name,
    status: a.status,
    kind: a.kind,
    environment: a.environment,
    location: a.location,
    cpu: a.cpu,
    memory: a.memory,
    disk: a.disk,
    bandwidth: m.bandwidthUtil,
    loss: m.packetLoss,
    latency: m.latencyMs,
    utilisation: m.utilisation,
    cost: m.monthlyCost,
    p95: m.p95Ms,
    errors: m.errorRate,
    apdex: m.apdex,
    connections: m.connections,
    lag: m.replicationLagS,
    qps: m.qps,
    availability: a.availability30d,
    service: a.service,
  };
}

// ---------------------------------------------------------------- SIEM / EDR
export const siemColumns = (aggregate: boolean): ColumnSpec[] => [
  { key: "rule", header: "Rule" },
  ...customerCol(aggregate),
  { key: "severity", header: "Severity", type: "severity", filter: true },
  { key: "category", header: "Category", filter: true },
  { key: "outcome", header: "Outcome", filter: true },
  { key: "user", header: "User", type: "mono", hideOnMobile: true },
  { key: "host", header: "Host", type: "mono", hideOnMobile: true },
  { key: "source", header: "Source", filter: true, hideOnMobile: true },
  { key: "time", header: "Time", type: "time" },
];

export function siemRow(e: SiemEvent): Row {
  return {
    _id: e.id,
    rule: e.rule,
    customer: e.tenant.name,
    severity: e.severity,
    category: e.category,
    outcome: e.outcome,
    user: e.user,
    host: e.host,
    source: e.source,
    time: e.time,
    _details: {
      "Event ID": e.id,
      Rule: e.rule,
      Source: `${e.source} (DEMO data; no connector configured)`,
      Category: e.category,
      Action: e.action,
      Outcome: e.outcome,
      User: e.user,
      Host: e.host,
      "Source IP": e.srcIp,
      "Destination IP": e.dstIp,
      "ATT&CK technique": technique(e.technique),
      Time: formatTime(e.time),
    },
  };
}

function renderTree(node: ProcessNode, depth = 0): string {
  const line = `${"  ".repeat(depth)}${depth ? "└─ " : ""}${node.name} (pid ${node.pid})\n${"  ".repeat(depth + 1)}${node.cmd}`;
  return [line, ...node.children.map((c) => renderTree(c, depth + 1))].join("\n");
}

export const edrColumns = (aggregate: boolean): ColumnSpec[] => [
  { key: "technique", header: "Detection" },
  ...customerCol(aggregate),
  { key: "severity", header: "Severity", type: "severity", filter: true },
  { key: "status", header: "Status", type: "state", filter: true },
  { key: "host", header: "Host", type: "mono" },
  { key: "tactic", header: "Tactic", filter: true, hideOnMobile: true },
  { key: "product", header: "Product", filter: true, hideOnMobile: true },
  { key: "time", header: "Time", type: "time" },
];

export function edrRow(d: EdrDetection): Row {
  return {
    _id: d.id,
    technique: technique(d.technique),
    customer: d.tenant.name,
    severity: d.severity,
    status: d.status,
    host: d.host,
    tactic: d.tactic,
    product: d.product,
    time: d.time,
    _details: {
      Detection: technique(d.technique),
      Tactic: d.tactic,
      Host: d.host,
      User: d.user,
      Product: `${d.product} (DEMO data; no connector configured)`,
      File: d.file,
      SHA256: d.sha256,
      "Process tree": renderTree(d.tree),
      "Response options": "Isolate host is a T3 action: 2 approvers, simulate mode only (automation arrives in P5).",
      Time: formatTime(d.time),
    },
  };
}

// ---------------------------------------------------------------- TI / vulns
export const indicatorColumns = (aggregate: boolean): ColumnSpec[] => [
  { key: "value", header: "Indicator", type: "mono" },
  ...customerCol(aggregate),
  { key: "type", header: "Type", filter: true },
  { key: "actor", header: "Associated actor", filter: true },
  { key: "confidence", header: "Confidence", type: "score" },
  { key: "sightings", header: "Sightings", type: "number", align: "right" },
  { key: "tags", header: "Tags", type: "tags", filter: true, hideOnMobile: true },
  { key: "feed", header: "Feed", filter: true, hideOnMobile: true },
  { key: "lastSeen", header: "Last seen", type: "relative" },
];

export function indicatorRow(i: Indicator): Row {
  return {
    _id: i.id,
    value: i.value,
    customer: i.tenant.name,
    type: i.type,
    actor: i.actor,
    confidence: i.confidence,
    sightings: i.sightings,
    tags: i.tags,
    feed: i.feed,
    lastSeen: i.lastSeen,
    _details: {
      Indicator: i.value,
      Type: i.type,
      Actor: i.actor,
      Confidence: `${i.confidence}/100`,
      "Sightings in your telemetry": i.sightings,
      Tags: i.tags.join(", "),
      Feed: `${i.feed} (DEMO)`,
      "First seen": formatTime(i.firstSeen),
      "Last seen": formatTime(i.lastSeen),
    },
  };
}

export const vulnColumns = (aggregate: boolean): ColumnSpec[] => [
  { key: "cve", header: "ID", type: "mono" },
  { key: "title", header: "Vulnerability" },
  ...customerCol(aggregate),
  { key: "severity", header: "Severity", type: "severity", filter: true },
  { key: "risk", header: "Risk", type: "score" },
  { key: "kev", header: "Known exploited", type: "bool", filter: true },
  { key: "exposure", header: "Exposure", filter: true, hideOnMobile: true },
  { key: "asset", header: "Asset", type: "mono", hideOnMobile: true },
  { key: "status", header: "Status", type: "state", filter: true },
  { key: "dueDate", header: "Due", type: "relative" },
];

export function vulnRow(v: Vulnerability): Row {
  return {
    _id: v.id,
    cve: v.cve,
    title: v.title,
    customer: v.tenant.name,
    severity: v.severity,
    risk: v.risk,
    kev: v.kev,
    exposure: v.exposure,
    asset: v.assetName,
    status: v.status,
    dueDate: v.dueDate,
    _details: {
      ID: `${v.cve} (demo identifier, not a real CVE)`,
      Title: v.title,
      Product: v.product,
      Asset: v.assetName,
      "CVSS base": v.cvss,
      EPSS: v.epss,
      "Known exploited": v.kev ? "Yes" : "No",
      Exposure: v.exposure,
      "Risk score": `${v.risk}/100 (CVSS, EPSS, KEV, exposure and asset criticality)`,
      Status: v.status.replace(/_/g, " "),
      Scanner: `${v.source} (DEMO data; no connector configured)`,
      "First found": formatTime(v.firstFound),
      "Remediation due": formatTime(v.dueDate),
    },
  };
}
