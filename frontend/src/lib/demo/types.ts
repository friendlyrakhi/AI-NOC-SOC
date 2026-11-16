/**
 * DEMO domain model. Shapes follow docs/03-data-model.md so pages can switch to the real
 * APIs (P2/P3) without UI changes. Every record carries `demo: true`.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export type Health = "healthy" | "degraded" | "down" | "maintenance";
export type AssetType = "server" | "network" | "cloud" | "application" | "database";

export interface TenantRef {
  id: string;
  name: string;
}

interface Base {
  demo: true;
  tenant: TenantRef;
}

export interface Asset extends Base {
  id: string;
  name: string;
  type: AssetType;
  kind: string;
  environment: "prod" | "stage" | "dev";
  location: string;
  status: Health;
  criticality: 1 | 2 | 3 | 4 | 5;
  owner: string;
  ip: string;
  source: string;
  service: string;
  cpu: number;
  memory: number;
  disk: number;
  availability30d: number;
  /** Type-specific metrics (latency, packet loss, QPS, p95, cost ...). */
  metrics: Record<string, number>;
}

export interface Service extends Base {
  id: string;
  name: string;
  tier: 1 | 2 | 3;
  sloTarget: number;
  attainment30d: number;
  status: Health;
  owner: string;
  assetIds: string[];
  breaches30d: number;
}

export type AlertStatus = "new" | "acknowledged" | "in_progress" | "resolved" | "suppressed";

export interface Alert extends Base {
  id: string;
  domain: "noc" | "soc";
  title: string;
  severity: Severity;
  status: AlertStatus;
  source: string;
  assetId: string;
  assetName: string;
  service: string;
  createdAt: string;
  count: number;
  groupId: string | null;
  technique: string | null;
}

export interface CorrelationGroup extends Base {
  id: string;
  title: string;
  rule: string;
  confidence: number;
  alertIds: string[];
  incidentId: string | null;
  severity: Severity;
  firstSeen: string;
}

export type IncidentStatus = "open" | "investigating" | "contained" | "mitigated" | "resolved" | "closed";

export interface TimelineEntry {
  at: string;
  kind: "detected" | "alert" | "status" | "comment" | "ai" | "action" | "approval" | "sla";
  actor: string;
  text: string;
}

export interface Hypothesis {
  text: string;
  confidence: number;
  evidence: string[];
}

export interface ResponseStep {
  id: string;
  title: string;
  kind: "manual" | "automated";
  tier: "T0" | "T1" | "T2" | "T3";
  status: "done" | "in_progress" | "pending" | "awaiting_approval" | "skipped";
  owner: string;
}

export interface Incident extends Base {
  id: string;
  number: string;
  domain: "noc" | "soc" | "joint";
  title: string;
  severity: Severity;
  priority: "P1" | "P2" | "P3" | "P4";
  status: IncidentStatus;
  commander: string;
  assignee: string;
  service: string;
  detectedAt: string;
  acknowledgedAt: string | null;
  resolvedAt: string | null;
  slaAckMinutes: number;
  slaResolveMinutes: number;
  alertIds: string[];
  assetIds: string[];
  techniques: string[];
  summary: string;
  rca: { summary: string; hypotheses: Hypothesis[]; gaps: string[] };
  steps: ResponseStep[];
  timeline: TimelineEntry[];
}

export interface SiemEvent extends Base {
  id: string;
  time: string;
  source: string;
  category: string;
  action: string;
  outcome: "success" | "failure" | "blocked";
  user: string;
  host: string;
  srcIp: string;
  dstIp: string;
  severity: Severity;
  rule: string;
  technique: string | null;
}

export interface ProcessNode {
  pid: number;
  name: string;
  cmd: string;
  children: ProcessNode[];
}

export interface EdrDetection extends Base {
  id: string;
  time: string;
  host: string;
  user: string;
  product: string;
  tactic: string;
  technique: string;
  severity: Severity;
  status: "new" | "investigating" | "contained" | "false_positive" | "resolved";
  sha256: string;
  file: string;
  tree: ProcessNode;
}

export interface Endpoint extends Base {
  host: string;
  os: string;
  agent: string;
  online: boolean;
  isolation: "not_isolated" | "isolation_requested";
  risk: number;
  lastSeen: string;
}

export interface Indicator extends Base {
  id: string;
  type: "ip" | "domain" | "sha256" | "url";
  value: string;
  actor: string;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  feed: string;
  sightings: number;
  tags: string[];
}

export interface ThreatActor {
  name: string;
  motivation: string;
  techniques: string[];
  sectors: string[];
  description: string;
}

export interface Vulnerability extends Base {
  id: string;
  cve: string;
  title: string;
  product: string;
  assetId: string;
  assetName: string;
  cvss: number;
  epss: number;
  kev: boolean;
  exposure: "internet" | "internal";
  status: "open" | "fixed" | "accepted" | "in_progress";
  severity: Severity;
  firstFound: string;
  dueDate: string;
  source: string;
  risk: number;
}

export interface VaptEngagement extends Base {
  id: string;
  name: string;
  type: "External network" | "Internal network" | "Web application" | "Cloud configuration" | "Red team";
  scope: string;
  tester: string;
  status: "planned" | "in_progress" | "reported" | "retest";
  start: string;
  end: string;
}

export interface VaptFinding extends Base {
  id: string;
  engagementId: string;
  title: string;
  severity: Severity;
  cvss: number;
  cwe: string;
  asset: string;
  status: "open" | "remediated" | "risk_accepted" | "retest_passed" | "retest_failed";
  dueDate: string;
}

export interface Hunt extends Base {
  id: string;
  name: string;
  hypothesis: string;
  technique: string;
  dataSources: string[];
  origin: "ai_suggested" | "analyst";
  status: "draft" | "scheduled" | "completed";
  lastRun: string | null;
  matches: number;
  query: string;
  rationale: string;
  evidence: string[];
}

export interface PlaybookStep {
  name: string;
  action: string;
  tier: "T0" | "T1" | "T2" | "T3";
}

export interface Playbook extends Base {
  id: string;
  name: string;
  domain: "noc" | "soc" | "joint";
  trigger: string;
  version: number;
  status: "published" | "draft";
  steps: PlaybookStep[];
  runs30d: number;
}

export interface PlaybookRun extends Base {
  id: string;
  playbookId: string;
  playbook: string;
  incident: string;
  startedAt: string;
  status: "succeeded" | "failed" | "awaiting_approval" | "running";
  mode: "simulate";
  steps: { name: string; result: "simulated_ok" | "simulated_failed" | "pending_approval" | "skipped" }[];
}

export interface ApprovalRequest extends Base {
  id: string;
  action: string;
  tier: "T2" | "T3";
  target: string;
  incident: string;
  requestedBy: string;
  requestedAt: string;
  expiresAt: string;
  approvalsNeeded: number;
  approvals: number;
  status: "pending" | "approved" | "denied" | "expired";
}

export interface DailyPoint {
  date: string;
  value: number;
}

export interface Kpis {
  mttaMinutes: DailyPoint[];
  mttrMinutes: DailyPoint[];
  nocAlerts: DailyPoint[];
  socAlerts: DailyPoint[];
  incidentsOpened: DailyPoint[];
  slaAttainment: DailyPoint[];
  automationRate: DailyPoint[];
  criticalVulns: DailyPoint[];
}

export interface DemoDataset {
  tenants: TenantRef[];
  generatedAt: string;
  assets: Asset[];
  services: Service[];
  alerts: Alert[];
  groups: CorrelationGroup[];
  incidents: Incident[];
  siem: SiemEvent[];
  edr: EdrDetection[];
  endpoints: Endpoint[];
  indicators: Indicator[];
  vulns: Vulnerability[];
  engagements: VaptEngagement[];
  vaptFindings: VaptFinding[];
  hunts: Hunt[];
  playbooks: Playbook[];
  runs: PlaybookRun[];
  approvals: ApprovalRequest[];
  kpis: Kpis;
}
