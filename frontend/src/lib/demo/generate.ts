/**
 * Deterministic DEMO data generator. Entities are stable per tenant; timestamps are
 * relative to the current hour so the data looks current. Nothing here comes from a
 * live system, and every record is marked `demo: true`.
 */
import {
  ACTORS,
  CLOUD_REGIONS,
  EDR_SOURCES,
  FEEDS,
  NOC_ALERT_TEMPLATES,
  PEOPLE,
  SERVICE_NAMES,
  SIEM_SOURCES,
  SITES,
  SOC_ALERT_TEMPLATES,
  TEAMS,
  TECHNIQUES,
  VAPT_TESTERS,
  VAPT_TITLES,
  VULN_SOURCES,
  VULN_TITLES,
} from "./reference";
import { createRng, hashSeed, type Rng } from "./rng";
import type {
  Alert,
  ApprovalRequest,
  Asset,
  AssetType,
  CorrelationGroup,
  DailyPoint,
  DemoDataset,
  EdrDetection,
  Endpoint,
  Health,
  Hunt,
  Incident,
  IncidentStatus,
  Indicator,
  Playbook,
  PlaybookRun,
  ProcessNode,
  ResponseStep,
  Service,
  Severity,
  SiemEvent,
  TenantRef,
  TimelineEntry,
  VaptEngagement,
  VaptFinding,
  Vulnerability,
} from "./types";

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

export function anchorHour(now = Date.now()): number {
  return Math.floor(now / HOUR) * HOUR;
}

const iso = (ms: number) => new Date(ms).toISOString();

function prefixOf(tenant: TenantRef): string {
  const letters = tenant.name.replace(/[^A-Za-z]/g, "").toUpperCase();
  return (letters.slice(0, 3) || "TEN").padEnd(3, "X");
}

/** Recent-weighted offset in ms, up to `maxMs` ago. */
function ago(r: Rng, maxMs: number): number {
  return Math.floor(Math.pow(r.next(), 1.8) * maxMs);
}

const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function maxSeverity(list: Severity[]): Severity {
  return list.reduce<Severity>((m, s) => (SEV_RANK[s] < SEV_RANK[m] ? s : m), "info");
}

// ---------------------------------------------------------------- assets
const ASSET_PLAN: Record<AssetType, { count: number; kinds: string[] }> = {
  server: { count: 40, kinds: ["Linux VM", "Windows Server", "Kubernetes node", "Bare-metal host"] },
  network: { count: 22, kinds: ["Core switch", "Distribution switch", "Firewall", "WAN router", "Load balancer", "Wireless controller"] },
  cloud: { count: 24, kinds: ["EC2 instance", "Lambda function", "Azure VM", "AKS cluster", "GCE instance", "Object storage bucket"] },
  application: { count: 12, kinds: ["Web frontend", "REST API", "Message consumer", "Batch job"] },
  database: { count: 12, kinds: ["PostgreSQL", "SQL Server", "MySQL", "Redis cache"] },
};

const SHORT: Record<string, string> = {
  "Linux VM": "lnx", "Windows Server": "win", "Kubernetes node": "k8s", "Bare-metal host": "bm",
  "Core switch": "core-sw", "Distribution switch": "dist-sw", Firewall: "fw", "WAN router": "rtr",
  "Load balancer": "lb", "Wireless controller": "wlc", "EC2 instance": "ec2", "Lambda function": "fn",
  "Azure VM": "azvm", "AKS cluster": "aks", "GCE instance": "gce", "Object storage bucket": "bucket",
  "Web frontend": "web", "REST API": "api", "Message consumer": "worker", "Batch job": "batch",
  PostgreSQL: "pg", "SQL Server": "mssql", MySQL: "mysql", "Redis cache": "redis",
};

function health(r: Rng): Health {
  return r.weighted([["healthy", 80], ["degraded", 12], ["down", 4], ["maintenance", 4]] as const);
}

function assetMetrics(r: Rng, type: AssetType, status: Health): Record<string, number> {
  const bad = status === "degraded" || status === "down";
  switch (type) {
    case "network":
      return {
        bandwidthUtil: r.float(bad ? 70 : 10, bad ? 98 : 70),
        packetLoss: r.float(0, bad ? 4 : 0.3, 2),
        latencyMs: r.float(1, bad ? 60 : 12),
        interfacesDown: bad ? r.int(1, 4) : 0,
        interfaces: r.int(24, 96),
      };
    case "cloud":
      return { monthlyCost: r.int(40, 4200), utilisation: r.float(bad ? 75 : 10, bad ? 99 : 70) };
    case "application":
      return {
        p95Ms: r.int(bad ? 700 : 80, bad ? 2400 : 450),
        errorRate: r.float(0, bad ? 6 : 0.8, 2),
        rps: r.int(20, 2400),
        apdex: r.float(bad ? 0.6 : 0.88, bad ? 0.84 : 0.99, 2),
      };
    case "database":
      return {
        connections: r.int(20, bad ? 500 : 300),
        qps: r.int(50, 9000),
        replicationLagS: r.float(0, bad ? 90 : 3),
        slowQueries: r.int(0, bad ? 140 : 12),
      };
    default:
      return { loadAvg: r.float(0.1, bad ? 18 : 4, 2), uptimeDays: r.int(1, 400) };
  }
}

function genAssets(r: Rng, tenant: TenantRef, p: string): Asset[] {
  const assets: Asset[] = [];
  for (const type of Object.keys(ASSET_PLAN) as AssetType[]) {
    const plan = ASSET_PLAN[type];
    for (let i = 1; i <= plan.count; i++) {
      const kind = r.pick(plan.kinds);
      const status = health(r);
      const bad = status === "degraded" || status === "down";
      const cloud = type === "cloud";
      assets.push({
        demo: true,
        tenant,
        id: `${p.toLowerCase()}-${type}-${i}`,
        name: `${p.toLowerCase()}-${SHORT[kind]}-${String(i).padStart(2, "0")}`,
        type,
        kind,
        environment: r.weighted([["prod", 70], ["stage", 20], ["dev", 10]] as const),
        location: cloud ? r.pick(CLOUD_REGIONS) : r.pick(SITES),
        status,
        criticality: r.weighted([[5, 10], [4, 25], [3, 35], [2, 20], [1, 10]] as const),
        owner: type === "network" ? "Network Eng" : type === "database" ? "Database Ops" : cloud ? "Cloud Ops" : r.pick(TEAMS),
        ip: `10.${r.int(10, 60)}.${r.int(0, 255)}.${r.int(2, 254)}`,
        source: cloud
          ? r.pick(["AWS CloudWatch", "Azure Monitor", "Google Cloud Ops"])
          : type === "network"
            ? "SolarWinds"
            : type === "application"
              ? "Datadog"
              : r.pick(["Prometheus", "Datadog", "SolarWinds"]),
        service: "",
        cpu: status === "down" ? 0 : r.float(bad ? 80 : 5, bad ? 99 : 70),
        memory: status === "down" ? 0 : r.float(bad ? 75 : 20, bad ? 98 : 80),
        disk: r.float(15, bad ? 96 : 85),
        availability30d: r.float(bad ? 97.5 : 99.6, bad ? 99.6 : 100, 3),
        metrics: assetMetrics(r, type, status),
      });
    }
  }
  return assets;
}

function genServices(r: Rng, tenant: TenantRef, p: string, assets: Asset[]): Service[] {
  const pool = [...assets];
  return SERVICE_NAMES.map((name, i) => {
    const members = r.sample(pool, r.int(8, 14));
    for (const a of members) a.service = name;
    const tier = (i < 3 ? 1 : i < 6 ? 2 : 3) as 1 | 2 | 3;
    const sloTarget = tier === 1 ? 99.9 : tier === 2 ? 99.5 : 99.0;
    const worst = members.some((a) => a.status === "down") ? "down" : members.some((a) => a.status === "degraded") ? "degraded" : "healthy";
    const attainment = Number((sloTarget + r.float(-0.6, 0.09, 3)).toFixed(3));
    return {
      demo: true as const,
      tenant,
      id: `${p.toLowerCase()}-svc-${i + 1}`,
      name,
      tier,
      sloTarget,
      attainment30d: Math.min(100, attainment),
      status: worst as Health,
      owner: r.pick(TEAMS),
      assetIds: members.map((a) => a.id),
      breaches30d: attainment < sloTarget ? r.int(1, 4) : 0,
    };
  }).map((s) => {
    for (const a of assets) if (!a.service) a.service = "Shared infrastructure";
    return s;
  });
}

// ---------------------------------------------------------------- alerts & correlation
function genNocAlerts(r: Rng, tenant: TenantRef, p: string, assets: Asset[], now: number): Alert[] {
  const out: Alert[] = [];
  for (let i = 1; i <= 140; i++) {
    const t = r.pick(NOC_ALERT_TEMPLATES);
    const candidates = assets.filter((a) => a.type === t.type);
    const asset = r.pick(candidates);
    out.push({
      demo: true,
      tenant,
      id: `${p.toLowerCase()}-na-${i}`,
      domain: "noc",
      title: t.title,
      severity: t.severity as Severity,
      status: r.weighted([["new", 25], ["acknowledged", 20], ["in_progress", 15], ["resolved", 35], ["suppressed", 5]] as const),
      source: asset.source,
      assetId: asset.id,
      assetName: asset.name,
      service: asset.service,
      createdAt: iso(now - ago(r, 3 * DAY)),
      count: r.weighted([[1, 50], [r.int(2, 9), 35], [r.int(10, 60), 15]] as const),
      groupId: null,
      technique: null,
    });
  }
  return out;
}

function genSocAlerts(r: Rng, tenant: TenantRef, p: string, assets: Asset[], now: number): Alert[] {
  const hosts = assets.filter((a) => a.type === "server" || a.type === "cloud");
  const out: Alert[] = [];
  for (let i = 1; i <= 120; i++) {
    const t = r.pick(SOC_ALERT_TEMPLATES);
    const asset = r.pick(hosts);
    out.push({
      demo: true,
      tenant,
      id: `${p.toLowerCase()}-sa-${i}`,
      domain: "soc",
      title: t.title,
      severity: t.severity as Severity,
      status: r.weighted([["new", 30], ["acknowledged", 15], ["in_progress", 20], ["resolved", 30], ["suppressed", 5]] as const),
      source: r.pick([...SIEM_SOURCES, ...EDR_SOURCES]),
      assetId: asset.id,
      assetName: asset.name,
      service: asset.service,
      createdAt: iso(now - ago(r, 3 * DAY)),
      count: r.int(1, 12),
      groupId: null,
      technique: t.technique,
    });
  }
  return out;
}

function genGroups(r: Rng, tenant: TenantRef, p: string, alerts: Alert[], now: number): CorrelationGroup[] {
  const rules = [
    "Same service within 10 minutes",
    "Topology adjacency (upstream device)",
    "Shared observable (host and user)",
    "Same asset, repeated signal",
  ];
  const groups: CorrelationGroup[] = [];
  const byService = new Map<string, Alert[]>();
  for (const a of alerts) if (a.status !== "resolved") byService.set(a.service, [...(byService.get(a.service) ?? []), a]);
  let n = 1;
  for (const [service, list] of byService) {
    if (list.length < 3 || n > 12) continue;
    const members = r.sample(list, Math.min(list.length, r.int(3, 8)));
    const id = `${p.toLowerCase()}-grp-${n++}`;
    for (const m of members) m.groupId = id;
    const domain = members[0].domain;
    groups.push({
      demo: true,
      tenant,
      id,
      title: domain === "soc" ? `Suspicious activity cluster on ${service}` : `${service} degradation`,
      rule: domain === "soc" ? rules[2] : r.pick(rules.filter((x) => x !== rules[2])),
      confidence: r.float(0.62, 0.97, 2),
      alertIds: members.map((m) => m.id),
      incidentId: null,
      severity: maxSeverity(members.map((m) => m.severity)),
      firstSeen: iso(Math.min(...members.map((m) => Date.parse(m.createdAt))) || now),
    });
  }
  return groups;
}

// ---------------------------------------------------------------- incidents
const SLA: Record<string, [number, number]> = { P1: [15, 240], P2: [30, 480], P3: [120, 1440], P4: [480, 4320] };

function nocSteps(r: Rng): ResponseStep[] {
  return [
    { id: "s1", title: "Acknowledge and assign commander", kind: "manual", tier: "T0", status: "done", owner: r.pick(PEOPLE) },
    { id: "s2", title: "Enrich with topology and recent changes", kind: "automated", tier: "T0", status: "done", owner: "Playbook" },
    { id: "s3", title: "Open ServiceNow incident (sandbox)", kind: "automated", tier: "T1", status: "done", owner: "Playbook" },
    { id: "s4", title: "Fail over to secondary path", kind: "automated", tier: "T2", status: r.pick(["awaiting_approval", "done", "pending"] as const), owner: "Approval: 1 approver" },
    { id: "s5", title: "Verify service SLO recovered", kind: "manual", tier: "T0", status: "pending", owner: r.pick(PEOPLE) },
  ];
}

function socSteps(r: Rng): ResponseStep[] {
  return [
    { id: "s1", title: "Triage and scope affected entities", kind: "manual", tier: "T0", status: "done", owner: r.pick(PEOPLE) },
    { id: "s2", title: "Enrich indicators with threat intelligence", kind: "automated", tier: "T0", status: "done", owner: "Playbook" },
    { id: "s3", title: "Disable compromised user sessions", kind: "automated", tier: "T2", status: r.pick(["done", "awaiting_approval"] as const), owner: "Approval: 1 approver" },
    { id: "s4", title: "Isolate affected host (EDR)", kind: "automated", tier: "T3", status: r.pick(["awaiting_approval", "pending"] as const), owner: "Approval: 2 approvers" },
    { id: "s5", title: "Collect forensic triage package", kind: "manual", tier: "T1", status: "pending", owner: r.pick(PEOPLE) },
    { id: "s6", title: "Eradicate and reset credentials", kind: "manual", tier: "T1", status: "pending", owner: r.pick(PEOPLE) },
  ];
}

function genIncidents(
  r: Rng,
  tenant: TenantRef,
  p: string,
  alerts: Alert[],
  groups: CorrelationGroup[],
  assets: Asset[],
  now: number,
): Incident[] {
  const incidents: Incident[] = [];
  const statuses: [IncidentStatus, number][] = [
    ["open", 15], ["investigating", 25], ["contained", 10], ["mitigated", 10], ["resolved", 25], ["closed", 15],
  ];
  const assetById = new Map(assets.map((a) => [a.id, a]));
  for (let i = 0; i < 36; i++) {
    const domain = r.weighted([["noc", 55], ["soc", 35], ["joint", 10]] as const);
    const pool = alerts.filter((a) => a.domain === (domain === "joint" ? r.pick(["noc", "soc"] as const) : domain));
    const group = r.chance(0.5) ? groups.find((g) => !g.incidentId && pool.some((a) => a.id === g.alertIds[0])) : undefined;
    const members = group ? alerts.filter((a) => group.alertIds.includes(a.id)) : r.sample(pool, r.int(1, 4));
    const severity = maxSeverity(members.map((m) => m.severity));
    const priority = severity === "critical" ? "P1" : severity === "high" ? "P2" : severity === "medium" ? "P3" : "P4";
    const detected = now - ago(r, 20 * DAY) - 30 * MIN;
    const status = r.weighted(statuses);
    const [ackSla, resSla] = SLA[priority];
    const ackMin = r.chance(0.85) ? r.int(2, ackSla) : r.int(ackSla + 1, ackSla * 3);
    const resolved = status === "resolved" || status === "closed";
    const resMin = r.chance(0.8) ? r.int(Math.max(ackMin + 10, 30), resSla) : r.int(resSla + 1, resSla * 2);
    // Narrative follows the alerts actually involved (a joint incident can start on either side).
    const story: "noc" | "soc" = members[0].domain;
    const number = `${p}-INC-${String(1001 + i)}`;
    const id = `${p.toLowerCase()}-inc-${1001 + i}`;
    if (group) group.incidentId = id;
    const primary = assetById.get(members[0].assetId);
    const techniques = [...new Set(members.map((m) => m.technique).filter((t): t is string => !!t))];
    const commander = r.pick(PEOPLE);
    const title =
      domain === "soc"
        ? `${members[0].title} on ${members[0].assetName}`
        : domain === "joint"
          ? `Service outage with suspicious activity: ${members[0].service}`
          : `${members[0].service}: ${members[0].title.toLowerCase()}`;

    const timeline: TimelineEntry[] = [
      { at: iso(detected), kind: "detected", actor: "Correlation engine", text: `${members.length} alert(s) correlated (${group?.rule ?? "manual grouping"}).` },
      ...members.slice(0, 3).map((m, k) => ({ at: iso(detected + k * MIN), kind: "alert" as const, actor: m.source, text: `${m.title} on ${m.assetName}` })),
      { at: iso(detected + ackMin * MIN), kind: "status", actor: commander, text: "Acknowledged; commander assigned." },
      { at: iso(detected + (ackMin + 4) * MIN), kind: "ai", actor: "AI copilot (demo)", text: "Summary and root-cause hypotheses drafted with cited evidence." },
      {
        at: iso(detected + (ackMin + 12) * MIN),
        kind: "action",
        actor: "Playbook",
        text: story === "noc" ? "Created ServiceNow incident (sandbox, simulated)." : "Enriched 4 indicators with threat intelligence.",
      },
    ];
    if (story === "soc") {
      timeline.push({
        at: iso(detected + (ackMin + 20) * MIN),
        kind: "approval",
        actor: r.pick(PEOPLE),
        text: "Requested T3 action 'Isolate host' (simulate mode); awaiting 2 approvers.",
      });
    }
    if (resolved) timeline.push({ at: iso(detected + resMin * MIN), kind: "status", actor: commander, text: "Resolved; post-incident review drafted." });
    if (resMin > resSla && resolved) timeline.push({ at: iso(detected + resSla * MIN), kind: "sla", actor: "SLA monitor", text: `Resolution SLA (${resSla} min) breached.` });

    const evidence = members.map((m) => m.id);
    const hypotheses =
      story === "soc"
        ? [
            { text: `Initial access via ${TECHNIQUES[techniques[0] ?? "T1566"]?.name.toLowerCase() ?? "phishing"} on ${members[0].assetName}.`, confidence: r.float(0.55, 0.82, 2), evidence: evidence.slice(0, 2) },
            { text: "Activity is consistent with hands-on-keyboard follow-up rather than commodity malware.", confidence: r.float(0.35, 0.6, 2), evidence: evidence.slice(-1) },
          ]
        : [
            { text: `Upstream dependency failure on ${primary?.name ?? "a shared component"} propagated to ${members[0].service}.`, confidence: r.float(0.6, 0.88, 2), evidence: evidence.slice(0, 2) },
            { text: "Capacity saturation during the daily batch window contributed to the impact.", confidence: r.float(0.3, 0.55, 2), evidence: evidence.slice(-1) },
          ];
    incidents.push({
      demo: true,
      tenant,
      id,
      number,
      domain,
      title,
      severity,
      priority,
      status,
      commander,
      assignee: r.pick(PEOPLE),
      service: members[0].service,
      detectedAt: iso(detected),
      acknowledgedAt: iso(detected + ackMin * MIN),
      resolvedAt: resolved ? iso(detected + resMin * MIN) : null,
      slaAckMinutes: ackSla,
      slaResolveMinutes: resSla,
      alertIds: evidence,
      assetIds: [...new Set(members.map((m) => m.assetId))],
      techniques,
      summary:
        story === "noc"
          ? `${members.length} correlated alerts on ${members[0].service}. Primary impact on ${primary?.name ?? "infrastructure"}.`
          : `${members.length} security alerts linked by shared host and user. Techniques: ${techniques.join(", ") || "n/a"}.`,
      rca: {
        summary: "AI-drafted from the cited alerts. Hypotheses must be confirmed by an engineer.",
        hypotheses,
        gaps: ["No change records found for the affected assets in the last 24 h (no ITSM connector configured yet)."],
      },
      steps: story === "noc" ? nocSteps(r) : socSteps(r),
      timeline: timeline.sort((a, b) => a.at.localeCompare(b.at)),
    });
  }
  return incidents.sort((a, b) => b.detectedAt.localeCompare(a.detectedAt));
}

// ---------------------------------------------------------------- SOC telemetry
const USERS = ["j.doe", "a.smith", "m.garcia", "s.chen", "svc-backup", "k.novak", "r.ali", "admin.ops", "t.berg"];

function docIp(r: Rng): string {
  return `${r.pick(["198.51.100", "203.0.113", "192.0.2"])}.${r.int(1, 254)}`;
}

function genSiem(r: Rng, tenant: TenantRef, p: string, assets: Asset[], now: number): SiemEvent[] {
  const hosts = assets.filter((a) => a.type === "server").map((a) => a.name);
  const kinds = [
    { category: "Authentication", action: "Sign-in", rule: "Sign-in from unfamiliar location", technique: "T1078" },
    { category: "Authentication", action: "Failed sign-in", rule: "Password spray pattern", technique: "T1110" },
    { category: "Process", action: "Process created", rule: "Encoded PowerShell", technique: "T1059" },
    { category: "Network", action: "Outbound connection", rule: "Connection to rare domain", technique: "T1071" },
    { category: "Network", action: "Inbound connection", rule: "Scan from external address", technique: "T1046" },
    { category: "Cloud audit", action: "Role assignment", rule: "Privileged role granted", technique: "T1098" },
    { category: "Email", action: "Message delivered", rule: "Lure with credential link", technique: "T1566" },
    { category: "File", action: "Archive created", rule: "Large archive in user profile", technique: "T1560" },
  ];
  return Array.from({ length: 350 }, (_, i) => {
    const k = r.pick(kinds);
    const outcome = r.weighted([["success", 60], ["failure", 30], ["blocked", 10]] as const);
    return {
      demo: true as const,
      tenant,
      id: `${p.toLowerCase()}-ev-${i + 1}`,
      time: iso(now - ago(r, 2 * DAY)),
      source: r.pick(SIEM_SOURCES),
      category: k.category,
      action: k.action,
      outcome,
      user: r.pick(USERS),
      host: r.pick(hosts),
      srcIp: k.category === "Network" && k.action === "Inbound connection" ? docIp(r) : `10.${r.int(10, 60)}.${r.int(0, 255)}.${r.int(2, 254)}`,
      dstIp: k.action === "Outbound connection" ? docIp(r) : `10.${r.int(10, 60)}.${r.int(0, 255)}.${r.int(2, 254)}`,
      severity: r.weighted([["info", 45], ["low", 25], ["medium", 18], ["high", 9], ["critical", 3]] as const),
      rule: k.rule,
      technique: r.chance(0.7) ? k.technique : null,
    };
  }).sort((a, b) => b.time.localeCompare(a.time));
}

function processTree(r: Rng): ProcessNode {
  const pid = () => r.int(1000, 9999);
  const parent = r.pick(["winword.exe", "outlook.exe", "explorer.exe", "w3wp.exe"]);
  return {
    pid: pid(),
    name: parent,
    cmd: `C:\\Program Files\\${parent}`,
    children: [
      {
        pid: pid(),
        name: "powershell.exe",
        cmd: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA… (demo)",
        children: [
          { pid: pid(), name: "rundll32.exe", cmd: "rundll32.exe C:\\Users\\Public\\upd.dll,Start (demo)", children: [] },
          { pid: pid(), name: "whoami.exe", cmd: "whoami /all", children: [] },
        ],
      },
    ],
  };
}

function genEndpoints(r: Rng, tenant: TenantRef, p: string, now: number): Endpoint[] {
  return Array.from({ length: 60 }, (_, i) => ({
    demo: true as const,
    tenant,
    host: `${p.toLowerCase()}-ws-${String(i + 1).padStart(3, "0")}`,
    os: r.pick(["Windows 11 23H2", "Windows 10 22H2", "macOS 15", "Ubuntu 24.04"]),
    agent: r.pick(EDR_SOURCES),
    online: r.chance(0.9),
    isolation: "not_isolated" as const,
    risk: r.int(0, 100),
    lastSeen: iso(now - ago(r, 6 * HOUR)),
  }));
}

function genEdr(r: Rng, tenant: TenantRef, p: string, endpoints: Endpoint[], now: number): EdrDetection[] {
  return Array.from({ length: 50 }, (_, i) => {
    const t = r.pick(SOC_ALERT_TEMPLATES);
    return {
      demo: true as const,
      tenant,
      id: `${p.toLowerCase()}-det-${i + 1}`,
      time: iso(now - ago(r, 4 * DAY)),
      host: r.pick(endpoints).host,
      user: r.pick(USERS),
      product: r.pick(EDR_SOURCES),
      tactic: TECHNIQUES[t.technique]?.tactic ?? "Execution",
      technique: t.technique,
      severity: t.severity as Severity,
      status: r.weighted([["new", 30], ["investigating", 25], ["contained", 10], ["false_positive", 15], ["resolved", 20]] as const),
      sha256: r.hex(64),
      file: r.pick(["upd.dll", "invoice_8841.docm", "svchost_.exe", "setup_tool.ps1", "7z.exe"]),
      tree: processTree(r),
    };
  }).sort((a, b) => b.time.localeCompare(a.time));
}

function genIndicators(r: Rng, tenant: TenantRef, p: string, now: number): Indicator[] {
  return Array.from({ length: 70 }, (_, i) => {
    const type = r.weighted([["ip", 35], ["domain", 30], ["sha256", 25], ["url", 10]] as const);
    const actor = r.pick(ACTORS);
    const word = r.pick(["cdn-sync", "update-check", "login-portal", "files-share", "telemetry", "auth-verify"]);
    const value =
      type === "ip" ? docIp(r)
      : type === "domain" ? `${word}-${r.hex(4)}.example`
      : type === "url" ? `https://${word}.example/${r.hex(6)}`
      : r.hex(64);
    const first = now - ago(r, 60 * DAY) - DAY;
    return {
      demo: true as const,
      tenant,
      id: `${p.toLowerCase()}-ioc-${i + 1}`,
      type,
      value,
      actor: actor.name,
      confidence: r.int(40, 98),
      firstSeen: iso(first),
      lastSeen: iso(Math.min(now, first + ago(r, 30 * DAY))),
      feed: r.pick(FEEDS),
      sightings: r.weighted([[0, 55], [r.int(1, 5), 35], [r.int(6, 40), 10]] as const),
      tags: r.sample(["c2", "phishing", "ransomware", "credential-theft", "scanner", "exfiltration"], r.int(1, 2)),
    };
  });
}

function genVulns(r: Rng, tenant: TenantRef, p: string, assets: Asset[], now: number): Vulnerability[] {
  const targets = assets.filter((a) => a.type !== "application");
  return Array.from({ length: 200 }, (_, i) => {
    const v = r.pick(VULN_TITLES);
    const asset = r.pick(targets);
    const cvss = r.float(3.1, 10, 1);
    const kev = cvss >= 8 && r.chance(0.25);
    const epss = Number((kev ? r.float(0.3, 0.97, 3) : Math.pow(r.next(), 3) * 0.6).toFixed(3));
    const exposure: Vulnerability["exposure"] = asset.type === "network" || r.chance(0.2) ? "internet" : "internal";
    const severity: Severity = cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : "low";
    const found = now - ago(r, 90 * DAY);
    const dueDays = severity === "critical" ? 7 : severity === "high" ? 30 : severity === "medium" ? 90 : 180;
    const risk = Math.round(Math.min(100, cvss * 6 + epss * 25 + (kev ? 15 : 0) + (exposure === "internet" ? 10 : 0) + asset.criticality * 2));
    return {
      demo: true as const,
      tenant,
      id: `${p.toLowerCase()}-vuln-${i + 1}`,
      cve: `CVE-DEMO-2026-${String(1000 + r.int(0, 8999))}`,
      title: v.title,
      product: v.product,
      assetId: asset.id,
      assetName: asset.name,
      cvss,
      epss,
      kev,
      exposure,
      status: r.weighted([["open", 60], ["in_progress", 15], ["fixed", 20], ["accepted", 5]] as const),
      severity,
      firstFound: iso(found),
      dueDate: iso(found + dueDays * DAY),
      source: r.pick(VULN_SOURCES),
      risk,
    };
  }).sort((a, b) => b.risk - a.risk);
}

function genVapt(r: Rng, tenant: TenantRef, p: string, assets: Asset[], now: number): [VaptEngagement[], VaptFinding[]] {
  const types: VaptEngagement["type"][] = ["External network", "Web application", "Cloud configuration", "Internal network"];
  const engagements = types.map((type, i) => {
    const start = now - r.int(5, 120) * DAY;
    return {
      demo: true as const,
      tenant,
      id: `${p.toLowerCase()}-pt-${i + 1}`,
      name: `${type} assessment ${new Date(start).getUTCFullYear()}-Q${Math.floor(new Date(start).getUTCMonth() / 3) + 1}`,
      type,
      scope: type === "Web application" ? "Customer Portal, Payments API" : type === "Cloud configuration" ? "Production cloud accounts" : `${r.int(40, 400)} hosts`,
      tester: r.pick(VAPT_TESTERS),
      status: r.pick(["planned", "in_progress", "reported", "retest"] as const),
      start: iso(start),
      end: iso(start + r.int(5, 15) * DAY),
    };
  });
  const findings: VaptFinding[] = [];
  let n = 1;
  for (const e of engagements) {
    if (e.status === "planned") continue;
    for (let k = 0; k < r.int(6, 12); k++) {
      const f = r.pick(VAPT_TITLES);
      const cvss = r.float(3.5, 9.8, 1);
      findings.push({
        demo: true,
        tenant,
        id: `${p.toLowerCase()}-ptf-${n++}`,
        engagementId: e.id,
        title: f.title,
        severity: cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : "low",
        cvss,
        cwe: f.cwe,
        asset: r.pick(assets).name,
        status: r.weighted([["open", 45], ["remediated", 25], ["risk_accepted", 5], ["retest_passed", 15], ["retest_failed", 10]] as const),
        dueDate: iso(Date.parse(e.end) + r.int(14, 60) * DAY),
      });
    }
  }
  return [engagements, findings];
}

function genHunts(r: Rng, tenant: TenantRef, p: string, now: number): Hunt[] {
  const base: Omit<Hunt, "demo" | "tenant" | "id" | "status" | "lastRun" | "matches" | "origin">[] = [
    {
      name: "Encoded PowerShell launched by Office",
      hypothesis: "Phishing payloads spawn encoded PowerShell from Office processes.",
      technique: "T1059",
      dataSources: ["EDR process events", "SIEM"],
      query: "process where parent.name in ('winword.exe','excel.exe') and name == 'powershell.exe' and cmdline contains '-enc'",
      rationale: "Three recent alerts share this parent/child pattern; widen to all hosts for 14 days.",
      evidence: [],
    },
    {
      name: "MFA fatigue followed by successful sign-in",
      hypothesis: "Repeated MFA prompts precede a successful sign-in from a new location.",
      technique: "T1621",
      dataSources: ["Identity sign-in logs"],
      query: "signin | where mfa_prompts > 8 within 10m | join success from new_country within 30m",
      rationale: "Copper Wasp (demo) uses this technique; two users had bursts of prompts this week.",
      evidence: [],
    },
    {
      name: "Rare outbound destinations from servers",
      hypothesis: "Compromised servers beacon to destinations no other host contacts.",
      technique: "T1071",
      dataSources: ["Firewall", "DNS"],
      query: "network where direction == 'outbound' and host.type == 'server' | stats dcount(host) by domain | where dcount == 1",
      rationale: "Beaconing alerts on two servers; look for siblings with lower volume.",
      evidence: [],
    },
    {
      name: "Shadow copy deletion",
      hypothesis: "Ransomware operators remove shadow copies before encryption.",
      technique: "T1490",
      dataSources: ["EDR process events"],
      query: "process where name in ('vssadmin.exe','wmic.exe') and cmdline contains 'delete shadows'",
      rationale: "High-impact precursor; worth a scheduled hunt across all endpoints.",
      evidence: [],
    },
    {
      name: "Service accounts used interactively",
      hypothesis: "Attackers reuse service account credentials for interactive logons.",
      technique: "T1078",
      dataSources: ["Windows security events"],
      query: "logon where account startswith 'svc-' and logon_type in (2, 10)",
      rationale: "Analyst hypothesis from last month's internal pentest findings.",
      evidence: [],
    },
    {
      name: "Large uploads to web storage",
      hypothesis: "Exfiltration to personal cloud storage after archive creation.",
      technique: "T1567",
      dataSources: ["Proxy", "EDR file events"],
      query: "proxy where bytes_out > 500MB and category == 'file-sharing' | join archive_created on user within 2h",
      rationale: "One alert this week; check whether it is isolated.",
      evidence: [],
    },
  ];
  return base.map((h, i) => {
    const status = r.pick(["completed", "scheduled", "draft"] as const);
    return {
      ...h,
      demo: true as const,
      tenant,
      id: `${p.toLowerCase()}-hunt-${i + 1}`,
      origin: i === 4 ? "analyst" : "ai_suggested",
      status,
      lastRun: status === "draft" ? null : iso(now - ago(r, 7 * DAY)),
      matches: status === "completed" ? r.int(0, 23) : 0,
    };
  });
}

function genAutomation(r: Rng, tenant: TenantRef, p: string, incidents: Incident[], now: number): [Playbook[], PlaybookRun[], ApprovalRequest[]] {
  const defs: Omit<Playbook, "demo" | "tenant" | "id" | "runs30d">[] = [
    { name: "Enrich and open ITSM ticket", domain: "noc", trigger: "Incident created (P1–P3)", version: 4, status: "published", steps: [
      { name: "Collect topology and recent changes", action: "cmdb.lookup", tier: "T0" },
      { name: "Create ServiceNow incident", action: "itsm.create_incident", tier: "T1" },
      { name: "Notify on-call", action: "notify.page", tier: "T1" },
    ] },
    { name: "Restart unhealthy service", domain: "noc", trigger: "Health check failing 3× in 5 min", version: 2, status: "published", steps: [
      { name: "Confirm health check failure", action: "monitor.query", tier: "T0" },
      { name: "Restart service", action: "host.restart_service", tier: "T2" },
      { name: "Verify recovery", action: "monitor.query", tier: "T0" },
    ] },
    { name: "Silence alerts during maintenance", domain: "noc", trigger: "Maintenance window starts", version: 1, status: "published", steps: [
      { name: "Create Alertmanager silence", action: "am.create_silence", tier: "T1" },
      { name: "Mute Datadog monitors", action: "dd.mute_monitor", tier: "T1" },
    ] },
    { name: "Phishing triage", domain: "soc", trigger: "User-reported phishing", version: 6, status: "published", steps: [
      { name: "Detonate URLs in sandbox (simulated)", action: "ti.detonate", tier: "T0" },
      { name: "Search mailboxes for same lure", action: "email.search", tier: "T0" },
      { name: "Purge matching messages", action: "email.purge", tier: "T2" },
    ] },
    { name: "Contain compromised host", domain: "soc", trigger: "Critical EDR detection", version: 3, status: "published", steps: [
      { name: "Collect triage package", action: "edr.collect", tier: "T1" },
      { name: "Isolate host", action: "edr.isolate_host", tier: "T3" },
      { name: "Disable user sessions", action: "idp.revoke_sessions", tier: "T2" },
    ] },
    { name: "Block malicious indicator", domain: "soc", trigger: "High-confidence IOC sighted", version: 2, status: "published", steps: [
      { name: "Validate indicator reputation", action: "ti.lookup", tier: "T0" },
      { name: "Block at firewall", action: "fw.block_ip", tier: "T3" },
    ] },
    { name: "Joint outage + security review", domain: "joint", trigger: "Joint incident created", version: 1, status: "draft", steps: [
      { name: "Page NOC and SOC commanders", action: "notify.page", tier: "T1" },
      { name: "Open bridge and timeline", action: "collab.open_bridge", tier: "T1" },
    ] },
  ];
  const playbooks: Playbook[] = defs.map((d, i) => ({ ...d, demo: true, tenant, id: `${p.toLowerCase()}-pb-${i + 1}`, runs30d: d.status === "draft" ? 0 : r.int(2, 60) }));
  const runs: PlaybookRun[] = Array.from({ length: 24 }, (_, i) => {
    const pb = r.pick(playbooks.filter((x) => x.status === "published"));
    const status = r.weighted([["succeeded", 65], ["awaiting_approval", 15], ["failed", 10], ["running", 10]] as const);
    return {
      demo: true as const,
      tenant,
      id: `${p.toLowerCase()}-run-${i + 1}`,
      playbookId: pb.id,
      playbook: pb.name,
      incident: r.pick(incidents).number,
      startedAt: iso(now - ago(r, 10 * DAY)),
      status,
      mode: "simulate" as const,
      steps: pb.steps.map((s, k): PlaybookRun["steps"][number] => ({
        name: s.name,
        result:
          status === "awaiting_approval" && (s.tier === "T2" || s.tier === "T3") ? "pending_approval"
          : status === "failed" && k === pb.steps.length - 1 ? "simulated_failed"
          : status === "running" && k === pb.steps.length - 1 ? "skipped"
          : "simulated_ok",
      })),
    };
  }).sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  const approvals: ApprovalRequest[] = Array.from({ length: 7 }, (_, i) => {
    const t3 = r.chance(0.5);
    const requested = now - ago(r, 2 * HOUR);
    const status = i < 4 ? "pending" : r.pick(["approved", "denied", "expired"] as const);
    return {
      demo: true as const,
      tenant,
      id: `${p.toLowerCase()}-apr-${i + 1}`,
      action: t3 ? r.pick(["edr.isolate_host", "fw.block_ip"]) : r.pick(["host.restart_service", "idp.revoke_sessions", "email.purge"]),
      tier: t3 ? "T3" : "T2",
      target: t3 ? `${p.toLowerCase()}-ws-${String(r.int(1, 60)).padStart(3, "0")}` : `${p.toLowerCase()}-lnx-${String(r.int(1, 40)).padStart(2, "0")}`,
      incident: r.pick(incidents).number,
      requestedBy: r.chance(0.4) ? "AI copilot (demo)" : r.pick(PEOPLE),
      requestedAt: iso(requested),
      expiresAt: iso(requested + 30 * MIN),
      approvalsNeeded: t3 ? 2 : 1,
      approvals: status === "approved" ? (t3 ? 2 : 1) : r.int(0, t3 ? 1 : 0),
      status,
    };
  });
  return [playbooks, runs, approvals];
}

function series(r: Rng, now: number, base: number, spread: number, drift = 0, digits = 0): DailyPoint[] {
  return Array.from({ length: 30 }, (_, i) => {
    const day = now - (29 - i) * DAY;
    const value = Math.max(0, base + drift * i + (r.next() - 0.5) * 2 * spread);
    return { date: new Date(day).toISOString().slice(0, 10), value: Number(value.toFixed(digits)) };
  });
}

// ---------------------------------------------------------------- public API
export function generateTenantDataset(tenant: TenantRef, now: number = anchorHour()): DemoDataset {
  const r = createRng(hashSeed(tenant.id));
  const p = prefixOf(tenant);
  const assets = genAssets(r, tenant, p);
  const services = genServices(r, tenant, p, assets);
  const nocAlerts = genNocAlerts(r, tenant, p, assets, now);
  const socAlerts = genSocAlerts(r, tenant, p, assets, now);
  const alerts = [...nocAlerts, ...socAlerts].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const groups = [...genGroups(r, tenant, p, nocAlerts, now), ...genGroups(r, tenant, `${p}S`, socAlerts, now)];
  const incidents = genIncidents(r, tenant, p, alerts, groups, assets, now);
  const endpoints = genEndpoints(r, tenant, p, now);
  const [engagements, vaptFindings] = genVapt(r, tenant, p, assets, now);
  const [playbooks, runs, approvals] = genAutomation(r, tenant, p, incidents, now);
  return {
    tenants: [tenant],
    generatedAt: iso(now),
    assets,
    services,
    alerts,
    groups,
    incidents,
    siem: genSiem(r, tenant, p, assets, now),
    edr: genEdr(r, tenant, p, endpoints, now),
    endpoints,
    indicators: genIndicators(r, tenant, p, now),
    vulns: genVulns(r, tenant, p, assets, now),
    engagements,
    vaptFindings,
    hunts: genHunts(r, tenant, p, now),
    playbooks,
    runs,
    approvals,
    kpis: {
      mttaMinutes: series(r, now, 14, 5, -0.12),
      mttrMinutes: series(r, now, 210, 60, -1.5),
      nocAlerts: series(r, now, 160, 45),
      socAlerts: series(r, now, 120, 35),
      incidentsOpened: series(r, now, 6, 3),
      slaAttainment: series(r, now, 97.5, 1.6, 0.03, 1).map((d) => ({ ...d, value: Math.min(100, d.value) })),
      automationRate: series(r, now, 32, 6, 0.5, 1),
      criticalVulns: series(r, now, 38, 4, -0.4),
    },
  };
}

function sumSeries(list: DailyPoint[][], average = false): DailyPoint[] {
  if (list.length === 0) return [];
  return list[0].map((point, i) => {
    const total = list.reduce((s, l) => s + (l[i]?.value ?? 0), 0);
    return { date: point.date, value: Number((average ? total / list.length : total).toFixed(1)) };
  });
}

/** Combines per-tenant datasets (MSP "All customers" view). */
export function mergeDatasets(sets: DemoDataset[]): DemoDataset {
  if (sets.length === 1) return sets[0];
  const cat = <K extends keyof DemoDataset>(k: K) => sets.flatMap((s) => s[k] as unknown[]) as DemoDataset[K];
  const k = (key: keyof DemoDataset["kpis"]) => sets.map((s) => s.kpis[key]);
  return {
    tenants: sets.flatMap((s) => s.tenants),
    generatedAt: sets[0]?.generatedAt ?? iso(anchorHour()),
    assets: cat("assets"),
    services: cat("services"),
    alerts: (cat("alerts") as DemoDataset["alerts"]).sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
    groups: cat("groups"),
    incidents: (cat("incidents") as DemoDataset["incidents"]).sort((a, b) => b.detectedAt.localeCompare(a.detectedAt)),
    siem: (cat("siem") as DemoDataset["siem"]).sort((a, b) => b.time.localeCompare(a.time)),
    edr: (cat("edr") as DemoDataset["edr"]).sort((a, b) => b.time.localeCompare(a.time)),
    endpoints: cat("endpoints"),
    indicators: cat("indicators"),
    vulns: (cat("vulns") as DemoDataset["vulns"]).sort((a, b) => b.risk - a.risk),
    engagements: cat("engagements"),
    vaptFindings: cat("vaptFindings"),
    hunts: cat("hunts"),
    playbooks: cat("playbooks"),
    runs: (cat("runs") as DemoDataset["runs"]).sort((a, b) => b.startedAt.localeCompare(a.startedAt)),
    approvals: cat("approvals"),
    kpis: {
      mttaMinutes: sumSeries(k("mttaMinutes"), true),
      mttrMinutes: sumSeries(k("mttrMinutes"), true),
      nocAlerts: sumSeries(k("nocAlerts")),
      socAlerts: sumSeries(k("socAlerts")),
      incidentsOpened: sumSeries(k("incidentsOpened")),
      slaAttainment: sumSeries(k("slaAttainment"), true),
      automationRate: sumSeries(k("automationRate"), true),
      criticalVulns: sumSeries(k("criticalVulns")),
    },
  };
}

/** 48 hourly points for an asset's two headline metrics (deterministic per asset). */
export function assetSeries(asset: Asset, now: number = anchorHour()): { name: string; unit: "percent" | "int" | "decimal"; points: DailyPoint[] }[] {
  const r = createRng(hashSeed(`${asset.id}:series`));
  const bad = asset.status === "degraded" || asset.status === "down";
  const curve = (base: number, spread: number, max: number, spikeAt: number) =>
    Array.from({ length: 48 }, (_, i) => {
      const t = now - (47 - i) * HOUR;
      const diurnal = Math.sin(((i % 24) / 24) * Math.PI * 2 - Math.PI / 2) * spread * 0.6;
      const spike = bad && i >= spikeAt ? spread * 1.6 : 0;
      const v = Math.min(max, Math.max(0, base + diurnal + spike + (r.next() - 0.5) * spread));
      return { date: new Date(t).toISOString(), value: Number(v.toFixed(1)) };
    });
  const spikeAt = r.int(30, 44);
  switch (asset.type) {
    case "network":
      return [
        { name: "Bandwidth utilisation %", unit: "percent", points: curve(asset.metrics.bandwidthUtil * 0.7, 18, 100, spikeAt) },
        { name: "Latency (ms)", unit: "decimal", points: curve(asset.metrics.latencyMs * 0.6, 6, 400, spikeAt) },
      ];
    case "application":
      return [
        { name: "p95 latency (ms)", unit: "int", points: curve(asset.metrics.p95Ms * 0.6, 180, 5000, spikeAt) },
        { name: "Error rate %", unit: "decimal", points: curve(asset.metrics.errorRate * 0.5, 0.8, 100, spikeAt) },
      ];
    case "database":
      return [
        { name: "Active connections", unit: "int", points: curve(asset.metrics.connections * 0.7, 60, 1000, spikeAt) },
        { name: "Replication lag (s)", unit: "decimal", points: curve(asset.metrics.replicationLagS * 0.5, 4, 600, spikeAt) },
      ];
    default:
      return [
        { name: "CPU %", unit: "percent", points: curve(Math.max(5, asset.cpu * 0.7), 15, 100, spikeAt) },
        { name: "Memory %", unit: "percent", points: curve(Math.max(10, asset.memory * 0.8), 8, 100, spikeAt) },
      ];
  }
}
