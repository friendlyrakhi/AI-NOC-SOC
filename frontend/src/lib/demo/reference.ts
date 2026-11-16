/**
 * Reference data for the DEMO generator.
 * - MITRE ATT&CK tactic/technique IDs are the real public Enterprise identifiers (subset).
 * - Threat actors, feeds, testers and people are fictional and marked as demo.
 * - IPs use documentation ranges (RFC 5737); domains use the reserved .example TLD.
 */
import type { ThreatActor } from "./types";

export interface Technique {
  id: string;
  name: string;
}

export interface Tactic {
  id: string;
  name: string;
  techniques: Technique[];
}

export const ATTACK_TACTICS: Tactic[] = [
  {
    id: "TA0001",
    name: "Initial Access",
    techniques: [
      { id: "T1566", name: "Phishing" },
      { id: "T1190", name: "Exploit Public-Facing Application" },
      { id: "T1078", name: "Valid Accounts" },
      { id: "T1133", name: "External Remote Services" },
    ],
  },
  {
    id: "TA0002",
    name: "Execution",
    techniques: [
      { id: "T1059", name: "Command and Scripting Interpreter" },
      { id: "T1204", name: "User Execution" },
      { id: "T1047", name: "Windows Management Instrumentation" },
      { id: "T1053", name: "Scheduled Task/Job" },
    ],
  },
  {
    id: "TA0003",
    name: "Persistence",
    techniques: [
      { id: "T1547", name: "Boot or Logon Autostart Execution" },
      { id: "T1136", name: "Create Account" },
      { id: "T1098", name: "Account Manipulation" },
      { id: "T1543", name: "Create or Modify System Process" },
    ],
  },
  {
    id: "TA0004",
    name: "Privilege Escalation",
    techniques: [
      { id: "T1068", name: "Exploitation for Privilege Escalation" },
      { id: "T1548", name: "Abuse Elevation Control Mechanism" },
      { id: "T1055", name: "Process Injection" },
    ],
  },
  {
    id: "TA0005",
    name: "Defense Evasion",
    techniques: [
      { id: "T1562", name: "Impair Defenses" },
      { id: "T1070", name: "Indicator Removal" },
      { id: "T1027", name: "Obfuscated Files or Information" },
      { id: "T1218", name: "System Binary Proxy Execution" },
    ],
  },
  {
    id: "TA0006",
    name: "Credential Access",
    techniques: [
      { id: "T1110", name: "Brute Force" },
      { id: "T1003", name: "OS Credential Dumping" },
      { id: "T1555", name: "Credentials from Password Stores" },
      { id: "T1621", name: "Multi-Factor Authentication Request Generation" },
    ],
  },
  {
    id: "TA0007",
    name: "Discovery",
    techniques: [
      { id: "T1087", name: "Account Discovery" },
      { id: "T1018", name: "Remote System Discovery" },
      { id: "T1082", name: "System Information Discovery" },
      { id: "T1046", name: "Network Service Discovery" },
    ],
  },
  {
    id: "TA0008",
    name: "Lateral Movement",
    techniques: [
      { id: "T1021", name: "Remote Services" },
      { id: "T1570", name: "Lateral Tool Transfer" },
      { id: "T1550", name: "Use Alternate Authentication Material" },
    ],
  },
  {
    id: "TA0009",
    name: "Collection",
    techniques: [
      { id: "T1560", name: "Archive Collected Data" },
      { id: "T1005", name: "Data from Local System" },
      { id: "T1114", name: "Email Collection" },
    ],
  },
  {
    id: "TA0011",
    name: "Command and Control",
    techniques: [
      { id: "T1071", name: "Application Layer Protocol" },
      { id: "T1105", name: "Ingress Tool Transfer" },
      { id: "T1572", name: "Protocol Tunneling" },
      { id: "T1090", name: "Proxy" },
    ],
  },
  {
    id: "TA0010",
    name: "Exfiltration",
    techniques: [
      { id: "T1041", name: "Exfiltration Over C2 Channel" },
      { id: "T1567", name: "Exfiltration Over Web Service" },
      { id: "T1048", name: "Exfiltration Over Alternative Protocol" },
    ],
  },
  {
    id: "TA0040",
    name: "Impact",
    techniques: [
      { id: "T1486", name: "Data Encrypted for Impact" },
      { id: "T1490", name: "Inhibit System Recovery" },
      { id: "T1489", name: "Service Stop" },
      { id: "T1498", name: "Network Denial of Service" },
    ],
  },
];

export const TECHNIQUES: Record<string, { name: string; tactic: string }> = Object.fromEntries(
  ATTACK_TACTICS.flatMap((t) => t.techniques.map((tech) => [tech.id, { name: tech.name, tactic: t.name }])),
);

export const ACTORS: ThreatActor[] = [
  {
    name: "Ember Lynx (demo)",
    motivation: "Financial",
    techniques: ["T1566", "T1204", "T1059", "T1486", "T1490"],
    sectors: ["Manufacturing", "Logistics"],
    description: "Fictional ransomware crew used in demo scenarios: phishing lures, scripted loaders, encryption.",
  },
  {
    name: "Quiet Heron (demo)",
    motivation: "Espionage",
    techniques: ["T1190", "T1078", "T1021", "T1560", "T1041"],
    sectors: ["Government", "Energy"],
    description: "Fictional intrusion set: exploits edge devices, moves laterally with valid accounts, stages archives.",
  },
  {
    name: "Copper Wasp (demo)",
    motivation: "Financial",
    techniques: ["T1110", "T1621", "T1078", "T1114", "T1567"],
    sectors: ["Finance", "Retail"],
    description: "Fictional credential-stuffing and MFA-fatigue actor targeting cloud mailboxes.",
  },
  {
    name: "Static Moth (demo)",
    motivation: "Hacktivism",
    techniques: ["T1498", "T1190", "T1489"],
    sectors: ["Public sector", "Media"],
    description: "Fictional DDoS and defacement group.",
  },
];

export const PEOPLE = [
  "A. Okafor", "B. Lindqvist", "C. Moreau", "D. Nakamura", "E. Haddad", "F. Kowalski",
  "G. Patel", "H. Svensson", "I. Rossi", "J. Mensah", "K. Ivanova", "L. Fernández",
];

export const TEAMS = ["Platform Ops", "Network Eng", "Cloud Ops", "Database Ops", "App Support", "Security Ops"];

export const SITES = ["Frankfurt DC1", "London DC2", "Dublin colo", "Branch-Paris", "Branch-Madrid"];
export const CLOUD_REGIONS = ["aws:eu-west-1", "aws:eu-central-1", "azure:westeurope", "gcp:europe-west4"];

export const SERVICE_NAMES = [
  "Customer Portal", "Payments", "Order Management", "Identity (SSO)", "Email", "Data Warehouse",
  "Logistics Tracking", "HR Self-Service",
];

export const NOC_SOURCES = ["SolarWinds", "Datadog", "Prometheus", "Grafana", "AWS CloudWatch", "Azure Monitor", "Google Cloud Ops"];
export const SIEM_SOURCES = ["Microsoft Sentinel", "Splunk", "Wazuh"];
export const EDR_SOURCES = ["CrowdStrike Falcon", "Microsoft Defender"];
export const VULN_SOURCES = ["Qualys VMDR", "Tenable"];

export const FEEDS = ["Demo community feed", "Demo commercial feed", "Internal sightings"];
export const VAPT_TESTERS = ["Northwind Security (demo)", "Contoso Red Team (demo)", "Internal AppSec"];

export const NOC_ALERT_TEMPLATES: { title: string; type: string; severity: string }[] = [
  { title: "Host unreachable (ICMP)", type: "server", severity: "critical" },
  { title: "CPU utilisation above 95% for 10 min", type: "server", severity: "high" },
  { title: "Disk /var above 90%", type: "server", severity: "medium" },
  { title: "Memory pressure: swap in use", type: "server", severity: "medium" },
  { title: "Interface Gi1/0/48 down", type: "network", severity: "high" },
  { title: "BGP session to upstream flapping", type: "network", severity: "critical" },
  { title: "Packet loss above 2% on WAN link", type: "network", severity: "high" },
  { title: "High interface utilisation (>85%)", type: "network", severity: "medium" },
  { title: "Instance status check failed", type: "cloud", severity: "high" },
  { title: "Auto-scaling group at max capacity", type: "cloud", severity: "medium" },
  { title: "Load balancer 5xx rate above 1%", type: "cloud", severity: "high" },
  { title: "Monthly spend anomaly (+38%)", type: "cloud", severity: "low" },
  { title: "p95 latency above SLO (800 ms)", type: "application", severity: "high" },
  { title: "Error rate above 2%", type: "application", severity: "critical" },
  { title: "Apdex below 0.85", type: "application", severity: "medium" },
  { title: "Replication lag above 30 s", type: "database", severity: "high" },
  { title: "Connection pool exhausted", type: "database", severity: "critical" },
  { title: "Slow queries above threshold", type: "database", severity: "medium" },
  { title: "Backup job failed", type: "database", severity: "high" },
  { title: "Certificate expires in 14 days", type: "application", severity: "low" },
];

export const SOC_ALERT_TEMPLATES: { title: string; technique: string; severity: string }[] = [
  { title: "Suspicious PowerShell with encoded command", technique: "T1059", severity: "high" },
  { title: "Phishing email clicked: credential page", technique: "T1566", severity: "high" },
  { title: "Impossible travel sign-in", technique: "T1078", severity: "medium" },
  { title: "MFA push fatigue: 14 prompts in 5 minutes", technique: "T1621", severity: "high" },
  { title: "Brute force against VPN gateway", technique: "T1110", severity: "medium" },
  { title: "LSASS memory access by unsigned binary", technique: "T1003", severity: "critical" },
  { title: "Defender tamper protection disabled", technique: "T1562", severity: "critical" },
  { title: "New local administrator account created", technique: "T1136", severity: "high" },
  { title: "Remote service execution from workstation", technique: "T1021", severity: "high" },
  { title: "Beaconing to rare external domain", technique: "T1071", severity: "high" },
  { title: "Large archive created in user profile", technique: "T1560", severity: "medium" },
  { title: "Upload to personal cloud storage (2.3 GB)", technique: "T1567", severity: "high" },
  { title: "Volume shadow copies deleted", technique: "T1490", severity: "critical" },
  { title: "Mass file renames with new extension", technique: "T1486", severity: "critical" },
  { title: "Web shell pattern in IIS logs", technique: "T1190", severity: "critical" },
  { title: "Scheduled task created by Office process", technique: "T1053", severity: "medium" },
  { title: "Port scan from internal host", technique: "T1046", severity: "low" },
  { title: "Inbox forwarding rule to external domain", technique: "T1114", severity: "medium" },
];

export const VULN_TITLES: { title: string; product: string }[] = [
  { title: "Remote code execution in VPN appliance web portal", product: "Edge VPN 9.x" },
  { title: "Authentication bypass in management interface", product: "Firewall OS 7.2" },
  { title: "Privilege escalation in kernel netfilter", product: "Linux kernel 5.15" },
  { title: "Deserialization RCE in Java logging library", product: "Java app server" },
  { title: "SQL injection in reporting module", product: "Reporting suite 4.1" },
  { title: "Outdated OpenSSL with known DoS", product: "OpenSSL 3.0" },
  { title: "Weak TLS configuration (TLS 1.0 enabled)", product: "Web server" },
  { title: "Unpatched Windows SMB remote code execution", product: "Windows Server 2019" },
  { title: "Path traversal in file upload service", product: "File gateway 2.4" },
  { title: "Default credentials on management port", product: "Storage array" },
  { title: "Cross-site scripting in admin console", product: "Monitoring console 8" },
  { title: "Database server missing security updates", product: "PostgreSQL 13" },
];

export const VAPT_TITLES = [
  { title: "Broken object level authorization on /api/orders/{id}", cwe: "CWE-639" },
  { title: "Stored cross-site scripting in support ticket view", cwe: "CWE-79" },
  { title: "Publicly readable storage bucket with backups", cwe: "CWE-732" },
  { title: "Missing rate limiting on password reset", cwe: "CWE-307" },
  { title: "SSRF via image import URL", cwe: "CWE-918" },
  { title: "Overly permissive security group (0.0.0.0/0 on 22)", cwe: "CWE-284" },
  { title: "Kerberoastable service accounts with weak passwords", cwe: "CWE-521" },
  { title: "Verbose stack traces in production errors", cwe: "CWE-209" },
  { title: "Session tokens not invalidated on logout", cwe: "CWE-613" },
  { title: "Outdated JavaScript library with known CVEs", cwe: "CWE-1104" },
];
