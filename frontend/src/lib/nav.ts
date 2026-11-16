/** Portal navigation (docs/07-ui-navigation.md). Items for later phases show their phase. */
export interface NavItem {
  label: string;
  href?: string;
  phase?: string;
}

export const PORTAL_NAV: Record<"noc" | "soc" | "command", NavItem[]> = {
  noc: [
    { label: "Overview", href: "/noc" },
    { label: "Alerts", phase: "P3" },
    { label: "Incidents", phase: "P3" },
    { label: "Topology", phase: "P3" },
    { label: "Infrastructure", phase: "P3" },
    { label: "Metrics", phase: "P3" },
    { label: "Maintenance", phase: "P3" },
    { label: "Runbooks & Automation", phase: "P5" },
    { label: "Reports", phase: "P6" },
  ],
  soc: [
    { label: "Overview", href: "/soc" },
    { label: "Triage queue", phase: "P3" },
    { label: "Cases", phase: "P3" },
    { label: "Vulnerabilities", phase: "P3" },
    { label: "Assets & identities", phase: "P3" },
    { label: "Investigate", phase: "P6" },
    { label: "Hunt", phase: "P6" },
    { label: "Playbooks", phase: "P5" },
    { label: "Reports", phase: "P6" },
  ],
  command: [
    { label: "Overview", href: "/command" },
    { label: "Major incidents", phase: "P6" },
    { label: "Service health", phase: "P6" },
    { label: "Risk posture", phase: "P6" },
    { label: "AI briefing", phase: "P6" },
  ],
};

export interface AdminNavItem extends NavItem {
  /** Shown when the user holds any of these permissions. */
  anyOf?: string[];
  mspOnly?: boolean;
  platformOnly?: boolean;
}

export const ADMIN_NAV: AdminNavItem[] = [
  { label: "Tenant", href: "/admin", anyOf: ["tenant:read"] },
  { label: "Members", href: "/admin/users", anyOf: ["user:read"] },
  { label: "Roles", href: "/admin/roles", anyOf: ["role:read"] },
  { label: "API keys", href: "/admin/api-keys", anyOf: ["apikey:read"] },
  { label: "Audit log", href: "/admin/audit", anyOf: ["audit:read"] },
  { label: "Delegations", href: "/admin/delegations", anyOf: ["delegation:read"] },
  { label: "Customers", href: "/admin/customers", anyOf: ["msp:customers:read"], mspOnly: true },
  { label: "Platform", href: "/admin/platform", platformOnly: true },
];

export function visibleAdminNav(permissions: string[], tenantKind: string | null, platformAdmin: boolean): NavItem[] {
  return ADMIN_NAV.filter((item) => {
    if (item.platformOnly) return platformAdmin;
    if (item.mspOnly && tenantKind !== "msp") return false;
    return item.anyOf?.some((p) => permissions.includes(p)) ?? false;
  }).map(({ label, href }) => ({ label, href }));
}
