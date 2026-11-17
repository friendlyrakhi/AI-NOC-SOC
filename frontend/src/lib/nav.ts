/**
 * Role-based navigation (docs/07-ui-navigation.md). Every item names the permission it
 * needs; menus are filtered server-side from the caller's effective permissions. The API
 * still enforces authorization on every call; hiding a link is not a security control.
 */
export interface NavItem {
  label: string;
  href: string;
  perm?: string;
}

export interface NavSection {
  title: string;
  items: NavItem[];
}

export type PortalKey = "command" | "noc" | "soc" | "ops" | "admin";

export const PORTAL_SECTIONS: Record<Exclude<PortalKey, "admin" | "ops">, NavSection[]> = {
  command: [
    {
      title: "Command Center",
      items: [
        { label: "Overview", href: "/command", perm: "portal:command" },
        { label: "Customers", href: "/command/customers", perm: "portal:command" },
      ],
    },
  ],
  noc: [
    {
      title: "AI NOC",
      items: [
        { label: "Overview", href: "/noc", perm: "portal:noc" },
        { label: "Alerts & correlation", href: "/noc/alerts", perm: "alert:read" },
        { label: "Incidents", href: "/incidents?portal=noc", perm: "incident:read" },
        { label: "Root cause analysis", href: "/noc/rca", perm: "incident:read" },
        { label: "SLA reporting", href: "/noc/sla", perm: "portal:noc" },
      ],
    },
    {
      title: "Infrastructure",
      items: [
        { label: "Servers", href: "/noc/servers", perm: "asset:read" },
        { label: "Network", href: "/noc/network", perm: "asset:read" },
        { label: "Cloud operations", href: "/noc/cloud", perm: "asset:read" },
        { label: "Applications (APM)", href: "/noc/applications", perm: "asset:read" },
        { label: "Databases", href: "/noc/databases", perm: "asset:read" },
        { label: "Services & topology", href: "/noc/topology", perm: "service:read" },
        { label: "Maintenance", href: "/noc/maintenance", perm: "maintenance:read" },
      ],
    },
  ],
  soc: [
    {
      title: "AI SOC",
      items: [
        { label: "Overview", href: "/soc", perm: "portal:soc" },
        { label: "Cases", href: "/incidents?portal=soc", perm: "incident:read" },
        { label: "Investigate", href: "/soc/investigations", perm: "search:read" },
        { label: "SIEM events", href: "/soc/siem", perm: "alert:read" },
        { label: "EDR / XDR", href: "/soc/edr", perm: "alert:read" },
      ],
    },
    {
      title: "Threat & exposure",
      items: [
        { label: "Threat intelligence", href: "/soc/threat-intel", perm: "alert:read" },
        { label: "Threat hunting", href: "/soc/hunting", perm: "hunt:run" },
        { label: "MITRE ATT&CK", href: "/soc/mitre", perm: "alert:read" },
        { label: "Vulnerabilities", href: "/soc/vulnerabilities", perm: "vuln:read" },
        { label: "VAPT", href: "/soc/vapt", perm: "vuln:read" },
      ],
    },
  ],
};

export const OPERATIONS_SECTION: NavSection = {
  title: "Operations",
  items: [
    { label: "Incidents", href: "/incidents", perm: "incident:read" },
    { label: "Automation", href: "/automation", perm: "playbook:read" },
    { label: "Approvals", href: "/automation/approvals", perm: "action:approve" },
    { label: "Connectors", href: "/connectors", perm: "connector:read" },
    { label: "Knowledge base", href: "/knowledge", perm: "knowledge:read" },
    { label: "Reports", href: "/reports", perm: "report:read" },
  ],
};

export interface AdminNavItem extends NavItem {
  anyOf?: string[];
  mspOnly?: boolean;
  platformOnly?: boolean;
}

export const ADMIN_NAV: AdminNavItem[] = [
  { label: "Tenant", href: "/admin", anyOf: ["tenant:read"] },
  { label: "Members", href: "/admin/users", anyOf: ["user:read"] },
  { label: "Roles", href: "/admin/roles", anyOf: ["role:read"] },
  { label: "API keys", href: "/admin/api-keys", anyOf: ["apikey:read"] },
  { label: "AI settings", href: "/admin/ai", anyOf: ["ai:admin"] },
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

export function filterSections(sections: NavSection[], permissions: string[]): NavSection[] {
  return sections
    .map((s) => ({ ...s, items: s.items.filter((i) => !i.perm || permissions.includes(i.perm)) }))
    .filter((s) => s.items.length > 0);
}

export function portalOf(pathname: string): PortalKey | null {
  const first = pathname.split("/")[1] ?? "";
  if (first === "command" || first === "noc" || first === "soc" || first === "admin") return first;
  if (["incidents", "automation", "connectors", "reports", "search"].includes(first)) return "ops";
  return null;
}

/** Everything a signed-in user may navigate to, keyed by portal (computed server-side). */
export function buildNav(
  permissions: string[],
  tenantKind: string | null,
  platformAdmin: boolean,
): Record<PortalKey, NavSection[]> {
  const ops = filterSections([OPERATIONS_SECTION], permissions);
  const admin = visibleAdminNav(permissions, tenantKind, platformAdmin);
  return {
    command: [...filterSections(PORTAL_SECTIONS.command, permissions), ...ops],
    noc: [...filterSections(PORTAL_SECTIONS.noc, permissions), ...ops],
    soc: [...filterSections(PORTAL_SECTIONS.soc, permissions), ...ops],
    ops,
    admin: admin.length ? [{ title: "Administration", items: admin }] : [],
  };
}
