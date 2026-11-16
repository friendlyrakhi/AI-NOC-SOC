/**
 * Portal registry. Entitlement checks arrive in P1 (IAM-4); in P0 this only
 * drives the placeholder shell.
 */
export type PortalId = "noc" | "soc" | "command" | "admin";

export interface Portal {
  id: PortalId;
  name: string;
  href: `/${string}`;
  permission: string;
  description: string;
  phase: string;
}

export const PORTALS: readonly Portal[] = [
  {
    id: "noc",
    name: "AI NOC",
    href: "/noc",
    permission: "portal:noc",
    description: "Infrastructure and service health, alerts, topology, incidents.",
    phase: "P1 shell · P3 workflows",
  },
  {
    id: "soc",
    name: "AI SOC",
    href: "/soc",
    permission: "portal:soc",
    description: "Security triage, cases, investigation, vulnerabilities.",
    phase: "P1 shell · P3 workflows",
  },
  {
    id: "command",
    name: "Command Center",
    href: "/command",
    permission: "portal:command",
    description: "Executive cross-domain KPIs, SLA and risk posture.",
    phase: "P6",
  },
  {
    id: "admin",
    name: "Administration",
    href: "/admin",
    permission: "admin",
    description: "Tenants, users, roles, integrations, AI settings, audit.",
    phase: "P1",
  },
] as const;

export function entitledPortals(permissions: ReadonlySet<string>): Portal[] {
  return PORTALS.filter((p) => permissions.has(p.permission));
}
