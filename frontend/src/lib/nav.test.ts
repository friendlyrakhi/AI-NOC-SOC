import { describe, expect, it } from "vitest";

import { buildNav, portalOf, visibleAdminNav } from "./nav";

const labels = (sections: { items: { label: string }[] }[]) => sections.flatMap((s) => s.items.map((i) => i.label));

describe("role-based navigation", () => {
  it("shows NOC items only for held permissions", () => {
    const nav = buildNav(["portal:noc", "alert:read"], "customer", false);
    expect(labels(nav.noc)).toEqual(["Overview", "Alerts & correlation", "SLA reporting"]);
    expect(labels(nav.noc)).not.toContain("Servers");
  });

  it("adds the operations section only for permitted areas", () => {
    const nav = buildNav(["portal:soc", "incident:read", "report:read"], "customer", false);
    expect(labels(nav.ops)).toEqual(["Incidents", "Reports"]);
    expect(labels(nav.soc)).toContain("Incidents");
  });

  it("shows the approvals inbox only to approvers", () => {
    expect(labels(buildNav(["playbook:read", "action:approve"], "customer", false).ops)).toEqual(["Automation", "Approvals"]);
    expect(labels(buildNav(["playbook:read", "action:request"], "customer", false).ops)).toEqual(["Automation"]);
  });

  it("gives an empty menu when nothing is permitted", () => {
    const nav = buildNav([], null, false);
    expect(nav.noc).toEqual([]);
    expect(nav.admin).toEqual([]);
  });

  it("maps paths to portals", () => {
    expect(portalOf("/noc/servers")).toBe("noc");
    expect(portalOf("/incidents/x")).toBe("ops");
    expect(portalOf("/login")).toBeNull();
  });
});

describe("admin navigation", () => {
  it("shows items for held permissions only", () => {
    expect(visibleAdminNav(["user:read", "audit:read"], "customer", false).map((i) => i.label)).toEqual(["Members", "Audit log"]);
  });

  it("hides MSP items outside MSP tenants even with the permission", () => {
    expect(visibleAdminNav(["msp:customers:read"], "customer", false)).toEqual([]);
    expect(visibleAdminNav(["msp:customers:read"], "msp", false).map((i) => i.label)).toEqual(["Customers"]);
  });

  it("shows the platform item only to platform admins", () => {
    expect(visibleAdminNav([], null, true).map((i) => i.label)).toEqual(["Platform"]);
  });
});
