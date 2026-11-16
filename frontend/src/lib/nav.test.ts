import { describe, expect, it } from "vitest";

import { visibleAdminNav } from "./nav";

describe("admin navigation", () => {
  it("shows items for held permissions only", () => {
    const labels = visibleAdminNav(["user:read", "audit:read"], "customer", false).map((i) => i.label);
    expect(labels).toEqual(["Members", "Audit log"]);
  });

  it("hides MSP items outside MSP tenants even with the permission", () => {
    expect(visibleAdminNav(["msp:customers:read"], "customer", false)).toEqual([]);
    expect(visibleAdminNav(["msp:customers:read"], "msp", false).map((i) => i.label)).toEqual(["Customers"]);
  });

  it("shows the platform item only to platform admins", () => {
    expect(visibleAdminNav([], null, true).map((i) => i.label)).toEqual(["Platform"]);
    expect(visibleAdminNav([], null, false)).toEqual([]);
  });
});
