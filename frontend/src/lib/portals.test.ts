import { describe, expect, it } from "vitest";
import { PORTALS, entitledPortals } from "./portals";

describe("portal registry", () => {
  it("has unique ids and permissions", () => {
    expect(new Set(PORTALS.map((p) => p.id)).size).toBe(PORTALS.length);
    expect(new Set(PORTALS.map((p) => p.permission)).size).toBe(PORTALS.length);
  });

  it("returns only entitled portals", () => {
    const result = entitledPortals(new Set(["portal:soc"]));
    expect(result.map((p) => p.id)).toEqual(["soc"]);
  });

  it("returns nothing without permissions", () => {
    expect(entitledPortals(new Set())).toEqual([]);
  });
});
