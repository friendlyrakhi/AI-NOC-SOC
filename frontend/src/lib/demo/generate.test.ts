import { describe, expect, it } from "vitest";

import { assetSeries, generateTenantDataset, mergeDatasets } from "./generate";

const NOW = Date.UTC(2026, 10, 16, 10);
const globex = { id: "11111111-1111-1111-1111-111111111111", name: "Globex Corporation" };
const initech = { id: "22222222-2222-2222-2222-222222222222", name: "Initech" };

describe("demo data generator", () => {
  it("is deterministic per tenant", () => {
    expect(generateTenantDataset(globex, NOW)).toEqual(generateTenantDataset(globex, NOW));
  });

  it("differs between tenants", () => {
    const a = generateTenantDataset(globex, NOW);
    const b = generateTenantDataset(initech, NOW);
    expect(a.assets.map((x) => x.name)).not.toEqual(b.assets.map((x) => x.name));
  });

  it("marks every record as demo and as the tenant's own", () => {
    const d = generateTenantDataset(globex, NOW);
    for (const list of [d.assets, d.alerts, d.incidents, d.siem, d.edr, d.indicators, d.vulns, d.runs, d.approvals]) {
      for (const record of list) {
        expect(record.demo).toBe(true);
        expect(record.tenant.id).toBe(globex.id);
      }
    }
  });

  it("keeps drill-down references consistent", () => {
    const d = generateTenantDataset(globex, NOW);
    const alertIds = new Set(d.alerts.map((a) => a.id));
    const assetIds = new Set(d.assets.map((a) => a.id));
    for (const i of d.incidents) {
      expect(i.alertIds.every((id) => alertIds.has(id))).toBe(true);
      expect(i.assetIds.every((id) => assetIds.has(id))).toBe(true);
      for (const h of i.rca.hypotheses) expect(h.evidence.every((id) => alertIds.has(id))).toBe(true);
    }
    for (const a of d.alerts) expect(assetIds.has(a.assetId)).toBe(true);
  });

  it("never uses identifiers that could be mistaken for real ones", () => {
    const d = generateTenantDataset(globex, NOW);
    expect(d.vulns.every((v) => v.cve.startsWith("CVE-DEMO-"))).toBe(true);
    for (const i of d.indicators) {
      if (i.type === "ip") expect(i.value).toMatch(/^(198\.51\.100|203\.0\.113|192\.0\.2)\./);
      if (i.type === "domain") expect(i.value).toMatch(/\.example$/);
      if (i.type === "url") expect(i.value).toMatch(/^https:\/\/[^/]+\.example\//);
    }
    expect(d.runs.every((r) => r.mode === "simulate")).toBe(true);
  });

  it("produces timestamps relative to the anchor hour, not in the future", () => {
    const d = generateTenantDataset(globex, NOW);
    for (const a of d.alerts) expect(Date.parse(a.createdAt)).toBeLessThanOrEqual(NOW);
    expect(d.kpis.nocAlerts).toHaveLength(30);
  });

  it("merges customers for the MSP view with unique IDs", () => {
    const merged = mergeDatasets([generateTenantDataset(globex, NOW), generateTenantDataset(initech, NOW)]);
    expect(merged.tenants).toHaveLength(2);
    const ids = merged.incidents.map((i) => i.id);
    expect(new Set(ids).size).toBe(ids.length);
    const a = generateTenantDataset(globex, NOW).kpis.nocAlerts[0].value;
    const b = generateTenantDataset(initech, NOW).kpis.nocAlerts[0].value;
    expect(merged.kpis.nocAlerts[0].value).toBeCloseTo(a + b, 0);
  });

  it("generates 48 hourly points for asset drill-downs", () => {
    const asset = generateTenantDataset(globex, NOW).assets[0];
    const series = assetSeries(asset, NOW);
    expect(series).toHaveLength(2);
    expect(series[0].points).toHaveLength(48);
  });
});

describe("incident narratives", () => {
  it("match the domain of the alerts they cite", () => {
    const d = generateTenantDataset(globex, NOW);
    const byId = new Map(d.alerts.map((a) => [a.id, a]));
    for (const i of d.incidents) {
      const first = byId.get(i.alertIds[0]);
      const securityStory = i.rca.hypotheses[0].text.startsWith("Initial access");
      expect(securityStory).toBe(first?.domain === "soc");
    }
  });
});
