import "server-only";

import { cache } from "react";

import { anchorHour, generateTenantDataset, mergeDatasets } from "@/lib/demo/generate";
import type { DemoDataset, TenantRef } from "@/lib/demo/types";
import { getMe, type Me } from "@/lib/server/api";

/**
 * DEMO data for the caller's current scope: the active tenant, or every customer in the
 * MSP "All customers" view. Generated, deterministic, and never presented as live data.
 * When the P2/P3 APIs exist, pages switch from this module to `apiGet` per dataset.
 */
const memo = new Map<string, DemoDataset>();

function tenantDataset(tenant: TenantRef, hour: number): DemoDataset {
  const key = `${tenant.id}:${hour}`;
  let data = memo.get(key);
  if (!data) {
    if (memo.size > 64) memo.clear();
    data = generateTenantDataset(tenant, hour);
    memo.set(key, data);
  }
  return data;
}

export interface DemoScope {
  me: Me;
  data: DemoDataset;
  aggregate: boolean;
}

export const getDemo = cache(async (): Promise<DemoScope> => {
  const me = await getMe();
  const names = new Map(me.tenants.map((t) => [t.id, t.name]));
  const ids =
    me.mode === "aggregate" ? me.aggregate_tenant_ids : me.active_tenant_id && me.mode === "tenant" ? [me.active_tenant_id] : [];
  const hour = anchorHour();
  const sets = ids.map((id) => tenantDataset({ id, name: names.get(id) ?? "Customer" }, hour));
  const data = sets.length ? mergeDatasets(sets) : mergeDatasets([emptyDataset()]);
  return { me, data, aggregate: me.mode === "aggregate" };
});

function emptyDataset(): DemoDataset {
  const empty: DemoDataset = generateTenantDataset({ id: "none", name: "None" });
  return Object.fromEntries(
    Object.entries(empty).map(([k, v]) => [k, Array.isArray(v) ? [] : k === "kpis" ? Object.fromEntries(Object.keys(v).map((s) => [s, []])) : v]),
  ) as unknown as DemoDataset;
}
