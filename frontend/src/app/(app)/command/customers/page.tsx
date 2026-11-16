import Link from "next/link";

import { DataTable, type Row } from "@/components/data-table";
import { DemoBadge, DemoNotice } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { apiGetOptional, type Schemas } from "@/lib/server/api";
import { getDemo } from "@/lib/server/demo";
import { OPEN_INCIDENT } from "@/lib/severity";

/**
 * Customer portfolio. Tenant names and delegations are real (API); per-customer
 * operational metrics are DEMO data until the P2/P3 APIs exist.
 */
export default async function CustomersOverview() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "portal:command", "Customers");
  if (denied) return denied;

  const real = me.active_tenant_kind === "msp" && !aggregate ? await apiGetOptional<Schemas["CustomerOut"][]>("/customers") : null;

  if (!aggregate) {
    return (
      <>
        <PageHeader title="Customers" description="Per-customer health and SLA comparison for managed service providers." />
        <Card>
          {real ? (
            <>
              <p className="text-sm">
                Your MSP manages {real.length} customer{real.length === 1 ? "" : "s"}. Switch the tenant selector to{" "}
                <strong>All customers (read-only)</strong> to compare them here.
              </p>
              <ul className="mt-3 space-y-1 text-sm">
                {real.map((c) => (
                  <li key={c.id}>
                    {c.name} <span className="text-muted text-xs">· {c.active_delegations} active delegations</span>
                  </li>
                ))}
              </ul>
              <Link href="/admin/customers" className="text-primary mt-3 inline-block text-sm hover:underline">
                Manage customers →
              </Link>
            </>
          ) : (
            <p className="text-muted text-sm">
              Customer comparison is available to MSP staff in the <strong>All customers</strong> view of the tenant selector.
            </p>
          )}
        </Card>
      </>
    );
  }

  const rows: Row[] = data.tenants.map((t) => {
    const incidents = data.incidents.filter((i) => i.tenant.id === t.id);
    const open = incidents.filter((i) => OPEN_INCIDENT.has(i.status));
    const services = data.services.filter((s) => s.tenant.id === t.id);
    const sla = services.length ? services.reduce((s, x) => s + x.attainment30d, 0) / services.length : 100;
    const vulns = data.vulns.filter((v) => v.tenant.id === t.id && v.kev && v.status !== "fixed");
    const down = data.assets.filter((a) => a.tenant.id === t.id && a.status === "down").length;
    return {
      _id: t.id,
      name: t.name,
      open: open.length,
      p1: open.filter((i) => i.priority === "P1").length,
      sla: Number(sla.toFixed(2)),
      below: services.filter((s) => s.attainment30d < s.sloTarget).length,
      kev: vulns.length,
      down,
    };
  });

  return (
    <>
      <PageHeader
        title="Customers"
        description="Side-by-side view of the customers your MSP role is delegated to (read-only)."
        actions={<DemoBadge />}
      />
      <DemoNotice>Customer names and access come from the platform. Health, SLA and vulnerability figures are demo data.</DemoNotice>
      <DataTable
        caption="Customer comparison"
        rows={rows}
        columns={[
          { key: "name", header: "Customer" },
          { key: "open", header: "Open incidents", type: "number", align: "right" },
          { key: "p1", header: "Open P1", type: "number", align: "right" },
          { key: "sla", header: "Avg SLO attainment", type: "percent", align: "right" },
          { key: "below", header: "Services below SLO", type: "number", align: "right" },
          { key: "kev", header: "Known-exploited vulns", type: "number", align: "right" },
          { key: "down", header: "Assets down", type: "number", align: "right" },
        ]}
        initialSort={{ key: "open", dir: "desc" }}
        exportName="customer-comparison"
      />
    </>
  );
}
