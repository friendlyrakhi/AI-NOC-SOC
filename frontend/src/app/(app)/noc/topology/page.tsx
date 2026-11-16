import { DataTable } from "@/components/data-table";
import { KpiTile, SandboxBadge, SandboxNotice } from "@/components/indicators";
import { LiveRefresh } from "@/components/live-refresh";
import { gate, Grid } from "@/components/page-states";
import { NotAvailable, PageHeader } from "@/components/ui";
import { serviceColumns, serviceRow } from "@/lib/pipeline-rows";
import { getMe } from "@/lib/server/api";
import { getServices } from "@/lib/server/pipeline";

export default async function TopologyPage() {
  const me = await getMe();
  const denied = gate(me, "service:read", "Services & topology");
  if (denied) return denied;
  const services = me.mode === "aggregate" ? null : await getServices();
  const list = services ?? [];
  return (
    <>
      <PageHeader
        title="Services & topology"
        description="Business services from the CMDB, the hosts that run them and the infrastructure they depend on. Health is derived from open alerts."
        actions={
          <span className="flex items-center gap-3">
            {services && <LiveRefresh topics={["alert.upserted", "incident.changed"]} />}
            {list.length > 0 && <SandboxBadge />}
          </span>
        }
      />
      {!services ? (
        <NotAvailable what="Services (select a single customer)" />
      ) : (
        <>
          <SandboxNotice>
            Topology comes from the ServiceNow sandbox connector&apos;s CMDB stream (simulated). The correlation engine uses it to
            group alerts on hosts and shared infrastructure into one incident per outage.
          </SandboxNotice>
          <Grid cols={4}>
            <KpiTile label="Services" value={list.length} />
            <KpiTile label="Down" value={list.filter((s) => s.health === "down").length} />
            <KpiTile label="Degraded" value={list.filter((s) => s.health === "degraded").length} />
            <KpiTile label="In maintenance" value={list.filter((s) => s.in_maintenance).length} />
          </Grid>
          <section className="mt-6">
            <DataTable
              caption="Business services"
              rows={list.map(serviceRow)}
              columns={serviceColumns}
              searchPlaceholder="Search services…"
              emptyText="No services yet. Add a ServiceNow sandbox integration; its CMDB sync creates them."
            />
          </section>
        </>
      )}
    </>
  );
}
