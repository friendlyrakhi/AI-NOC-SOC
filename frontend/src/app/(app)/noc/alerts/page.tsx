import { CorrelationGroups } from "@/components/correlation-groups";
import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { Tabs } from "@/components/tabs";
import { PageHeader } from "@/components/ui";
import { alertColumns, alertRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";

export default async function NocAlertsPage() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "alert:read", "Alerts & correlation");
  if (denied) return denied;
  const alerts = data.alerts.filter((a) => a.domain === "noc");
  const groups = data.groups.filter((g) => alerts.some((a) => a.id === g.alertIds[0]));
  const incidentFor = new Map(data.incidents.flatMap((i) => i.alertIds.map((a) => [a, i.number] as const)));
  return (
    <>
      <PageHeader
        title="Alerts & correlation"
        description="Operational alerts after de-duplication, and the groups the correlation engine formed from them."
        actions={<DemoBadge />}
      />
      <DemoNotice />
      <Tabs
        tabs={[
          {
            label: "Alert queue",
            count: alerts.length,
            content: (
              <DataTable
                caption="NOC alert queue"
                rows={alerts.map((a) => alertRow(a, incidentFor.get(a.id)))}
                columns={alertColumns(aggregate)}
                searchPlaceholder="Search alert, asset, service…"
                exportName="noc-alerts"
              />
            ),
          },
          {
            label: "Correlated groups",
            count: groups.length,
            content: <CorrelationGroups groups={groups} alerts={alerts} incidents={data.incidents} />,
          },
        ]}
      />
    </>
  );
}
