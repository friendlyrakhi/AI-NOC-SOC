import { CorrelationGroups } from "@/components/correlation-groups";
import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice, SandboxBadge, SandboxNotice } from "@/components/indicators";
import { LiveRefresh } from "@/components/live-refresh";
import { gate } from "@/components/page-states";
import { Tabs } from "@/components/tabs";
import { PageHeader } from "@/components/ui";
import { pipelineAlertRow } from "@/lib/pipeline-rows";
import { alertColumns, alertRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";
import { getAlerts } from "@/lib/server/pipeline";

export default async function NocAlertsPage() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "alert:read", "Alerts & correlation");
  if (denied) return denied;
  const ingested = aggregate ? null : await getAlerts("noc");
  const alerts = data.alerts.filter((a) => a.domain === "noc");
  const groups = data.groups.filter((g) => alerts.some((a) => a.id === g.alertIds[0]));
  const incidentFor = new Map(data.incidents.flatMap((i) => i.alertIds.map((a) => [a, i.number] as const)));
  const hasIngested = !!ingested && ingested.total > 0;

  const pipelineTab = {
    label: "Sandbox pipeline",
    count: ingested?.total ?? 0,
    content: (
      <>
        <SandboxNotice />
        <DataTable
          caption="NOC alerts ingested from sandbox connectors"
          rows={(ingested?.items ?? []).map(pipelineAlertRow)}
          columns={[...alertColumns(false), { key: "incident", header: "Incident", type: "mono", hideOnMobile: true }]}
          searchPlaceholder="Search alert, asset, service…"
          exportName="noc-alerts-sandbox"
          emptyText={
            ingested
              ? "No NOC alerts ingested yet. Add a sandbox integration or replay a scenario under Connectors."
              : "Ingested alerts are not available here (select a single customer, and run the stream profile)."
          }
        />
        {ingested && ingested.total > ingested.items.length && (
          <p className="text-muted mt-2 text-xs">
            Showing the {ingested.items.length} highest-severity of {ingested.total} alerts.
          </p>
        )}
      </>
    ),
  };
  const demoTabs = [
    {
      label: "DEMO alert queue",
      count: alerts.length,
      content: (
        <>
          <DemoNotice />
          <DataTable
            caption="NOC alert queue (DEMO)"
            rows={alerts.map((a) => alertRow(a, incidentFor.get(a.id)))}
            columns={alertColumns(aggregate)}
            searchPlaceholder="Search alert, asset, service…"
            exportName="noc-alerts"
          />
        </>
      ),
    },
    {
      label: "DEMO correlated groups",
      count: groups.length,
      content: (
        <>
          <DemoNotice>Correlation runs on ingested alerts from phase P3. These groups are generated demonstration data.</DemoNotice>
          <CorrelationGroups groups={groups} alerts={alerts} incidents={data.incidents} />
        </>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Alerts & correlation"
        description="Operational alerts after de-duplication, and the groups the correlation engine formed from them."
        actions={
          <span className="flex items-center gap-2">
            {!aggregate && <LiveRefresh topics={["alert.upserted"]} />}
            {hasIngested && <SandboxBadge />}
            <DemoBadge />
          </span>
        }
      />
      <Tabs tabs={aggregate ? demoTabs : hasIngested ? [pipelineTab, ...demoTabs] : [...demoTabs, pipelineTab]} />
    </>
  );
}
