import { BarList, SegmentBar } from "@/components/charts";
import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice, KpiTile } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Tabs } from "@/components/tabs";
import { Card, PageHeader } from "@/components/ui";
import { alertColumns, alertRow, siemColumns, siemRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";
import { countBy, severityParts } from "@/lib/severity";

export default async function SiemPage() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "alert:read", "SIEM events");
  if (denied) return denied;
  const events = data.siem;
  const alerts = data.alerts.filter((a) => a.domain === "soc");
  const incidentFor = new Map(data.incidents.flatMap((i) => i.alertIds.map((a) => [a, i.number] as const)));
  return (
    <>
      <PageHeader
        title="SIEM events"
        description="Normalized security events (OCSF-aligned) and the alerts raised from them. Planned sources: Microsoft Sentinel, Splunk, Wazuh."
        actions={<DemoBadge />}
      />
      <DemoNotice />
      <Grid cols={4}>
        <KpiTile label="Events (48 h)" value={events.length} />
        <KpiTile label="Failed or blocked" value={events.filter((e) => e.outcome !== "success").length} />
        <KpiTile label="High or critical events" value={events.filter((e) => e.severity === "high" || e.severity === "critical").length} />
        <KpiTile label="Security alerts (72 h)" value={alerts.length} />
      </Grid>
      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card title="Events by severity">
          <SegmentBar label="SIEM events by severity" parts={severityParts(events)} />
        </Card>
        <Card title="Events by category">
          <BarList label="SIEM events by category" items={countBy(events, (e) => e.category, 6)} />
        </Card>
        <Card title="Top users in events">
          <BarList label="SIEM events by user" items={countBy(events, (e) => e.user, 6)} />
        </Card>
      </div>
      <div className="mt-6">
        <Tabs
          tabs={[
            {
              label: "Events",
              count: events.length,
              content: (
                <DataTable
                  caption="SIEM events"
                  rows={events.map(siemRow)}
                  columns={siemColumns(aggregate)}
                  searchPlaceholder="Search rule, user, host, IP…"
                  exportName="siem-events"
                />
              ),
            },
            {
              label: "Security alerts",
              count: alerts.length,
              content: (
                <DataTable
                  caption="Security alerts"
                  rows={alerts.map((a) => alertRow(a, incidentFor.get(a.id)))}
                  columns={alertColumns(aggregate, true)}
                  exportName="security-alerts"
                />
              ),
            },
          ]}
        />
      </div>
    </>
  );
}
