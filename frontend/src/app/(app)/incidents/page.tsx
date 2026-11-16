import { BarList, SegmentBar, TimeSeriesChart } from "@/components/charts";
import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice, KpiTile } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { minutes } from "@/lib/format";
import { incidentColumns, incidentRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";
import { OPEN_INCIDENT, avgLast, countBy, severityParts } from "@/lib/severity";

export default async function IncidentsPage() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "incident:read", "Incident management");
  if (denied) return denied;
  const all = data.incidents;
  const open = all.filter((i) => OPEN_INCIDENT.has(i.status));
  return (
    <>
      <PageHeader
        title="Incident management"
        description="NOC, SOC and joint incidents with SLA timers, timelines, AI analysis and response workflows."
        actions={<DemoBadge />}
      />
      <DemoNotice />
      <Grid cols={4}>
        <KpiTile label="Open incidents" value={open.length} hint={`${open.filter((i) => i.priority === "P1").length} P1 · ${open.filter((i) => i.priority === "P2").length} P2`} />
        <KpiTile label="MTTA (7 d)" value={minutes(avgLast(data.kpis.mttaMinutes))} />
        <KpiTile label="MTTR (7 d)" value={minutes(avgLast(data.kpis.mttrMinutes))} />
        <KpiTile label="Joint NOC/SOC" value={all.filter((i) => i.domain === "joint").length} />
      </Grid>
      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <Card title="Incidents opened per day (30 days)" className="xl:col-span-2">
          <TimeSeriesChart title="Incidents opened per day" series={[{ name: "Incidents opened", slot: 1, points: data.kpis.incidentsOpened }]} height={160} />
        </Card>
        <Card title="Open incidents">
          <SegmentBar label="Open incidents by severity" parts={severityParts(open, ["critical", "high", "medium", "low"])} />
          <h3 className="mt-5 mb-2 text-xs font-semibold">By service</h3>
          <BarList label="Open incidents by service" items={countBy(open, (i) => i.service, 5)} />
        </Card>
      </div>
      <section className="mt-6">
        <DataTable
          caption="Incidents"
          rows={all.map(incidentRow)}
          columns={incidentColumns(aggregate)}
          searchPlaceholder="Search number, title, commander…"
          exportName="incidents"
        />
      </section>
    </>
  );
}
