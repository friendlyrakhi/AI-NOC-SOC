import { TimeSeriesChart } from "@/components/charts";
import { DataTable, type ColumnSpec, type Row } from "@/components/data-table";
import { DemoBadge, DemoNotice, KpiTile } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { minutes, weekDelta } from "@/lib/format";
import { customerCol } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";
import { avgLast } from "@/lib/severity";

export default async function SlaPage() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "portal:noc", "SLA reporting");
  if (denied) return denied;

  const serviceRows: Row[] = data.services.map((s) => {
    const budget = 100 - s.sloTarget;
    const used = Math.max(0, 100 - s.attainment30d);
    return {
      _id: s.id,
      name: s.name,
      customer: s.tenant.name,
      tier: `Tier ${s.tier}`,
      status: s.status,
      target: s.sloTarget,
      attainment: s.attainment30d,
      budget: Math.max(0, Math.round(((budget - used) / budget) * 100)),
      breaches: s.breaches30d,
      owner: s.owner,
      _details: {
        Service: s.name,
        Tier: s.tier,
        "SLO target": `${s.sloTarget}%`,
        "Attainment (30 d)": `${s.attainment30d}%`,
        "Error budget remaining": `${Math.max(0, Math.round(((budget - used) / budget) * 100))}%`,
        "Breaches (30 d)": s.breaches30d,
        Owner: s.owner,
        "Supporting assets": s.assetIds.length,
      },
    };
  });
  const serviceCols: ColumnSpec[] = [
    { key: "name", header: "Service" },
    ...customerCol(aggregate),
    { key: "tier", header: "Tier", filter: true },
    { key: "status", header: "Health", type: "health", filter: true },
    { key: "target", header: "SLO target", type: "percent", align: "right" },
    { key: "attainment", header: "Attainment 30 d", type: "percent", align: "right" },
    { key: "budget", header: "Error budget left", type: "score" },
    { key: "breaches", header: "Breaches", type: "number", align: "right" },
    { key: "owner", header: "Owner", hideOnMobile: true },
  ];

  const breachRows: Row[] = data.incidents
    .map((i) => {
      const ack = i.acknowledgedAt ? (Date.parse(i.acknowledgedAt) - Date.parse(i.detectedAt)) / 60000 : null;
      const res = i.resolvedAt ? (Date.parse(i.resolvedAt) - Date.parse(i.detectedAt)) / 60000 : null;
      const ackBreach = ack !== null && ack > i.slaAckMinutes;
      const resBreach = res !== null && res > i.slaResolveMinutes;
      return { i, ack, res, ackBreach, resBreach };
    })
    .filter((x) => x.ackBreach || x.resBreach)
    .map(({ i, ack, res, ackBreach, resBreach }) => ({
      _id: i.id,
      _href: `/incidents/${i.id}`,
      number: i.number,
      customer: i.tenant.name,
      priority: i.priority,
      severity: i.severity,
      breach: ackBreach && resBreach ? "acknowledge + resolve" : ackBreach ? "acknowledge" : "resolve",
      ack: ack === null ? "—" : `${minutes(ack)} / ${minutes(i.slaAckMinutes)}`,
      resolve: res === null ? "open" : `${minutes(res)} / ${minutes(i.slaResolveMinutes)}`,
      detectedAt: i.detectedAt,
    }));

  const k = data.kpis;
  return (
    <>
      <PageHeader title="SLA reporting" description="Service-level objectives, error budgets and incident response SLAs." actions={<DemoBadge />} />
      <DemoNotice />
      <Grid cols={4}>
        <KpiTile label="SLA attainment (7 d)" value={avgLast(k.slaAttainment).toFixed(1)} unit="%" delta={weekDelta(k.slaAttainment)} goodWhen="up" />
        <KpiTile label="Services below SLO" value={data.services.filter((s) => s.attainment30d < s.sloTarget).length} hint={`of ${data.services.length}`} />
        <KpiTile label="Response SLA breaches" value={breachRows.length} hint="Acknowledge or resolve" />
        <KpiTile label="MTTR (7 d)" value={minutes(avgLast(k.mttrMinutes))} />
      </Grid>
      <div className="mt-6 grid gap-6 xl:grid-cols-2">
        <Card title="SLA attainment (30 days)">
          <TimeSeriesChart title="Daily SLA attainment" series={[{ name: "SLA attainment", slot: 1, points: k.slaAttainment }]} format="percent" yMin={90} yMax={100} exportName="sla-attainment" />
        </Card>
        <Card title="Mean time to resolve (30 days)">
          <TimeSeriesChart title="Daily mean time to resolve" series={[{ name: "MTTR", slot: 1, points: k.mttrMinutes }]} format="minutes" exportName="mttr" />
        </Card>
      </div>
      <section className="mt-6">
        <h2 className="mb-3 text-sm font-semibold">Service-level objectives</h2>
        <DataTable caption="Service-level objectives" rows={serviceRows} columns={serviceCols} initialSort={{ key: "budget", dir: "asc" }} exportName="slo-report" />
      </section>
      <section className="mt-6">
        <h2 className="mb-3 text-sm font-semibold">Incident response SLA breaches</h2>
        <DataTable
          caption="Incidents that breached a response SLA"
          rows={breachRows}
          columns={[
            { key: "number", header: "Incident", type: "mono" },
            ...customerCol(aggregate),
            { key: "priority", header: "Priority", filter: true },
            { key: "severity", header: "Severity", type: "severity" },
            { key: "breach", header: "Breached", filter: true },
            { key: "ack", header: "Acknowledge (actual / SLA)" },
            { key: "resolve", header: "Resolve (actual / SLA)" },
            { key: "detectedAt", header: "Detected", type: "relative" },
          ]}
          exportName="sla-breaches"
          emptyText="No SLA breaches in this period."
        />
      </section>
    </>
  );
}
