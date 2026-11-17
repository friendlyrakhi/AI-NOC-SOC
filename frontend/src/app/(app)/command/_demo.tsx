import Link from "next/link";

import { BarList, SegmentBar, Sparkline, TimeSeriesChart } from "@/components/charts";
import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice, HealthBadge, KpiTile } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { weekDelta } from "@/lib/format";
import { incidentColumns, incidentRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";
import { OPEN_INCIDENT, avgLast, severityParts } from "@/lib/severity";

export async function DemoCommandCenter({ reason }: { reason?: string }) {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "portal:command", "Executive Command Center");
  if (denied) return denied;
  const k = data.kpis;
  const open = data.incidents.filter((i) => OPEN_INCIDENT.has(i.status));
  const major = open.filter((i) => i.priority === "P1" || i.priority === "P2");
  const kev = data.vulns.filter((v) => v.kev && v.status !== "fixed");
  const scope = aggregate ? `${data.tenants.length} customers` : (data.tenants[0]?.name ?? "");

  const perCustomer = data.tenants.map((t) => ({
    label: t.name,
    value: open.filter((i) => i.tenant.id === t.id).length,
    href: "/command/customers",
  }));

  return (
    <>
      <PageHeader
        title="Executive Command Center"
        description={`Cross-domain operations and security posture for ${scope}.`}
        actions={<DemoBadge />}
      />
      <DemoNotice>{reason}</DemoNotice>
      <Grid cols={6}>
        <KpiTile label="Mean time to acknowledge" value={Math.round(avgLast(k.mttaMinutes))} unit="min" delta={weekDelta(k.mttaMinutes)} goodWhen="down">
          <Sparkline points={k.mttaMinutes} />
        </KpiTile>
        <KpiTile label="Mean time to resolve" value={(avgLast(k.mttrMinutes) / 60).toFixed(1)} unit="h" delta={weekDelta(k.mttrMinutes)} goodWhen="down">
          <Sparkline points={k.mttrMinutes} />
        </KpiTile>
        <KpiTile label="SLA attainment (7 d)" value={avgLast(k.slaAttainment).toFixed(1)} unit="%" delta={weekDelta(k.slaAttainment)} goodWhen="up">
          <Sparkline points={k.slaAttainment} />
        </KpiTile>
        <KpiTile label="Open P1 / P2 incidents" value={major.length} hint={`${open.length} open in total`} href="/incidents" />
        <KpiTile label="Known-exploited vulns open" value={kev.length} hint="CISA-KEV style flag (demo)" href="/soc/vulnerabilities" />
        <KpiTile label="Automation rate" value={avgLast(k.automationRate).toFixed(0)} unit="%" delta={weekDelta(k.automationRate)} goodWhen="up" hint="Simulated actions" />
      </Grid>

      <div className="mt-6 grid gap-6 xl:grid-cols-2">
        <Card title="Alert volume: NOC and SOC (30 days)">
          <TimeSeriesChart
            title="Daily alert volume for NOC and SOC over 30 days"
            series={[
              { name: "NOC", slot: 1, points: k.nocAlerts },
              { name: "SOC", slot: 2, points: k.socAlerts },
            ]}
          />
        </Card>
        <Card title="SLA attainment (30 days)">
          <TimeSeriesChart title="Daily SLA attainment percentage" series={[{ name: "SLA attainment", slot: 1, points: k.slaAttainment }]} format="percent" yMin={90} yMax={100} />
        </Card>
        <Card title="Mean time to acknowledge">
          <TimeSeriesChart title="Daily mean time to acknowledge in minutes" series={[{ name: "MTTA", slot: 1, points: k.mttaMinutes }]} format="minutes" height={160} />
        </Card>
        <Card title="Mean time to resolve">
          <TimeSeriesChart title="Daily mean time to resolve in minutes" series={[{ name: "MTTR", slot: 1, points: k.mttrMinutes }]} format="minutes" height={160} />
        </Card>
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <Card title="Open incidents by severity">
          <SegmentBar label="Open incidents by severity" parts={severityParts(open, ["critical", "high", "medium", "low"])} />
        </Card>
        <Card title="Business services">
          <ul className="space-y-1.5 text-sm">
            {data.services.slice(0, 8).map((s) => (
              <li key={s.id} className="flex items-center justify-between gap-2">
                <span className="truncate">
                  {s.name}
                  {aggregate && <span className="text-muted ml-1 text-xs">{s.tenant.name}</span>}
                </span>
                <HealthBadge status={s.status} />
              </li>
            ))}
          </ul>
          <Link href="/noc/sla" className="text-primary mt-3 inline-block text-xs hover:underline">
            SLA reporting →
          </Link>
        </Card>
        <Card title={aggregate ? "Open incidents by customer" : "Critical vulnerabilities (30 days)"}>
          {aggregate ? (
            <BarList label="Open incidents by customer" items={perCustomer} />
          ) : (
            <TimeSeriesChart title="Open critical vulnerabilities per day" series={[{ name: "Critical vulnerabilities", slot: 2, points: k.criticalVulns }]} height={150} />
          )}
        </Card>
      </div>

      <section className="mt-6">
        <h2 className="mb-3 text-sm font-semibold">Major incidents (open P1 and P2)</h2>
        <DataTable
          caption="Open P1 and P2 incidents"
          rows={major.map(incidentRow)}
          columns={incidentColumns(aggregate)}
          pageSize={10}
          initialSort={{ key: "severity", dir: "asc" }}
          emptyText="No open P1 or P2 incidents."
        />
      </section>
    </>
  );
}
