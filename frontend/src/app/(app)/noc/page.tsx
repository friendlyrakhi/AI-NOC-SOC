import Link from "next/link";

import { BarList, SegmentBar, TimeSeriesChart } from "@/components/charts";
import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice, HealthBadge, KpiTile } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import type { AssetType } from "@/lib/demo/types";
import { weekDelta } from "@/lib/format";
import { incidentColumns, incidentRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";
import { OPEN_ALERT, OPEN_INCIDENT, countBy, healthParts, severityParts } from "@/lib/severity";

const DOMAINS: { type: AssetType; label: string; href: string }[] = [
  { type: "server", label: "Servers", href: "/noc/servers" },
  { type: "network", label: "Network", href: "/noc/network" },
  { type: "cloud", label: "Cloud", href: "/noc/cloud" },
  { type: "application", label: "Applications", href: "/noc/applications" },
  { type: "database", label: "Databases", href: "/noc/databases" },
];

export default async function NocOverview() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "portal:noc", "AI NOC");
  if (denied) return denied;
  const alerts = data.alerts.filter((a) => a.domain === "noc");
  const active = alerts.filter((a) => OPEN_ALERT.has(a.status));
  const incidents = data.incidents.filter((i) => i.domain !== "soc" && OPEN_INCIDENT.has(i.status));
  const unhealthy = data.assets.filter((a) => a.status === "degraded" || a.status === "down");
  const breaching = data.services.filter((s) => s.attainment30d < s.sloTarget);

  return (
    <>
      <PageHeader
        title={aggregate ? "AI NOC: all customers" : "AI NOC"}
        description="Infrastructure and service health, operational alerts, correlation and incidents."
        actions={<DemoBadge />}
      />
      <DemoNotice />
      <Grid cols={4}>
        <KpiTile label="Active NOC alerts" value={active.length} hint={`${active.filter((a) => a.severity === "critical").length} critical`} href="/noc/alerts" />
        <KpiTile label="Alerts today vs last week" value={data.kpis.nocAlerts.at(-1)?.value ?? 0} delta={weekDelta(data.kpis.nocAlerts)} goodWhen="down" />
        <KpiTile label="Open NOC incidents" value={incidents.length} hint={`${incidents.filter((i) => i.priority === "P1").length} P1`} href="/incidents" />
        <KpiTile label="Services below SLO (30 d)" value={breaching.length} hint={`of ${data.services.length} services`} href="/noc/sla" />
      </Grid>

      <h2 className="mt-8 mb-3 text-sm font-semibold">Infrastructure health</h2>
      <Grid cols={5}>
        {DOMAINS.map((d) => {
          const assets = data.assets.filter((a) => a.type === d.type);
          return (
            <Link key={d.type} href={d.href} className="bg-surface border-border hover:border-primary/60 block rounded-lg border p-4">
              <p className="text-sm font-medium">{d.label}</p>
              <p className="text-muted mb-3 text-xs">{assets.length} monitored</p>
              <SegmentBar label={`${d.label} health`} parts={healthParts(assets)} />
            </Link>
          );
        })}
      </Grid>

      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <Card title="NOC alert volume (30 days)" className="xl:col-span-2">
          <TimeSeriesChart title="Daily NOC alert volume" series={[{ name: "NOC alerts", slot: 1, points: data.kpis.nocAlerts }]} />
        </Card>
        <Card title="Active alerts by severity">
          <SegmentBar label="Active alerts by severity" parts={severityParts(active, ["critical", "high", "medium", "low"])} />
          <h3 className="mt-5 mb-2 text-xs font-semibold">Noisiest sources (active)</h3>
          <BarList label="Active alerts by source" items={countBy(active, (a) => a.source, 6)} />
        </Card>
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <section className="xl:col-span-2">
          <h2 className="mb-3 text-sm font-semibold">Open NOC incidents</h2>
          <DataTable caption="Open NOC incidents" rows={incidents.map(incidentRow)} columns={incidentColumns(aggregate)} pageSize={10} />
        </section>
        <Card title="Unhealthy assets">
          <ul className="space-y-1.5 text-sm">
            {unhealthy.slice(0, 12).map((a) => (
              <li key={a.id} className="flex items-center justify-between gap-2">
                <Link href={`/noc/assets/${a.id}`} className="text-primary truncate font-mono text-xs hover:underline">
                  {a.name}
                </Link>
                <HealthBadge status={a.status} />
              </li>
            ))}
          </ul>
          {unhealthy.length === 0 && <p className="text-muted text-sm">All assets healthy.</p>}
        </Card>
      </div>
    </>
  );
}
