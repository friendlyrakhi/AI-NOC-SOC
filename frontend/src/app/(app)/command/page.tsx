import Link from "next/link";

import { TimeSeriesChart, type Slot } from "@/components/charts";
import { DataTable } from "@/components/data-table";
import { SandboxNotice } from "@/components/indicators";
import { BriefingCard, KpiGrid, PeriodNav } from "@/components/insights";
import { gate } from "@/components/page-states";
import { Tabs } from "@/components/tabs";
import { Card, PageHeader } from "@/components/ui";
import { formatTime } from "@/lib/format";
import { getMe } from "@/lib/server/api";
import { getLatestBriefing, getOverview, getSeries, period as toPeriod, toSeries } from "@/lib/server/insights";

import { DemoCommandCenter } from "./_demo";

const SEVERITY_SLOT: Record<string, Slot> = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
const DOMAIN_SLOT: Record<string, Slot> = { noc: 1, soc: 2, joint: 3 };

export default async function CommandCenter({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const me = await getMe();
  const denied = gate(me, "portal:command", "Executive Command Center");
  if (denied) return denied;
  if (me.mode === "aggregate") {
    return (
      <DemoCommandCenter reason="The figures below are demo data. Real per-customer KPIs for the customers you are delegated to are on the Customers page." />
    );
  }
  const p = toPeriod((await searchParams).period);
  const [overview, alerts, incidents, briefing] = await Promise.all([
    getOverview(p),
    getSeries("alerts", p, "domain"),
    getSeries("incidents", p, "severity"),
    me.permissions.includes("analytics:read") ? getLatestBriefing() : Promise.resolve(null),
  ]);
  if (!overview) {
    return <DemoCommandCenter reason="Real KPIs need the analytics store (stream profile) and the analytics:read permission. Showing demo data." />;
  }
  const granularity = p === "24h" ? "hour" : "day";
  const alertSeries = toSeries(alerts ?? [], p).map((s) => ({ ...s, name: s.name.toUpperCase(), slot: DOMAIN_SLOT[s.name] ?? 4 }));
  const incidentSeries = toSeries(incidents ?? [], p).map((s) => ({ ...s, slot: SEVERITY_SLOT[s.name] ?? 6 }));

  return (
    <>
      <PageHeader
        title="Executive Command Center"
        description={`KPIs computed from this tenant's incidents, alerts and actions (analytics facts, as of ${formatTime(overview.computed_at)}). Select a KPI to see the records behind it.`}
        actions={<PeriodNav current={p} base="/command" />}
      />
      <SandboxNotice>Figures come from sandbox connector data and demo seed content processed by the real platform, not production systems.</SandboxNotice>
      <Tabs
        tabs={(["all", "noc", "soc"] as const).map((d) => ({
          label: d === "all" ? "All" : d.toUpperCase(),
          content: <KpiGrid kpis={overview.kpis[d] ?? []} domain={d} period={p} />,
        }))}
      />
      <div className="mt-6 grid gap-6 xl:grid-cols-2">
        <Card title="Alerts by domain">
          {alertSeries.length ? (
            <TimeSeriesChart title={`Alerts per ${granularity} by domain`} series={alertSeries} granularity={granularity} />
          ) : (
            <p className="text-muted text-sm">No alerts in this period.</p>
          )}
        </Card>
        <Card title="Incidents by severity">
          {incidentSeries.length ? (
            <TimeSeriesChart title={`Incidents opened per ${granularity} by severity`} series={incidentSeries} granularity={granularity} />
          ) : (
            <p className="text-muted text-sm">No incidents in this period.</p>
          )}
        </Card>
      </div>
      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <section className="xl:col-span-2">
          <h2 className="mb-3 text-sm font-semibold">Major incidents (open P1 and P2)</h2>
          <DataTable
            caption="Open P1 and P2 incidents"
            rows={overview.open_incidents.map((i) => ({
              _id: i.id,
              _href: `/incidents/${i.id}`,
              number: i.number,
              title: i.title,
              priority: i.priority,
              severity: i.severity,
              status: i.status,
              domain: i.domain.toUpperCase(),
              detected: i.detected_at,
            }))}
            columns={[
              { key: "number", header: "Incident", type: "link" },
              { key: "title", header: "Title" },
              { key: "priority", header: "Priority", filter: true },
              { key: "severity", header: "Severity", type: "severity" },
              { key: "status", header: "Status", type: "state" },
              { key: "domain", header: "Domain", filter: true, hideOnMobile: true },
              { key: "detected", header: "Detected", type: "relative" },
            ]}
            emptyText="No open P1 or P2 incidents."
          />
          <p className="mt-2 text-xs">
            <Link href="/reports" className="text-primary hover:underline">
              Reports and exports →
            </Link>
          </p>
        </section>
        <BriefingCard run={briefing} canGenerate={me.permissions.includes("ai:use")} />
      </div>
    </>
  );
}
