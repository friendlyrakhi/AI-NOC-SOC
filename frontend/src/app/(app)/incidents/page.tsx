import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { BarList, SegmentBar, TimeSeriesChart } from "@/components/charts";
import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice, KpiTile, SandboxBadge, SandboxNotice } from "@/components/indicators";
import { LiveRefresh } from "@/components/live-refresh";
import { gate, Grid } from "@/components/page-states";
import { Tabs } from "@/components/tabs";
import { Card, Field, PageHeader } from "@/components/ui";
import { createIncident } from "@/app/actions/incidents";
import { minutes } from "@/lib/format";
import { pipelineIncidentColumns, pipelineIncidentRow } from "@/lib/pipeline-rows";
import { incidentColumns, incidentRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";
import { getIncidentMetrics, getIncidents } from "@/lib/server/pipeline";
import { OPEN_INCIDENT, avgLast, countBy, severityParts } from "@/lib/severity";

const PORTALS = { noc: "NOC and joint", soc: "SOC and joint" } as const;

function secondsToMinutes(value: number | null | undefined): string {
  return value == null ? "No data" : minutes(value / 60);
}

export default async function IncidentsPage({ searchParams }: { searchParams: Promise<{ portal?: string }> }) {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "incident:read", "Incident management");
  if (denied) return denied;
  const sp = await searchParams;
  const portal = sp.portal === "noc" || sp.portal === "soc" ? sp.portal : undefined;
  const [real, metrics] = aggregate ? [null, null] : await Promise.all([getIncidents(portal), getIncidentMetrics(portal)]);
  const items = real?.items ?? [];
  const open = items.filter((i) => i.status !== "resolved" && i.status !== "closed");
  const canCreate = me.permissions.includes("incident:create") && !aggregate;
  const hasReal = items.length > 0;

  const demoAll = data.incidents;
  const demoOpen = demoAll.filter((i) => OPEN_INCIDENT.has(i.status));
  const filterLinks = (
    <nav aria-label="Portal filter" className="mb-3 flex flex-wrap gap-2 text-xs">
      {([undefined, "noc", "soc"] as const).map((p) => (
        <Link
          key={p ?? "all"}
          href={p ? `/incidents?portal=${p}` : "/incidents"}
          aria-current={portal === p ? "page" : undefined}
          className={`rounded border px-2 py-1 ${portal === p ? "border-primary text-primary" : "border-border text-muted hover:text-fg"}`}
        >
          {p ? PORTALS[p] : "All incidents"}
        </Link>
      ))}
    </nav>
  );

  const realTab = {
    label: "Incidents",
    count: real?.total ?? 0,
    content: (
      <>
        <SandboxNotice>
          Incidents are opened by the correlation engine from alerts ingested from sandbox connectors (simulated vendor data), or
          declared by analysts. Joint incidents appear in both the NOC and SOC views.
        </SandboxNotice>
        {filterLinks}
        <Grid cols={4}>
          <KpiTile label="Open incidents" value={open.length} hint={`${open.filter((i) => i.priority === "P1").length} P1 · ${open.filter((i) => i.priority === "P2").length} P2`} />
          <KpiTile label="MTTA (30 d)" value={secondsToMinutes(metrics?.mtta_seconds)} hint={metrics ? `${metrics.acknowledged} acknowledged` : undefined} />
          <KpiTile label="MTTR (30 d)" value={secondsToMinutes(metrics?.mttr_seconds)} hint={metrics ? `${metrics.resolved} resolved` : undefined} />
          <KpiTile
            label="Resolve SLA met (30 d)"
            value={metrics?.resolve_sla_attainment == null ? "No data" : `${Math.round(metrics.resolve_sla_attainment * 100)}%`}
          />
        </Grid>
        <section className="mt-6">
          <DataTable
            caption={portal ? `Incidents (${PORTALS[portal]})` : "Incidents"}
            rows={items.map(pipelineIncidentRow)}
            columns={pipelineIncidentColumns}
            searchPlaceholder="Search number, title, service…"
            exportName="incidents"
            emptyText={
              real
                ? "No incidents yet. Replay a scenario under Connectors, or declare one below."
                : "Incidents are not available here (select a single customer)."
            }
          />
        </section>
        {canCreate && (
          <Card title="Declare an incident" className="mt-6">
            <ActionForm action={createIncident} submitLabel="Declare incident" className="grid gap-3 sm:grid-cols-4">
              <Field label="Title">
                <input name="title" required maxLength={300} className="input mt-1 w-full" />
              </Field>
              <Field label="Domain">
                <select name="domain" className="input mt-1 w-full" defaultValue={portal ?? "noc"}>
                  <option value="noc">NOC</option>
                  <option value="soc">SOC</option>
                </select>
              </Field>
              <Field label="Severity">
                <select name="severity" className="input mt-1 w-full" defaultValue="high">
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </Field>
              <Field label="Summary (optional)">
                <input name="summary" maxLength={2000} className="input mt-1 w-full" />
              </Field>
            </ActionForm>
          </Card>
        )}
      </>
    ),
  };

  const demoTab = {
    label: "DEMO incidents",
    count: demoAll.length,
    content: (
      <>
        <DemoNotice />
        <Grid cols={4}>
          <KpiTile label="Open incidents" value={demoOpen.length} hint={`${demoOpen.filter((i) => i.priority === "P1").length} P1 · ${demoOpen.filter((i) => i.priority === "P2").length} P2`} />
          <KpiTile label="MTTA (7 d)" value={minutes(avgLast(data.kpis.mttaMinutes))} />
          <KpiTile label="MTTR (7 d)" value={minutes(avgLast(data.kpis.mttrMinutes))} />
          <KpiTile label="Joint NOC/SOC" value={demoAll.filter((i) => i.domain === "joint").length} />
        </Grid>
        <div className="mt-6 grid gap-6 xl:grid-cols-3">
          <Card title="Incidents opened per day (30 days)" className="xl:col-span-2">
            <TimeSeriesChart title="Incidents opened per day" series={[{ name: "Incidents opened", slot: 1, points: data.kpis.incidentsOpened }]} height={160} />
          </Card>
          <Card title="Open incidents">
            <SegmentBar label="Open incidents by severity" parts={severityParts(demoOpen, ["critical", "high", "medium", "low"])} />
            <h3 className="mt-5 mb-2 text-xs font-semibold">By service</h3>
            <BarList label="Open incidents by service" items={countBy(demoOpen, (i) => i.service, 5)} />
          </Card>
        </div>
        <section className="mt-6">
          <DataTable
            caption="Incidents (DEMO)"
            rows={demoAll.map(incidentRow)}
            columns={incidentColumns(aggregate)}
            searchPlaceholder="Search number, title, commander…"
            exportName="incidents-demo"
          />
        </section>
      </>
    ),
  };

  return (
    <>
      <PageHeader
        title="Incident management"
        description="NOC, SOC and joint incidents with SLA timers, timelines, tasks and ITSM sync."
        actions={
          <span className="flex items-center gap-3">
            {!aggregate && <LiveRefresh topics={["incident.changed"]} />}
            {hasReal && <SandboxBadge />}
            <DemoBadge />
          </span>
        }
      />
      <Tabs tabs={aggregate ? [demoTab] : hasReal || real ? [realTab, demoTab] : [demoTab, realTab]} />
    </>
  );
}
