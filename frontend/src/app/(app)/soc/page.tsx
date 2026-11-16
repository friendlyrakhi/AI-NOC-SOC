import Link from "next/link";

import { BarList, SegmentBar, TimeSeriesChart } from "@/components/charts";
import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice, KpiTile } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { TECHNIQUES } from "@/lib/demo/reference";
import { weekDelta } from "@/lib/format";
import { incidentColumns, incidentRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";
import { OPEN_ALERT, OPEN_INCIDENT, countBy, severityParts } from "@/lib/severity";

export default async function SocOverview() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "portal:soc", "AI SOC");
  if (denied) return denied;
  const alerts = data.alerts.filter((a) => a.domain === "soc");
  const active = alerts.filter((a) => OPEN_ALERT.has(a.status));
  const triaged = alerts.filter((a) => a.status !== "new");
  const cases = data.incidents.filter((i) => i.domain !== "noc");
  const openCases = cases.filter((i) => OPEN_INCIDENT.has(i.status));
  const kev = data.vulns.filter((v) => v.kev && v.status !== "fixed");
  const criticalEdr = data.edr.filter((d) => d.severity === "critical" && (d.status === "new" || d.status === "investigating"));
  const tactics = countBy(
    [...alerts.map((a) => a.technique), ...data.edr.map((d) => d.technique)],
    (t) => (t ? TECHNIQUES[t]?.tactic : null),
    8,
  );

  return (
    <>
      <PageHeader
        title={aggregate ? "AI SOC: all customers" : "AI SOC"}
        description="Security alert triage, investigations, threat exposure and response."
        actions={<DemoBadge />}
      />
      <DemoNotice />
      <Grid cols={5}>
        <KpiTile label="Untriaged security alerts" value={alerts.filter((a) => a.status === "new").length} hint={`${active.length} active`} href="/soc/siem" />
        <KpiTile label="SOC alerts today" value={data.kpis.socAlerts.at(-1)?.value ?? 0} delta={weekDelta(data.kpis.socAlerts)} goodWhen="down" />
        <KpiTile label="Critical EDR detections" value={criticalEdr.length} hint="New or investigating" href="/soc/edr" />
        <KpiTile label="Open investigations" value={openCases.length} href="/soc/investigations" />
        <KpiTile label="Known-exploited vulns open" value={kev.length} href="/soc/vulnerabilities" />
      </Grid>

      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <Card title="SOC alert volume (30 days)" className="xl:col-span-2">
          <TimeSeriesChart title="Daily SOC alert volume" series={[{ name: "SOC alerts", slot: 2, points: data.kpis.socAlerts }]} />
        </Card>
        <Card title="Detection funnel (72 h)">
          <BarList
            label="Detection funnel"
            items={[
              { label: "SIEM events ingested", value: data.siem.length },
              { label: "Security alerts raised", value: alerts.length },
              { label: "Alerts triaged", value: triaged.length },
              { label: "Escalated to investigations", value: cases.length },
            ]}
          />
        </Card>
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <Card title="Active alerts by severity">
          <SegmentBar label="Active security alerts by severity" parts={severityParts(active, ["critical", "high", "medium", "low"])} />
        </Card>
        <Card title="Observed ATT&CK tactics">
          <BarList label="Detections by ATT&CK tactic" items={tactics} />
          <Link href="/soc/mitre" className="text-primary mt-3 inline-block text-xs hover:underline">
            ATT&CK matrix →
          </Link>
        </Card>
        <Card title="Most targeted hosts">
          <BarList label="Security alerts by host" items={countBy(alerts, (a) => a.assetName, 6)} />
        </Card>
      </div>

      <section className="mt-6">
        <h2 className="mb-3 text-sm font-semibold">Open investigations</h2>
        <DataTable caption="Open security investigations" rows={openCases.map(incidentRow)} columns={incidentColumns(aggregate)} pageSize={10} />
      </section>
    </>
  );
}
