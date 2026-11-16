import { SegmentBar } from "@/components/charts";
import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice, KpiTile } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { incidentColumns, incidentRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";
import { OPEN_INCIDENT, severityParts } from "@/lib/severity";

export default async function InvestigationsPage() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "incident:read", "Investigations");
  if (denied) return denied;
  const cases = data.incidents.filter((i) => i.domain !== "noc");
  const open = cases.filter((i) => OPEN_INCIDENT.has(i.status));
  const awaiting = cases.filter((i) => i.steps.some((s) => s.status === "awaiting_approval"));
  return (
    <>
      <PageHeader
        title="Investigations"
        description="Security incidents and joint NOC/SOC incidents. Open a case for its timeline, evidence, AI analysis and response workflow."
        actions={<DemoBadge />}
      />
      <DemoNotice />
      <Grid cols={4}>
        <KpiTile label="Open investigations" value={open.length} />
        <KpiTile label="Joint with NOC" value={cases.filter((i) => i.domain === "joint").length} />
        <KpiTile label="Awaiting action approval" value={awaiting.length} hint="Simulated response steps" />
        <Card title="Open by severity">
          <SegmentBar label="Open investigations by severity" parts={severityParts(open, ["critical", "high", "medium", "low"])} />
        </Card>
      </Grid>
      <section className="mt-6">
        <DataTable
          caption="Security investigations"
          rows={cases.map(incidentRow)}
          columns={incidentColumns(aggregate)}
          searchPlaceholder="Search case number, title, commander…"
          exportName="investigations"
        />
      </section>
    </>
  );
}
