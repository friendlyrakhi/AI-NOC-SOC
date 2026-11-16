import { BarList, SegmentBar, TimeSeriesChart } from "@/components/charts";
import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice, KpiTile, SandboxBadge, SandboxNotice } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { weekDelta } from "@/lib/format";
import { vulnColumns, vulnRow } from "@/lib/rows";
import { pipelineVulnColumns, pipelineVulnRow } from "@/lib/pipeline-rows";
import { getDemo } from "@/lib/server/demo";
import { getVulns } from "@/lib/server/pipeline";
import { countBy, severityParts } from "@/lib/severity";

export default async function VulnerabilitiesPage() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "vuln:read", "Vulnerability management");
  if (denied) return denied;
  const ingested = aggregate ? null : await getVulns();
  const all = data.vulns;
  const open = all.filter((v) => v.status === "open" || v.status === "in_progress");
  const now = Date.parse(data.generatedAt);
  const overdue = open.filter((v) => Date.parse(v.dueDate) < now);
  return (
    <>
      <PageHeader
        title="Vulnerability management"
        description="Findings prioritized by risk: CVSS, exploit likelihood (EPSS), known exploitation, internet exposure and asset criticality. Planned sources: Qualys VMDR, Tenable."
        actions={<DemoBadge />}
      />
      <DemoNotice>Identifiers use a CVE-DEMO prefix and are not real CVEs. Scores are generated.</DemoNotice>
      <Grid cols={5}>
        <KpiTile label="Open findings" value={open.length} />
        <KpiTile label="Known exploited (open)" value={open.filter((v) => v.kev).length} />
        <KpiTile label="Internet-exposed critical/high" value={open.filter((v) => v.exposure === "internet" && (v.severity === "critical" || v.severity === "high")).length} />
        <KpiTile label="Past remediation due date" value={overdue.length} />
        <KpiTile label="Critical (today)" value={data.kpis.criticalVulns.at(-1)?.value ?? 0} delta={weekDelta(data.kpis.criticalVulns)} goodWhen="down" />
      </Grid>
      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <Card title="Open critical vulnerabilities (30 days)" className="xl:col-span-2">
          <TimeSeriesChart title="Open critical vulnerabilities per day" series={[{ name: "Critical", slot: 2, points: data.kpis.criticalVulns }]} exportName="critical-vulns" />
        </Card>
        <Card title="Open findings by severity">
          <SegmentBar label="Open findings by severity" parts={severityParts(open, ["critical", "high", "medium", "low"])} />
          <h3 className="mt-5 mb-2 text-xs font-semibold">Most affected assets</h3>
          <BarList label="Open findings by asset" items={countBy(open, (v) => v.assetName, 6)} />
        </Card>
      </div>
      {ingested && ingested.total > 0 && (
        <section className="mt-6">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold">
            Findings ingested from sandbox scanners <SandboxBadge />
          </h2>
          <SandboxNotice>
            Open findings from this tenant&apos;s sandbox Qualys and Tenable connectors, known-exploited first. Identifiers are sandbox
            values, not real CVEs.
          </SandboxNotice>
          <DataTable
            caption="Vulnerability findings ingested from sandbox connectors"
            rows={ingested.items.map(pipelineVulnRow)}
            columns={pipelineVulnColumns}
            searchPlaceholder="Search ID, title, asset…"
            exportName="vulnerabilities-sandbox"
          />
        </section>
      )}
      <section className="mt-6">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold">
          Findings (highest risk first) <DemoBadge />
        </h2>
        <DataTable
          caption="Vulnerability findings"
          rows={all.map(vulnRow)}
          columns={vulnColumns(aggregate)}
          initialSort={{ key: "risk", dir: "desc" }}
          searchPlaceholder="Search ID, title, asset…"
          exportName="vulnerabilities"
        />
      </section>
    </>
  );
}
