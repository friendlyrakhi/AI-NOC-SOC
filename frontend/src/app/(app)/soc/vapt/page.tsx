import { SegmentBar } from "@/components/charts";
import { DataTable, type Row } from "@/components/data-table";
import { DemoBadge, DemoNotice, KpiTile, StateBadge } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { formatTime } from "@/lib/format";
import { customerCol } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";
import { severityParts } from "@/lib/severity";

export default async function VaptPage() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "vuln:read", "VAPT");
  if (denied) return denied;
  const findings = data.vaptFindings;
  const open = findings.filter((f) => f.status === "open" || f.status === "retest_failed");
  const engagementName = new Map(data.engagements.map((e) => [e.id, e.name]));
  const rows: Row[] = findings.map((f) => ({
    _id: f.id,
    title: f.title,
    customer: f.tenant.name,
    engagement: engagementName.get(f.engagementId) ?? "",
    severity: f.severity,
    cvss: f.cvss,
    cwe: f.cwe,
    asset: f.asset,
    status: f.status,
    dueDate: f.dueDate,
    _details: {
      Finding: f.title,
      Engagement: engagementName.get(f.engagementId) ?? "",
      Severity: f.severity,
      CVSS: f.cvss,
      Weakness: f.cwe,
      Asset: f.asset,
      Status: f.status.replace(/_/g, " "),
      "Remediation due": formatTime(f.dueDate),
    },
  }));
  return (
    <>
      <PageHeader
        title="VAPT"
        description="Vulnerability assessment and penetration testing engagements, findings, remediation and retests."
        actions={<DemoBadge />}
      />
      <DemoNotice>Testing firms are fictional. Findings are generated examples.</DemoNotice>
      <Grid cols={4}>
        <KpiTile label="Engagements" value={data.engagements.length} hint={`${data.engagements.filter((e) => e.status === "in_progress").length} in progress`} />
        <KpiTile label="Open findings" value={open.length} />
        <KpiTile label="Failed retests" value={findings.filter((f) => f.status === "retest_failed").length} />
        <Card title="Open by severity">
          <SegmentBar label="Open VAPT findings by severity" parts={severityParts(open, ["critical", "high", "medium", "low"])} />
        </Card>
      </Grid>
      <h2 className="mt-8 mb-3 text-sm font-semibold">Engagements</h2>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {data.engagements.map((e) => {
          const own = findings.filter((f) => f.engagementId === e.id);
          return (
            <Card key={e.id}>
              <div className="flex items-start justify-between gap-2">
                <h3 className="text-sm font-semibold">{e.name}</h3>
                <StateBadge value={e.status} />
              </div>
              <p className="text-muted mt-1 text-xs">
                {e.type} · {e.tester}
                {aggregate && ` · ${e.tenant.name}`}
              </p>
              <p className="mt-2 text-xs">Scope: {e.scope}</p>
              <p className="text-muted mt-1 text-xs">
                {formatTime(e.start).split(" ").slice(0, 2).join(" ")} – {formatTime(e.end).split(" ").slice(0, 2).join(" ")}
              </p>
              <p className="mt-2 text-xs">
                {own.length} findings · {own.filter((f) => f.status === "open" || f.status === "retest_failed").length} open
              </p>
            </Card>
          );
        })}
      </div>
      <section className="mt-6">
        <h2 className="mb-3 text-sm font-semibold">Findings</h2>
        <DataTable
          caption="Penetration test findings"
          rows={rows}
          columns={[
            { key: "title", header: "Finding" },
            ...customerCol(aggregate),
            { key: "engagement", header: "Engagement", filter: true, hideOnMobile: true },
            { key: "severity", header: "Severity", type: "severity", filter: true },
            { key: "cvss", header: "CVSS", type: "number", align: "right" },
            { key: "cwe", header: "CWE", type: "mono", hideOnMobile: true },
            { key: "asset", header: "Asset", type: "mono", hideOnMobile: true },
            { key: "status", header: "Status", type: "state", filter: true },
            { key: "dueDate", header: "Due", type: "relative" },
          ]}
          initialSort={{ key: "severity", dir: "asc" }}
          exportName="vapt-findings"
        />
      </section>
    </>
  );
}
