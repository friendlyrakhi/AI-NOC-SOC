import { BarList, SegmentBar } from "@/components/charts";
import { DataTable, type Row } from "@/components/data-table";
import { DemoBadge, DemoNotice, KpiTile } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Tabs } from "@/components/tabs";
import { Card, PageHeader } from "@/components/ui";
import { formatTime } from "@/lib/format";
import { customerCol, edrColumns, edrRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";
import { countBy, severityParts } from "@/lib/severity";

export default async function EdrPage() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "alert:read", "EDR / XDR");
  if (denied) return denied;
  const detections = data.edr;
  const active = detections.filter((d) => d.status === "new" || d.status === "investigating");
  const endpoints: Row[] = data.endpoints.map((e) => ({
    _id: `${e.tenant.id}:${e.host}`,
    host: e.host,
    customer: e.tenant.name,
    os: e.os,
    agent: e.agent,
    online: e.online ? "online" : "offline",
    isolation: e.isolation,
    risk: e.risk,
    lastSeen: e.lastSeen,
    _details: {
      Host: e.host,
      OS: e.os,
      Agent: `${e.agent} (DEMO data; no connector configured)`,
      Connectivity: e.online ? "Online" : "Offline",
      Isolation: "Not isolated. Isolation is a T3 action requiring 2 approvers (simulate mode).",
      "Risk score": `${e.risk}/100`,
      "Last seen": formatTime(e.lastSeen),
    },
  }));
  return (
    <>
      <PageHeader
        title="EDR / XDR"
        description="Endpoint detections with process lineage, and the endpoint fleet. Planned sources: CrowdStrike Falcon, Microsoft Defender for Endpoint."
        actions={<DemoBadge />}
      />
      <DemoNotice />
      <Grid cols={4}>
        <KpiTile label="Active detections" value={active.length} hint={`${active.filter((d) => d.severity === "critical").length} critical`} />
        <KpiTile label="Endpoints" value={data.endpoints.length} hint={`${data.endpoints.filter((e) => !e.online).length} offline`} />
        <KpiTile label="High-risk endpoints (≥ 80)" value={data.endpoints.filter((e) => e.risk >= 80).length} />
        <KpiTile label="False positives (4 d)" value={detections.filter((d) => d.status === "false_positive").length} />
      </Grid>
      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card title="Active detections by severity">
          <SegmentBar label="Active detections by severity" parts={severityParts(active, ["critical", "high", "medium", "low"])} />
        </Card>
        <Card title="Detections by tactic">
          <BarList label="Detections by ATT&CK tactic" items={countBy(detections, (d) => d.tactic, 6)} />
        </Card>
        <Card title="Hosts with most detections">
          <BarList label="Detections by host" items={countBy(detections, (d) => d.host, 6)} />
        </Card>
      </div>
      <div className="mt-6">
        <Tabs
          tabs={[
            {
              label: "Detections",
              count: detections.length,
              content: (
                <DataTable
                  caption="EDR detections (select a row for the process tree)"
                  rows={detections.map(edrRow)}
                  columns={edrColumns(aggregate)}
                  searchPlaceholder="Search technique, host, file…"
                  exportName="edr-detections"
                />
              ),
            },
            {
              label: "Endpoints",
              count: endpoints.length,
              content: (
                <DataTable
                  caption="Endpoint fleet"
                  rows={endpoints}
                  columns={[
                    { key: "host", header: "Host", type: "mono" },
                    ...customerCol(aggregate),
                    { key: "os", header: "OS", filter: true },
                    { key: "agent", header: "Agent", filter: true },
                    { key: "online", header: "Connectivity", type: "state", filter: true },
                    { key: "risk", header: "Risk", type: "score" },
                    { key: "lastSeen", header: "Last seen", type: "relative" },
                  ]}
                  initialSort={{ key: "risk", dir: "desc" }}
                  exportName="endpoints"
                />
              ),
            },
          ]}
        />
      </div>
    </>
  );
}
