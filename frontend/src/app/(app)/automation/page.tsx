import { DataTable, type Row } from "@/components/data-table";
import { DemoBadge, DemoNotice, KpiTile, StateBadge } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Tabs } from "@/components/tabs";
import { Card, PageHeader } from "@/components/ui";
import { formatTime } from "@/lib/format";
import { customerCol } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";

const TIER_HELP: Record<string, string> = {
  T0: "Read-only: runs automatically",
  T1: "Low impact: runs automatically, audited",
  T2: "Medium impact: 1 approver",
  T3: "High impact: 2 distinct approvers",
};

export default async function AutomationPage() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "playbook:read", "Automation center");
  if (denied) return denied;
  const pending = data.approvals.filter((a) => a.status === "pending");

  const runRows: Row[] = data.runs.map((r) => ({
    _id: r.id,
    playbook: r.playbook,
    customer: r.tenant.name,
    incident: r.incident,
    status: r.status,
    mode: "SIMULATED",
    startedAt: r.startedAt,
    _details: {
      Playbook: r.playbook,
      Incident: r.incident,
      Mode: "Simulate (no real system was changed)",
      Status: r.status.replace(/_/g, " "),
      Started: formatTime(r.startedAt),
      Steps: r.steps.map((s, i) => `${i + 1}. ${s.name}: ${s.result.replace(/_/g, " ")}`).join("\n"),
    },
  }));

  const approvalRows: Row[] = data.approvals.map((a) => ({
    _id: a.id,
    action: a.action,
    customer: a.tenant.name,
    tier: a.tier,
    target: a.target,
    incident: a.incident,
    requestedBy: a.requestedBy,
    approvals: `${a.approvals} of ${a.approvalsNeeded}`,
    status: a.status,
    expiresAt: a.expiresAt,
    _details: {
      Action: a.action,
      Tier: `${a.tier}: ${TIER_HELP[a.tier]}`,
      Target: a.target,
      Incident: a.incident,
      "Requested by": a.requestedBy,
      Approvals: `${a.approvals} of ${a.approvalsNeeded}`,
      Rule: "The requester cannot approve. AI-originated requests always need a human approver.",
      Expires: formatTime(a.expiresAt),
      Execution: "Simulate mode only. Approving and executing arrives with the workflow engine in phase P5.",
    },
  }));

  return (
    <>
      <PageHeader
        title="Automation center"
        description="Versioned playbooks, simulated runs and the approval inbox for high-impact actions."
        actions={<DemoBadge />}
      />
      <DemoNotice>
        Playbooks, runs and approvals are demo content. Execution mode is <strong>simulate</strong>: live remediation is disabled in this build and
        cannot be enabled from the UI.
      </DemoNotice>
      <Grid cols={4}>
        <KpiTile label="Published playbooks" value={data.playbooks.filter((p) => p.status === "published").length} />
        <KpiTile label="Runs (10 d)" value={data.runs.length} hint="All simulated" />
        <KpiTile label="Pending approvals" value={pending.length} hint={`${pending.filter((a) => a.tier === "T3").length} need two approvers`} />
        <KpiTile label="Failed runs" value={data.runs.filter((r) => r.status === "failed").length} />
      </Grid>
      <div className="mt-6">
        <Tabs
          tabs={[
            {
              label: "Playbooks",
              count: data.playbooks.length,
              content: (
                <div className="grid gap-4 xl:grid-cols-2">
                  {data.playbooks.map((p) => (
                    <Card key={p.id}>
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <h2 className="text-sm font-semibold">{p.name}</h2>
                          <p className="text-muted text-xs">
                            {p.domain.toUpperCase()} · v{p.version} · trigger: {p.trigger}
                            {aggregate && ` · ${p.tenant.name}`}
                          </p>
                        </div>
                        <StateBadge value={p.status} />
                      </div>
                      <ol className="mt-3 space-y-1.5">
                        {p.steps.map((s, i) => (
                          <li key={s.name} className="flex items-center gap-2 text-sm">
                            <span className="text-muted w-4 text-right text-xs">{i + 1}.</span>
                            <span className="flex-1">{s.name}</span>
                            <code className="text-muted hidden font-mono text-[11px] sm:inline">{s.action}</code>
                            <span className="bg-border/50 rounded px-1.5 py-px font-mono text-[11px]" title={TIER_HELP[s.tier]}>
                              {s.tier}
                            </span>
                          </li>
                        ))}
                      </ol>
                      <p className="text-muted mt-3 text-xs">{p.runs30d} simulated runs in 30 days</p>
                    </Card>
                  ))}
                </div>
              ),
            },
            {
              label: "Runs",
              count: runRows.length,
              content: (
                <DataTable
                  caption="Playbook runs"
                  rows={runRows}
                  columns={[
                    { key: "playbook", header: "Playbook", filter: true },
                    ...customerCol(aggregate),
                    { key: "incident", header: "Incident", type: "mono" },
                    { key: "status", header: "Status", type: "state", filter: true },
                    { key: "mode", header: "Mode" },
                    { key: "startedAt", header: "Started", type: "relative" },
                  ]}
                />
              ),
            },
            {
              label: "Approvals",
              count: pending.length,
              content: (
                <DataTable
                  caption="Approval requests"
                  rows={approvalRows}
                  columns={[
                    { key: "action", header: "Action", type: "mono" },
                    ...customerCol(aggregate),
                    { key: "tier", header: "Tier", filter: true },
                    { key: "target", header: "Target", type: "mono" },
                    { key: "incident", header: "Incident", type: "mono", hideOnMobile: true },
                    { key: "requestedBy", header: "Requested by", hideOnMobile: true },
                    { key: "approvals", header: "Approvals" },
                    { key: "status", header: "Status", type: "state", filter: true },
                    { key: "expiresAt", header: "Expires", type: "relative" },
                  ]}
                />
              ),
            },
          ]}
        />
      </div>
    </>
  );
}
