import { ActionForm } from "@/components/action-form";
import { SandboxNotice } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { Card, Field, PageHeader } from "@/components/ui";
import { createReport, deleteReport } from "@/app/actions/insights";
import { formatTime } from "@/lib/format";
import { getMe } from "@/lib/server/api";
import { getReports } from "@/lib/server/insights";

import { DemoReports } from "./_demo";

const KIND: Record<string, { label: string; text: string }> = {
  kpi_summary: { label: "KPI summary", text: "The Command Center KPIs with their numerators and bases." },
  incident_register: { label: "Incident register", text: "Every incident in the period with its timestamps." },
  sla_report: { label: "SLA report", text: "Per-incident SLA outcomes plus MTTA, MTTR and attainment." },
};

export default async function ReportsPage() {
  const me = await getMe();
  const denied = gate(me, "report:read", "Reports");
  if (denied) return denied;
  const reports = me.mode === "tenant" ? await getReports() : null;
  if (!reports) return <DemoReports />;
  const canCreate = me.permissions.includes("report:create");
  return (
    <>
      <PageHeader
        title="Reports"
        description="Saved report definitions. Every export is computed fresh from current data, downloaded as CSV or PDF, and recorded in the audit log."
      />
      <SandboxNotice>Reports are built from sandbox connector data and demo seed content processed by the real platform.</SandboxNotice>
      <div className="grid gap-6 xl:grid-cols-3">
        <section className="xl:col-span-2" aria-labelledby="saved-reports">
          <h2 id="saved-reports" className="mb-3 text-sm font-semibold">
            Saved reports
          </h2>
          {reports.length === 0 ? (
            <Card>
              <p className="text-muted text-sm">No saved reports yet.</p>
            </Card>
          ) : (
            <ul className="space-y-3" aria-label="Saved reports">
              {reports.map((r) => (
                <li key={r.id}>
                  <Card>
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <h3 className="text-sm font-semibold">{r.name}</h3>
                        <p className="text-muted text-xs">
                          {KIND[r.kind]?.label ?? r.kind} · {r.domain === "all" ? "all domains" : r.domain.toUpperCase()} · last {r.period}
                          {r.last_exported_at ? ` · last exported ${formatTime(r.last_exported_at)}` : ""}
                        </p>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <a className="btn btn-primary text-xs" href={`/api/reports/${r.id}/export?format=csv`} download>
                          Download CSV
                        </a>
                        <a className="btn btn-ghost border-border border text-xs" href={`/api/reports/${r.id}/export?format=pdf`} download>
                          Download PDF
                        </a>
                        {canCreate && (
                          <ActionForm action={deleteReport} submitLabel="Delete" danger className="flex items-center gap-2">
                            <input type="hidden" name="report_id" value={r.id} />
                          </ActionForm>
                        )}
                      </div>
                    </div>
                  </Card>
                </li>
              ))}
            </ul>
          )}
        </section>
        {canCreate && (
          <Card title="New report">
            <ActionForm action={createReport} submitLabel="Save report" resetOnSuccess>
              <Field label="Name">
                <input name="name" required maxLength={200} className="input w-full" />
              </Field>
              <Field label="Type">
                <select name="kind" className="input w-full" defaultValue="kpi_summary">
                  {Object.entries(KIND).map(([k, v]) => (
                    <option key={k} value={k}>
                      {v.label}: {v.text}
                    </option>
                  ))}
                </select>
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Domain">
                  <select name="domain" className="input w-full" defaultValue="all">
                    <option value="all">All</option>
                    <option value="noc">NOC</option>
                    <option value="soc">SOC</option>
                  </select>
                </Field>
                <Field label="Period">
                  <select name="period" className="input w-full" defaultValue="7d">
                    <option value="24h">Last 24 hours</option>
                    <option value="7d">Last 7 days</option>
                    <option value="30d">Last 30 days</option>
                    <option value="90d">Last 90 days</option>
                  </select>
                </Field>
              </div>
            </ActionForm>
          </Card>
        )}
      </div>
    </>
  );
}
