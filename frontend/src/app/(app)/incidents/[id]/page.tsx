import Link from "next/link";
import { notFound } from "next/navigation";

import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice, SeverityBadge, StateBadge } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { Tabs } from "@/components/tabs";
import { Card, PageHeader } from "@/components/ui";
import { TECHNIQUES } from "@/lib/demo/reference";
import type { Incident, TimelineEntry } from "@/lib/demo/types";
import { formatTime, minutes } from "@/lib/format";
import { alertColumns, alertRow, assetColumns, assetRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";

const KIND_LABEL: Record<TimelineEntry["kind"], string> = {
  detected: "Detected",
  alert: "Alert",
  status: "Status",
  comment: "Comment",
  ai: "AI",
  action: "Action",
  approval: "Approval",
  sla: "SLA",
};

function SlaClock({ label, startedAt, endedAt, slaMinutes, now }: { label: string; startedAt: string; endedAt: string | null; slaMinutes: number; now: number }) {
  const elapsed = ((endedAt ? Date.parse(endedAt) : now) - Date.parse(startedAt)) / 60000;
  const breached = elapsed > slaMinutes;
  return (
    <div>
      <p className="text-muted text-xs">{label}</p>
      <p className="text-sm font-medium">
        {endedAt ? minutes(elapsed) : `${minutes(elapsed)} so far`} <span className="text-muted font-normal">/ SLA {minutes(slaMinutes)}</span>
      </p>
      <p className={`text-xs ${breached ? "text-danger" : "text-success"}`}>{breached ? "✕ Breached" : endedAt ? "✓ Met" : "✓ Within SLA"}</p>
    </div>
  );
}

function Rca({ incident, alertTitles }: { incident: Incident; alertTitles: Map<string, string> }) {
  return (
    <div className="space-y-4">
      <div className="border-accent-soc/50 bg-accent-soc/5 rounded-md border p-3 text-xs">
        <p className="text-accent-soc font-semibold">AI draft (demo) · not confirmed</p>
        <p className="text-muted mt-1">{incident.rca.summary} Every statement cites the alerts it relies on; nothing here is applied automatically.</p>
      </div>
      {incident.rca.hypotheses.map((h, i) => (
        <Card key={i}>
          <div className="flex items-start justify-between gap-4">
            <p className="text-sm">{h.text}</p>
            <span className="text-muted shrink-0 text-xs tabular-nums">{Math.round(h.confidence * 100)}% confidence</span>
          </div>
          <div aria-hidden="true" className="bg-border/50 mt-2 h-1 overflow-hidden rounded">
            <div className="h-full rounded" style={{ width: `${h.confidence * 100}%`, background: "var(--series-1)" }} />
          </div>
          <p className="text-muted mt-3 mb-1 text-xs font-medium">Cited evidence</p>
          <ul className="flex flex-wrap gap-1.5">
            {h.evidence.map((id) => (
              <li key={id} className="bg-border/50 rounded px-1.5 py-0.5 text-xs" title={id}>
                [{id.split("-").slice(-2).join("-")}] {alertTitles.get(id) ?? id}
              </li>
            ))}
          </ul>
        </Card>
      ))}
      <Card title="Gaps the AI could not close">
        <ul className="text-muted list-disc space-y-1 pl-5 text-sm">
          {incident.rca.gaps.map((g) => (
            <li key={g}>{g}</li>
          ))}
        </ul>
      </Card>
    </div>
  );
}

function Response({ incident }: { incident: Incident }) {
  return (
    <div className="space-y-3">
      <p className="text-muted text-xs">
        Steps run through the policy engine. T2 needs one approver, T3 two distinct approvers. All execution is <strong>simulated</strong>; live
        remediation is disabled in this build. Approvals and playbooks arrive in phase P5.
      </p>
      <ol className="space-y-2">
        {incident.steps.map((s, i) => (
          <li key={s.id} className="bg-surface border-border flex flex-wrap items-center gap-3 rounded-lg border p-3">
            <span className="text-muted w-5 text-right text-xs tabular-nums">{i + 1}.</span>
            <span className="min-w-48 flex-1 text-sm">{s.title}</span>
            <span className="bg-border/50 rounded px-1.5 py-px font-mono text-[11px]" title="Action risk tier">
              {s.tier}
            </span>
            <span className="text-muted text-xs">{s.kind === "automated" ? "Automated (simulated)" : "Manual"}</span>
            <span className="text-muted text-xs">{s.owner}</span>
            <StateBadge value={s.status} />
            {s.status === "awaiting_approval" && (
              <button type="button" disabled className="btn btn-ghost border-border border text-xs" title="Approval workflow arrives in phase P5">
                Review approval (P5)
              </button>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}

export default async function IncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { me, data } = await getDemo();
  const denied = gate(me, "incident:read", "Incident");
  if (denied) return denied;
  const incident = data.incidents.find((i) => i.id === id);
  if (!incident) notFound();
  const now = Date.parse(data.generatedAt) + 30 * 60000;
  const alerts = data.alerts.filter((a) => incident.alertIds.includes(a.id));
  const assets = data.assets.filter((a) => incident.assetIds.includes(a.id));
  const alertTitles = new Map(alerts.map((a) => [a.id, a.title]));
  const back = incident.domain === "soc" ? { href: "/soc/investigations", label: "Investigations" } : { href: "/incidents", label: "Incidents" };

  return (
    <>
      <nav aria-label="Breadcrumb" className="text-muted mb-2 text-sm">
        <Link href={back.href} className="hover:text-foreground">
          ← {back.label}
        </Link>
      </nav>
      <PageHeader
        title={`${incident.number}: ${incident.title}`}
        description={incident.summary}
        actions={
          <div className="flex flex-wrap items-center gap-3">
            <SeverityBadge severity={incident.severity} />
            <span className="bg-border/50 rounded px-1.5 py-px text-xs font-medium">{incident.priority}</span>
            <StateBadge value={incident.status} />
            <DemoBadge />
          </div>
        }
      />
      <DemoNotice />
      <Card className="mb-6">
        <div className="grid gap-4 sm:grid-cols-3 lg:grid-cols-6">
          <div>
            <p className="text-muted text-xs">Domain</p>
            <p className="text-sm font-medium">{incident.domain.toUpperCase()}</p>
          </div>
          <div>
            <p className="text-muted text-xs">Service</p>
            <p className="text-sm font-medium">{incident.service}</p>
          </div>
          <div>
            <p className="text-muted text-xs">Commander / assignee</p>
            <p className="text-sm font-medium">
              {incident.commander} / {incident.assignee}
            </p>
          </div>
          <div>
            <p className="text-muted text-xs">Detected</p>
            <p className="text-sm font-medium">{formatTime(incident.detectedAt)}</p>
          </div>
          <SlaClock label="Acknowledge" startedAt={incident.detectedAt} endedAt={incident.acknowledgedAt} slaMinutes={incident.slaAckMinutes} now={now} />
          <SlaClock label="Resolve" startedAt={incident.detectedAt} endedAt={incident.resolvedAt} slaMinutes={incident.slaResolveMinutes} now={now} />
        </div>
        {incident.techniques.length > 0 && (
          <p className="text-muted mt-4 text-xs">
            ATT&CK:{" "}
            {incident.techniques.map((t) => (
              <span key={t} className="bg-border/50 mr-1 rounded px-1.5 py-px font-mono" title={TECHNIQUES[t]?.name}>
                {t} {TECHNIQUES[t]?.name}
              </span>
            ))}
          </p>
        )}
      </Card>
      <Tabs
        tabs={[
          {
            label: "Timeline",
            count: incident.timeline.length,
            content: (
              <ol className="border-border relative space-y-4 border-l pl-5">
                {incident.timeline.map((t, i) => (
                  <li key={i}>
                    <span aria-hidden="true" className="bg-border absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full" />
                    <p className="text-muted text-xs">
                      {formatTime(t.at)} · <span className="font-medium">{KIND_LABEL[t.kind]}</span> · {t.actor}
                    </p>
                    <p className="text-sm">{t.text}</p>
                  </li>
                ))}
              </ol>
            ),
          },
          {
            label: "Alerts",
            count: alerts.length,
            content: <DataTable caption="Alerts in this incident" rows={alerts.map((a) => alertRow(a, incident.number))} columns={alertColumns(false, incident.domain !== "noc")} pageSize={10} />,
          },
          { label: "Root cause (AI)", content: <Rca incident={incident} alertTitles={alertTitles} /> },
          { label: "Response workflow", count: incident.steps.length, content: <Response incident={incident} /> },
          {
            label: "Assets",
            count: assets.length,
            content: (
              <DataTable
                caption="Affected assets"
                rows={assets.map(assetRow)}
                columns={assetColumns(assets[0]?.type ?? "server", false).filter((c) => ["name", "status", "kind", "environment", "availability", "service"].includes(c.key))}
                pageSize={10}
              />
            ),
          },
        ]}
      />
    </>
  );
}
