import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { DataTable, type ColumnSpec } from "@/components/data-table";
import { KpiTile, SandboxBadge, SandboxNotice, SectionTitle, SeverityBadge, StateBadge } from "@/components/indicators";
import { LiveRefresh } from "@/components/live-refresh";
import { Grid } from "@/components/page-states";
import { Tabs } from "@/components/tabs";
import { Card, Field, PageHeader } from "@/components/ui";
import {
  addComment,
  addTask,
  assignToMe,
  changeStatus,
  escalateIncident,
  openServiceNowTicket,
  setTaskStatus,
} from "@/app/actions/incidents";
import type { Me } from "@/lib/server/api";
import { AiPanel } from "@/components/ai-panel";
import type { AiRun, IncidentOut, IncidentTask, LinkedAlert, TimelineEntry } from "@/lib/server/pipeline";
import { formatTime, minutes } from "@/lib/format";

/** Real incident (from correlation or declared by an analyst) with its live workflow. */

const NEXT_STATUSES: Record<IncidentOut["status"], IncidentOut["status"][]> = {
  open: ["investigating", "contained", "mitigated", "resolved"],
  investigating: ["contained", "mitigated", "resolved"],
  contained: ["investigating", "mitigated", "resolved"],
  mitigated: ["investigating", "resolved"],
  resolved: ["closed", "investigating"],
  closed: [],
};

const RULES: Record<string, string> = {
  same_asset: "Same asset",
  service_topology: "Service topology",
  shared_observable: "Shared observable",
};

const alertColumns: ColumnSpec[] = [
  { key: "title", header: "Alert" },
  { key: "severity", header: "Severity", type: "severity", filter: true },
  { key: "status", header: "Status", type: "state", filter: true },
  { key: "domain", header: "Domain", filter: true, hideOnMobile: true },
  { key: "asset", header: "Asset", type: "mono" },
  { key: "source", header: "Source", filter: true, hideOnMobile: true },
  { key: "linkedBy", header: "Linked by", filter: true },
  { key: "count", header: "Count", type: "number", align: "right", hideOnMobile: true },
  { key: "lastSeen", header: "Last seen", type: "relative" },
];

function SlaClock({ label, start, end, due, breached }: { label: string; start: string; end: string | null; due: string; breached: boolean }) {
  // The API evaluates breaches; rendering stays pure (no clock reads).
  const target = (Date.parse(due) - Date.parse(start)) / 60000;
  return (
    <div>
      <p className="text-muted text-xs">{label}</p>
      <p className="text-sm font-medium">
        {end ? minutes((Date.parse(end) - Date.parse(start)) / 60000) : `Due ${formatTime(due)}`}{" "}
        <span className="text-muted font-normal">/ SLA {minutes(target)}</span>
      </p>
      <p className={`text-xs ${breached ? "text-danger" : "text-success"}`}>{breached ? "✕ Breached" : end ? "✓ Met" : "✓ Within SLA"}</p>
    </div>
  );
}

function describe(e: TimelineEntry): string {
  const b = e.body as Record<string, unknown>;
  const s = (k: string) => (b[k] == null ? "" : String(b[k]));
  switch (e.kind) {
    case "created":
      return `Incident ${s("number")} opened (${s("domain").toUpperCase()}, ${s("severity")}, ${s("priority")}) by ${s("by") === "correlation" ? "the correlation engine" : "an analyst"}.`;
    case "alert_added":
      return `Alert linked: ${s("title")} [${s("severity")}, ${s("connector")}]${b.rule ? ` · rule: ${RULES[s("rule")] ?? s("rule")}` : ""}. ${s("reason")}`;
    case "alert_removed":
      return "An alert was unlinked.";
    case "state_change":
      return b.to ? `Status ${s("from")} → ${s("to")}${b.reason ? `: ${s("reason")}` : ""}` : `Priority ${s("priority_from")} → ${s("priority_to")}`;
    case "escalation":
      return `Escalated ${s("from").toUpperCase()} → JOINT: ${s("reason")}`;
    case "merge":
      return b.into ? `Merged into ${s("into")}. ${s("reason")}` : `Merged ${s("merged")} (${s("alerts")} alerts) into this incident. ${s("reason")}`;
    case "comment":
      return s("text");
    case "task":
      return `Task "${s("title")}" is ${s("status").replace("_", " ")}.`;
    case "assignment":
      return "Assignment changed.";
    case "external_sync":
      return `ServiceNow ${s("number")} ${b.direction === "outbound" ? "← platform" : "→ platform"}: ${s("state")}${b.simulated ? " (simulated)" : ""}${b.applied === false ? " (recorded, no change)" : ""}`;
    default:
      return e.kind;
  }
}

export function IncidentDetail({
  me,
  incident: i,
  alerts,
  timeline,
  tasks,
  aiRuns,
}: {
  me: Me;
  aiRuns: AiRun[];
  incident: IncidentOut;
  alerts: LinkedAlert[];
  timeline: TimelineEntry[];
  tasks: IncidentTask[];
}) {
  const can = (p: string) => me.permissions.includes(p);
  const hidden = (
    <>
      <input type="hidden" name="incident_id" value={i.id} />
      <input type="hidden" name="version" value={i.version} />
    </>
  );
  const ticket = i.external_tickets[0];
  const next = NEXT_STATUSES[i.status];
  const assignedToMe = i.assignee_id === me.user_id;

  const timelineTab = {
    label: "Timeline",
    count: timeline.length,
    content: (
      <ol className="space-y-3" aria-label="Incident timeline">
        {timeline.map((e) => (
          <li key={e.id} className="border-border border-l-2 pl-3">
            <p className="text-muted text-xs">
              {formatTime(e.at)} · {e.kind.replace(/_/g, " ")} · {e.actor_name ?? e.actor_type}
            </p>
            {/* Alert and comment text is external or user content: rendered as plain text only. */}
            <p className="text-sm break-words whitespace-pre-wrap">{describe(e)}</p>
          </li>
        ))}
      </ol>
    ),
  };
  const alertsTab = {
    label: "Alerts",
    count: alerts.length,
    content: (
      <DataTable
        caption="Alerts in this incident"
        rows={alerts.map((a) => ({
          _id: a.id,
          title: a.title,
          severity: a.severity,
          status: a.status,
          domain: a.domain.toUpperCase(),
          asset: a.asset_name ?? null,
          source: a.connector_id,
          linkedBy: a.added_by === "user" ? "Analyst" : a.rule_key ? RULES[a.rule_key] ?? a.rule_key : "Opened incident",
          count: a.occurrence_count,
          lastSeen: a.last_seen,
          _details: {
            Alert: a.title,
            Severity: a.severity,
            Source: `${a.connector_id} (sandbox connector)`,
            Asset: a.asset_name ?? null,
            "Linked by": a.added_by,
            Rule: a.rule_key ? RULES[a.rule_key] ?? a.rule_key : null,
            "Why linked": a.reason,
            Occurrences: a.occurrence_count,
            "Last seen": formatTime(a.last_seen),
          },
        }))}
        columns={alertColumns}
        searchPlaceholder="Search alerts…"
        emptyText="No alerts linked."
      />
    ),
  };
  const tasksTab = {
    label: "Tasks",
    count: tasks.length,
    content: (
      <div className="space-y-4">
        <ul className="space-y-2" aria-label="Tasks">
          {tasks.length === 0 && <li className="text-muted text-sm">No tasks yet.</li>}
          {tasks.map((t) => (
            <li key={t.id} className="border-border flex flex-wrap items-center justify-between gap-3 rounded border px-3 py-2">
              <span className="text-sm">
                <StateBadge value={t.status} /> <span className="ml-2">{t.title}</span>
              </span>
              {can("incident:update") && (
                <ActionForm action={setTaskStatus} submitLabel={t.status === "done" ? "Reopen" : "Mark done"} className="flex items-center gap-2">
                  <input type="hidden" name="incident_id" value={i.id} />
                  <input type="hidden" name="task_id" value={t.id} />
                  <input type="hidden" name="version" value={t.version} />
                  <input type="hidden" name="status" value={t.status === "done" ? "open" : "done"} />
                </ActionForm>
              )}
            </li>
          ))}
        </ul>
        {can("incident:update") && i.status !== "closed" && (
          <ActionForm action={addTask} submitLabel="Add task" className="flex flex-wrap items-end gap-3" resetOnSuccess>
            <input type="hidden" name="incident_id" value={i.id} />
            <Field label="New task">
              <input name="title" maxLength={300} required className="input mt-1 w-72" />
            </Field>
          </ActionForm>
        )}
      </div>
    ),
  };

  return (
    <>
      <p className="mb-2 text-xs">
        <Link href="/incidents" className="text-primary hover:underline">
          ← Incidents
        </Link>
      </p>
      <PageHeader
        title={`${i.number} · ${i.title}`}
        description={`${i.domain === "joint" ? "Joint NOC/SOC" : i.domain.toUpperCase()} incident · opened ${formatTime(i.detected_at)} by ${i.created_by_type === "correlation" ? "correlation" : "an analyst"}`}
        actions={
          <span className="flex items-center gap-3">
            <LiveRefresh topics={["incident.changed"]} incidentId={i.id} />
            {i.sandbox && <SandboxBadge />}
          </span>
        }
      />
      {i.sandbox && <SandboxNotice>Built from alerts of sandbox connectors (simulated vendor data). Nothing here touched a real system.</SandboxNotice>}
      <Grid cols={4}>
        <KpiTile label="Status" value={i.status.replace(/_/g, " ")}>
          <StateBadge value={i.status} />
        </KpiTile>
        <KpiTile label="Priority" value={i.priority}>
          <SeverityBadge severity={i.severity} />
        </KpiTile>
        <KpiTile label="Impacted services" value={i.services.length ? i.services.map((s) => s.name).join(", ") : "None identified"} />
        <KpiTile label="Alerts" value={i.alert_count} hint={assignedToMe ? "Assigned to you" : i.assignee_id ? "Assigned" : "Unassigned"} />
      </Grid>

      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <Tabs tabs={[timelineTab, alertsTab, tasksTab]} />
        </div>
        <div className="space-y-6">
          <Card title="SLA">
            <div className="grid grid-cols-2 gap-4">
              <SlaClock label="Acknowledge" start={i.detected_at} end={i.acknowledged_at} due={i.sla.ack_due_at} breached={i.sla.ack_breached} />
              <SlaClock label="Resolve" start={i.detected_at} end={i.resolved_at} due={i.sla.resolve_due_at} breached={i.sla.resolve_breached} />
            </div>
          </Card>

          {can("incident:update") && next.length > 0 && (
            <Card title="Change status">
              <ActionForm action={changeStatus} submitLabel="Update status">
                {hidden}
                <Field label="New status">
                  <select name="to" className="input mt-1 w-full" defaultValue={next[0]}>
                    {next.map((s) => (
                      <option key={s} value={s}>
                        {s.replace(/_/g, " ")}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Reason (optional)">
                  <input name="reason" maxLength={1000} className="input mt-1 w-full" />
                </Field>
              </ActionForm>
              {!assignedToMe && (
                <div className="mt-3">
                  <ActionForm action={assignToMe} submitLabel="Assign to me" className="flex items-center gap-3">
                    {hidden}
                  </ActionForm>
                </div>
              )}
            </Card>
          )}

          {can("incident:escalate") && i.domain !== "joint" && i.status !== "closed" && (
            <Card title={`Escalate to ${i.domain === "noc" ? "SOC" : "NOC"}`}>
              <p className="text-muted mb-2 text-xs">Makes this a joint incident, visible in both portals.</p>
              <ActionForm action={escalateIncident} submitLabel="Escalate to joint">
                <input type="hidden" name="incident_id" value={i.id} />
                <Field label="Why the other team is needed">
                  <input name="reason" required maxLength={1000} className="input mt-1 w-full" />
                </Field>
              </ActionForm>
            </Card>
          )}

          <Card title="ServiceNow">
            {ticket ? (
              <dl className="grid grid-cols-2 gap-2 text-sm">
                <dt className="text-muted">Ticket</dt>
                <dd className="font-mono">{ticket.external_number}</dd>
                <dt className="text-muted">State there</dt>
                <dd>{ticket.external_state.replace(/_/g, " ")}</dd>
                <dt className="text-muted">Last change from</dt>
                <dd>{ticket.last_sync_origin === "platform" ? "This platform" : "ServiceNow"}</dd>
                <dt className="text-muted">Sync</dt>
                <dd>{ticket.sync_state === "synced" ? "In sync (sandbox)" : "Error"}</dd>
              </dl>
            ) : can("incident:sync") && i.status !== "closed" ? (
              <>
                <p className="text-muted mb-2 text-xs">
                  Opens a ticket through the ServiceNow sandbox connector (a simulated call; nothing leaves the platform). Status
                  changes then sync both ways, and echoes of our own updates are ignored.
                </p>
                <ActionForm action={openServiceNowTicket} submitLabel="Open ServiceNow ticket">
                  <input type="hidden" name="incident_id" value={i.id} />
                </ActionForm>
              </>
            ) : (
              <p className="text-muted text-sm">No ticket linked.</p>
            )}
          </Card>

          {can("incident:comment") && (
            <Card title="Add comment">
              <ActionForm action={addComment} submitLabel="Comment" resetOnSuccess>
                <input type="hidden" name="incident_id" value={i.id} />
                <label className="block">
                  <span className="sr-only">Comment</span>
                  <textarea name="body" required maxLength={8000} rows={3} className="input w-full" />
                </label>
              </ActionForm>
            </Card>
          )}
        </div>
      </div>
      {(me.permissions.includes("ai:use") || aiRuns.length > 0) && (
        <div className="mt-6">
          <AiPanel incidentId={i.id} runs={aiRuns} canUse={me.permissions.includes("ai:use") && i.status !== "closed"} />
        </div>
      )}
      <SectionTitle>Summary</SectionTitle>
      <p className="text-sm whitespace-pre-wrap">{i.summary || "No analyst summary yet. Use the AI copilot above for a cited draft."}</p>
    </>
  );
}
