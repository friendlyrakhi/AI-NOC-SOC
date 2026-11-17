import Link from "next/link";
import { notFound } from "next/navigation";

import { ActionForm } from "@/components/action-form";
import { RequestsTable } from "@/components/automation";
import { SandboxNotice, StateBadge } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { PollRefresh } from "@/components/poll-refresh";
import { Card, PageHeader } from "@/components/ui";
import { cancelRun } from "@/app/actions/automation";
import { formatTime } from "@/lib/format";
import { getMe } from "@/lib/server/api";
import { getPlaybook, getRequests, getRun, stepsOf, type StepState } from "@/lib/server/automation";
import { isUuid } from "@/lib/server/pipeline";

const RUN_HELP: Record<string, string> = {
  running: "Running. Steps that need approval wait in the approvals inbox.",
  succeeded: "Every step succeeded or was skipped.",
  failed: "A step failed or was denied; later steps that depend on it were skipped.",
  halted: "Stopped by the automation kill switch before the next step.",
  cancelled: "Cancelled by a user.",
};

export default async function RunPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const me = await getMe();
  const denied = gate(me, "playbook:read", "Playbook run");
  if (denied) return denied;
  const run = isUuid(id) ? await getRun(id) : null;
  if (!run) notFound();
  const [playbook, requests] = await Promise.all([
    getPlaybook(run.playbook_id),
    me.permissions.includes("action:read") ? getRequests({ runId: run.id }) : Promise.resolve(null),
  ]);
  const definition = playbook?.versions?.find((v) => v.version === run.version)?.definition;
  const states = run.steps as Record<string, StepState>;
  const byRequest = new Map((requests ?? []).map((r) => [r.id, r]));

  return (
    <>
      <p className="mb-2 text-xs">
        <Link href={`/automation/playbooks/${run.playbook_id}`} className="text-primary hover:underline">
          ← {run.playbook_name}
        </Link>
      </p>
      <PageHeader
        title={`${run.playbook_name} · v${run.version}`}
        description={`Started ${formatTime(run.started_at)}${run.ended_at ? ` · ended ${formatTime(run.ended_at)}` : ""}`}
        actions={
          <span className="flex items-center gap-2">
            {run.status === "running" && <PollRefresh />}
            <StateBadge value={run.status} />
          </span>
        }
      />
      <SandboxNotice>
        {run.mode === "dry_run" ? "Dry run: each step only previews what it would do." : "Simulate: steps run through sandbox connectors."} No real system is
        changed.
      </SandboxNotice>
      <Card className="mb-6">
        <p className="text-sm">{RUN_HELP[run.status] ?? run.status}</p>
        {run.error && <p className="text-danger mt-1 text-sm whitespace-pre-wrap">{run.error}</p>}
        <div className="mt-2 flex flex-wrap gap-4 text-sm">
          {run.incident_id && (
            <Link href={`/incidents/${run.incident_id}`} className="text-primary hover:underline">
              Open incident
            </Link>
          )}
        </div>
        {run.status === "running" && me.permissions.includes("playbook:run") && (
          <div className="mt-3">
            <ActionForm action={cancelRun} submitLabel="Cancel run" danger className="flex items-center gap-3">
              <input type="hidden" name="run_id" value={run.id} />
            </ActionForm>
          </div>
        )}
      </Card>
      <h2 className="mb-2 text-sm font-semibold">Steps</h2>
      <ol className="mb-6 space-y-2" aria-label="Playbook steps">
        {stepsOf(definition).map((s, i) => {
          const st = states[s.id];
          const req = st?.request_id ? byRequest.get(st.request_id) : undefined;
          return (
            <li key={s.id} className="bg-surface border-border flex flex-wrap items-center gap-3 rounded-lg border p-3">
              <span className="text-muted w-5 text-right text-xs tabular-nums">{i + 1}.</span>
              <div className="min-w-48 flex-1">
                <p className="font-mono text-sm">{s.action}</p>
                <p className="text-muted text-xs">
                  {s.id}
                  {s.requires?.length ? ` · after ${s.requires.join(", ")}` : ""} · on failure: {s.on_failure ?? "stop"}
                </p>
                {st?.detail && <p className="text-muted text-xs whitespace-pre-wrap">{st.detail}</p>}
              </div>
              {req ? (
                <Link href={`/automation/requests/${req.id}`} className="text-primary text-xs hover:underline">
                  Request ({req.status.replace(/_/g, " ")})
                </Link>
              ) : null}
              <StateBadge value={st?.status ?? (run.status === "running" ? "pending" : "not_run")} />
            </li>
          );
        })}
      </ol>
      {requests && <RequestsTable requests={requests} caption="Action requests in this run" empty="No step has requested an action yet." />}
    </>
  );
}
