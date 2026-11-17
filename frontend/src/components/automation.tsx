import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { DataTable } from "@/components/data-table";
import { StateBadge } from "@/components/indicators";
import { Field } from "@/components/ui";
import { approveRequest, cancelRequest, denyRequest, requestAction } from "@/app/actions/automation";
import { formatTime } from "@/lib/format";
import type { Me } from "@/lib/server/api";
import { TIER_HELP, type ActionRequest, type CatalogEntry } from "@/lib/server/automation";

/**
 * Shared automation UI. Nothing here executes anything: forms call Server Actions, the API
 * runs the policy engine and approvals, and the workflow worker executes approved actions
 * in simulate or dry-run mode only.
 */

export function TierBadge({ tier }: { tier: string }) {
  const tone = tier === "T3" ? "border-danger/40 text-danger" : tier === "T2" ? "border-caution/60 text-warning" : "border-border text-muted";
  return (
    <span className={`inline-block rounded border px-1.5 py-px font-mono text-[11px] font-medium ${tone}`} title={TIER_HELP[tier]}>
      {tier}
    </span>
  );
}

export function ModeBadge({ mode }: { mode: string }) {
  return (
    <span className="border-primary/40 text-primary inline-block rounded border px-1.5 py-px text-[11px] font-medium whitespace-nowrap">
      {mode === "dry_run" ? "Dry run (preview)" : "Simulated"}
    </span>
  );
}

function targetText(r: ActionRequest): string {
  const t = r.target as { kind?: string; name?: string; number?: string; id?: string };
  return t.name ?? t.number ?? t.id ?? "—";
}

export function requestRows(requests: ActionRequest[]) {
  return requests.map((r) => ({
    _id: r.id,
    _href: `/automation/requests/${r.id}`,
    action: r.action_key,
    tier: r.tier,
    target: targetText(r),
    mode: r.execution_mode === "dry_run" ? "Dry run" : "Simulate",
    by: r.requested_by_type === "ai" ? `AI (for ${r.requested_by_name ?? "user"})` : r.requested_by_type === "workflow" ? "Playbook" : r.requested_by_name ?? r.requested_by_type,
    approvals: r.required_approvals ? `${(r.approvals ?? []).filter((a) => a.decision === "approve").length} of ${r.required_approvals}` : "Not needed",
    status: r.status,
    created: r.created_at,
  }));
}

export function RequestsTable({ requests, caption, empty }: { requests: ActionRequest[]; caption: string; empty?: string }) {
  return (
    <DataTable
      caption={caption}
      rows={requestRows(requests)}
      columns={[
        { key: "action", header: "Action", type: "link" },
        { key: "tier", header: "Tier", filter: true },
        { key: "target", header: "Target", type: "mono" },
        { key: "mode", header: "Mode", filter: true, hideOnMobile: true },
        { key: "by", header: "Requested by", hideOnMobile: true },
        { key: "approvals", header: "Approvals" },
        { key: "status", header: "Status", type: "state", filter: true },
        { key: "created", header: "Requested", type: "relative" },
      ]}
      emptyText={empty ?? "No action requests."}
    />
  );
}

/** Result of a run: simulated or dry-run output from the sandbox connector. Plain text only. */
export function ResultBlock({ r }: { r: ActionRequest }) {
  if (!r.result && !r.error) return null;
  return (
    <div className="mt-3">
      <p className="text-muted text-xs font-semibold">{r.execution_mode === "dry_run" ? "Dry-run preview (nothing was changed)" : "Simulated result (no real system was changed)"}</p>
      {r.error && <p className="text-danger text-sm whitespace-pre-wrap">{r.error}</p>}
      {r.result && <pre className="bg-border/30 mt-1 max-h-64 overflow-auto rounded p-2 font-mono text-xs whitespace-pre-wrap">{JSON.stringify(r.result, null, 2)}</pre>}
    </div>
  );
}

/** Approve, deny or cancel, shown only when the caller may do it. The API enforces every rule again. */
export function DecisionControls({ r, me, compact }: { r: ActionRequest; me: Me; compact?: boolean }) {
  const can = (p: string) => me.permissions.includes(p);
  const mine = r.requested_by === me.user_id;
  const decided = (r.approvals ?? []).some((a) => a.approver_id === me.user_id);
  // Expiry is enforced by the API (an approval after expires_at is refused and the request expires).
  const pending = r.status === "pending_approval";
  const hidden = <input type="hidden" name="request_id" value={r.id} />;
  return (
    <div className={compact ? "space-y-2" : "space-y-4"}>
      {pending && can("action:approve") && !mine && !decided && (
        <div className="grid gap-4 md:grid-cols-2">
          <ActionForm action={approveRequest} submitLabel="Approve" stepUp>
            {hidden}
            <Field label="Comment (optional)">
              <input name="comment" maxLength={1000} className="input w-full" />
            </Field>
          </ActionForm>
          <ActionForm action={denyRequest} submitLabel="Deny" stepUp danger>
            {hidden}
            <Field label="Reason for denying">
              <input name="comment" maxLength={1000} required className="input w-full" />
            </Field>
          </ActionForm>
        </div>
      )}
      {pending && mine && <p className="text-muted text-xs">You requested this, so someone else must approve it.</p>}
      {pending && decided && <p className="text-muted text-xs">You already decided. {r.required_approvals > 1 ? "A different approver must approve too." : ""}</p>}
      {(r.status === "pending_approval" || r.status === "approved") && (mine || can("action:approve")) && can("action:request") && (
        <ActionForm action={cancelRequest} submitLabel="Cancel request" className="flex items-center gap-3">
          {hidden}
        </ActionForm>
      )}
    </div>
  );
}

export function RequestSummary({ r }: { r: ActionRequest }) {
  const reasons = (r.policy_decision as { reasons?: string[] }).reasons ?? [];
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-sm">
      <dt className="text-muted">Action</dt>
      <dd className="font-mono">{r.action_key}</dd>
      <dt className="text-muted">Connector</dt>
      <dd>{r.connector_id} (sandbox)</dd>
      <dt className="text-muted">Target</dt>
      <dd className="font-mono">{targetText(r)}</dd>
      <dt className="text-muted">Risk tier</dt>
      <dd>
        <TierBadge tier={r.tier} /> <span className="text-muted text-xs">{TIER_HELP[r.tier]}</span>
      </dd>
      <dt className="text-muted">Mode</dt>
      <dd>
        <ModeBadge mode={r.execution_mode} />
      </dd>
      <dt className="text-muted">Requested by</dt>
      <dd>
        {r.requested_by_type === "ai" ? `AI suggestion, requested by ${r.requested_by_name ?? "a user"}` : r.requested_by_type === "workflow" ? `Playbook step ${r.step_id ?? ""}` : r.requested_by_name ?? r.requested_by_type}
        {" · "}
        {formatTime(r.created_at)}
      </dd>
      <dt className="text-muted">Justification</dt>
      <dd className="whitespace-pre-wrap">{r.justification || "—"}</dd>
      <dt className="text-muted">Parameters</dt>
      <dd>
        <code className="font-mono text-xs break-all">{JSON.stringify(r.params)}</code>
      </dd>
      <dt className="text-muted">Policy</dt>
      <dd className="text-xs">{reasons.length ? reasons.join(" ") : "—"}</dd>
      {r.expires_at && r.status === "pending_approval" && (
        <>
          <dt className="text-muted">Expires</dt>
          <dd>{formatTime(r.expires_at)} (then it is rejected automatically)</dd>
        </>
      )}
      {r.incident_id && (
        <>
          <dt className="text-muted">Incident</dt>
          <dd>
            <Link href={`/incidents/${r.incident_id}`} className="text-primary hover:underline">
              Open incident
            </Link>
          </dd>
        </>
      )}
      {r.workflow_run_id && (
        <>
          <dt className="text-muted">Playbook run</dt>
          <dd>
            <Link href={`/automation/runs/${r.workflow_run_id}`} className="text-primary hover:underline">
              Open run
            </Link>
          </dd>
        </>
      )}
    </dl>
  );
}

export function ApprovalList({ r }: { r: ActionRequest }) {
  if (r.required_approvals === 0 && (r.approvals ?? []).length === 0) return <p className="text-muted text-sm">No approval needed for this tier.</p>;
  return (
    <div>
      <p className="text-muted mb-1 text-xs">
        {r.required_approvals > 1 ? `Needs ${r.required_approvals} approvals from different people.` : `Needs ${r.required_approvals} approval.`} The requester can never approve.
      </p>
      {(r.approvals ?? []).length === 0 ? (
        <p className="text-muted text-sm">No decisions yet.</p>
      ) : (
        <ul className="space-y-1 text-sm" aria-label="Decisions">
          {(r.approvals ?? []).map((a) => (
            <li key={a.approver_id}>
              <StateBadge value={a.decision === "approve" ? "approved" : "denied"} /> {a.approver_name ?? "Approver"} · {formatTime(a.decided_at)}
              {a.comment && <span className="text-muted"> · {a.comment}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Ask for one catalog action against an incident (or its primary asset). */
export function RequestActionForm({
  catalog,
  incidentId,
  aiRunId,
  actionKey,
  justification,
}: {
  catalog: CatalogEntry[];
  incidentId: string;
  aiRunId?: string;
  actionKey?: string;
  justification?: string;
}) {
  const allowed = catalog.filter((c) => c.allowed);
  return (
    <ActionForm action={requestAction} submitLabel={aiRunId ? "Request this action" : "Request action"} resetOnSuccess={!aiRunId}>
      <input type="hidden" name="incident_id" value={incidentId} />
      {aiRunId && <input type="hidden" name="ai_run_id" value={aiRunId} />}
      {actionKey ? (
        <input type="hidden" name="action_key" value={actionKey} />
      ) : (
        <Field label="Action" hint="Asset actions run against the incident's primary asset.">
          <select name="action_key" required className="input w-full">
            {allowed.map((c) => (
              <option key={c.key} value={c.key}>
                {c.key} · {c.effective_tier} · {c.description}
              </option>
            ))}
          </select>
        </Field>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Mode">
          <select name="mode" defaultValue="dry_run" className="input w-full">
            <option value="dry_run">Dry run: preview only</option>
            <option value="simulate">Simulate: sandbox connector</option>
          </select>
        </Field>
        <Field label="Parameters (JSON, optional)">
          <input name="params" placeholder='{"reason": "…"}' maxLength={4000} className="input w-full font-mono" />
        </Field>
      </div>
      <Field label="Justification">
        <input name="justification" maxLength={1000} defaultValue={justification} className="input w-full" />
      </Field>
      <p className="text-muted text-xs">Live execution is disabled in this build; it is not an option here and the API refuses it.</p>
    </ActionForm>
  );
}
