import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { askIncidentAi, rateRun, runIncidentAi } from "@/app/actions/ai";
import { RequestActionForm } from "@/components/automation";
import type { CatalogEntry } from "@/lib/server/automation";
import type { components } from "@/lib/api/schema";
import { formatTime } from "@/lib/format";

/**
 * Copilot panel. AI output is rendered as plain text only (never HTML or markdown), always
 * labelled as AI-generated with its provider, template and validation status, and every
 * statement shows chips linking to the evidence it cites. Suggested actions are suggestions:
 * a user may turn one into an action request, which always needs a human approver.
 */
type Run = components["schemas"]["AiRunOut"];
type Output = {
  claims: { text: string; citations: string[] }[];
  gaps: string[];
  suggested_actions: { action_key: string; rationale: string; citations: string[] }[];
};

const TASK_LABEL: Record<string, string> = {
  incident_summary: "Summary",
  triage: "Triage suggestion",
  rca: "Root-cause hypotheses",
  pir_draft: "Post-incident review draft",
  chat: "Answer",
  alert_summary: "Alert summary",
  query_assist: "Search suggestion",
  daily_briefing: "Daily briefing",
};

const STATUS: Record<Run["validation_status"], { label: string; tone: string }> = {
  grounded: { label: "Grounded", tone: "border-success/40 text-success" },
  partially_grounded: { label: "Partially grounded", tone: "border-caution/60 text-warning" },
  insufficient_evidence: { label: "Insufficient evidence", tone: "border-border text-muted" },
  rejected: { label: "Rejected", tone: "border-danger/40 text-danger" },
};

function evidenceHref(e: Run["evidence"][number]): string | null {
  if (e.type === "incident") return `/incidents/${e.id}`;
  if (e.type === "runbook") return `/knowledge/${e.id}`;
  if (e.type === "service") return `/noc/topology/${e.id}`;
  if (e.type === "kpi") return `/command/kpi/${e.id}?period=24h`;
  return null;
}

export function RunCard({ run, back, incidentId, requestable }: { run: Run; back: string; incidentId: string; requestable: CatalogEntry[] | null }) {
  const out = run.output as Output;
  const anchor = (ref: string) => `ev-${run.id.slice(0, 8)}-${ref}`;
  const byRef = new Map(run.evidence.map((e) => [e.ref, e]));
  const status = STATUS[run.validation_status];
  return (
    <article className="border-border rounded-md border p-3" aria-label={`${TASK_LABEL[run.task] ?? run.task} (AI-generated)`}>
      <header className="mb-2 flex flex-wrap items-center gap-2 text-xs">
        <span className="font-semibold">{TASK_LABEL[run.task] ?? run.task}</span>
        <span className="border-primary/40 text-primary rounded border px-1.5 py-px font-medium">AI-generated</span>
        <span className={`rounded border px-1.5 py-px font-medium ${status.tone}`}>{status.label}</span>
        <span className="text-muted">
          {run.provider} · {run.model} · {run.template} · confidence {Math.round(run.confidence * 100)}% · {formatTime(run.created_at)}
        </span>
      </header>
      {run.question && <p className="text-muted mb-2 text-xs">Question: {run.question}</p>}
      {run.suspicious_count > 0 && (
        <p role="note" className="border-danger/40 text-danger mb-2 rounded border px-2 py-1 text-xs">
          {run.suspicious_count} evidence item(s) contain instruction-like text (possible prompt injection). They were treated as data;
          review them before acting.
        </p>
      )}
      {out.claims.length > 0 ? (
        <ul className="space-y-2">
          {out.claims.map((c, i) => (
            <li key={i} className="text-sm">
              {c.text}{" "}
              {c.citations.map((ref) => (
                <a
                  key={ref}
                  href={`#${anchor(ref)}`}
                  title={byRef.get(ref)?.title ?? ref}
                  className="border-border text-primary ml-1 inline-block rounded border px-1 font-mono text-[11px] hover:underline"
                >
                  {ref}
                </a>
              ))}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-muted text-sm">No statements could be supported by the evidence.</p>
      )}
      {out.gaps.length > 0 && (
        <div className="mt-2">
          <p className="text-muted text-xs font-semibold">Gaps and open questions</p>
          <ul className="text-muted list-disc pl-5 text-xs">
            {out.gaps.map((g, i) => (
              <li key={i}>{g}</li>
            ))}
          </ul>
        </div>
      )}
      {out.suggested_actions.length > 0 && (
        <div className="mt-2">
          <p className="text-xs font-semibold">Suggested actions (not performed; requesting one always needs a human approver)</p>
          <ul className="list-disc pl-5 text-xs">
            {out.suggested_actions.map((a, i) => (
              <li key={i}>
                <span className="font-mono">{a.action_key}</span>: {a.rationale}{" "}
                {a.citations.map((ref) => (
                  <a key={ref} href={`#${anchor(ref)}`} className="text-primary ml-1 font-mono underline">
                    {ref}
                  </a>
                ))}
                {requestable?.some((c) => c.key === a.action_key && c.allowed) && run.validation_status !== "rejected" && (
                  <details className="mt-1">
                    <summary className="text-primary cursor-pointer">Request this action</summary>
                    <div className="mt-2">
                      <RequestActionForm
                        catalog={requestable}
                        incidentId={incidentId}
                        aiRunId={run.id}
                        actionKey={a.action_key}
                        justification={`AI suggestion: ${a.rationale}`.slice(0, 1000)}
                      />
                    </div>
                  </details>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      <details className="mt-2">
        <summary className="text-muted cursor-pointer text-xs">Evidence ({run.evidence.length})</summary>
        <ol className="mt-1 space-y-1 text-xs">
          {run.evidence.map((e) => {
            const href = evidenceHref(e);
            return (
              <li key={e.ref} id={anchor(e.ref)} className="scroll-mt-20">
                <span className="font-mono">{e.ref}</span> <span className="text-muted">{e.type}</span>{" "}
                {href ? (
                  <Link href={href} className="text-primary underline">
                    {e.title}
                  </Link>
                ) : (
                  <span>{e.title}</span>
                )}
                {e.suspicious && <span className="text-danger ml-1">(instruction-like text)</span>}
              </li>
            );
          })}
        </ol>
      </details>
      <div className="mt-2 flex items-center gap-2 text-xs">
        <span className="text-muted">{run.my_rating === 1 ? "You found this helpful." : run.my_rating === -1 ? "You marked this unhelpful." : "Helpful?"}</span>
        {(["1", "-1"] as const).map((rating) => (
          <ActionForm key={rating} action={rateRun} submitLabel={rating === "1" ? "Yes" : "No"} className="flex items-center gap-1">
            <input type="hidden" name="run_id" value={run.id} />
            <input type="hidden" name="rating" value={rating} />
            <input type="hidden" name="back" value={back} />
          </ActionForm>
        ))}
      </div>
    </article>
  );
}

export function AiPanel({
  incidentId,
  runs,
  canUse,
  requestable = null,
}: {
  incidentId: string;
  runs: Run[];
  canUse: boolean;
  /** Catalog entries the caller may request (null: may not request actions). */
  requestable?: CatalogEntry[] | null;
}) {
  const back = `/incidents/${incidentId}`;
  return (
    <section aria-labelledby="copilot-title" className="border-border rounded-lg border p-4">
      <h2 id="copilot-title" className="mb-1 text-sm font-semibold">
        AI copilot
      </h2>
      <p className="text-muted mb-3 text-xs">
        Answers come only from this incident&apos;s evidence and cite it. The copilot cannot change anything; review every statement.
      </p>
      {canUse && (
        <div className="mb-4 space-y-3">
          <div className="flex flex-wrap gap-2">
            {(
              [
                ["summary", "Summarise"],
                ["triage", "Suggest triage"],
                ["rca", "Root-cause hypotheses"],
                ["pir-draft", "Draft PIR"],
              ] as const
            ).map(([task, label]) => (
              <ActionForm key={task} action={runIncidentAi} submitLabel={label} className="flex items-center gap-2">
                <input type="hidden" name="incident_id" value={incidentId} />
                <input type="hidden" name="task" value={task} />
              </ActionForm>
            ))}
          </div>
          <ActionForm action={askIncidentAi} submitLabel="Ask" className="flex flex-wrap items-end gap-2" resetOnSuccess>
            <input type="hidden" name="incident_id" value={incidentId} />
            <label className="block flex-1">
              <span className="text-muted text-xs">Ask about this incident</span>
              <input name="question" maxLength={2000} className="input mt-1 w-full" />
            </label>
          </ActionForm>
        </div>
      )}
      <div className="space-y-3">
        {runs.length === 0 ? <p className="text-muted text-sm">No AI analysis yet.</p> : runs.map((r) => <RunCard key={r.id} run={r} back={back} incidentId={incidentId} requestable={requestable} />)}
      </div>
    </section>
  );
}
