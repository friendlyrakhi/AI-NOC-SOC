"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import type { FormState } from "@/lib/forms";
import { str } from "@/lib/forms";
import { apiFetch, type ApiResult, type Schemas } from "@/lib/server/api";

/**
 * Automation: action requests, approvals, playbooks and the kill switch. The browser never
 * talks to the API; these run server-side with the session token. The API applies the policy
 * engine, two-person rule, expiry and kill switch, and refuses live execution in this build.
 */
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ACTION_KEY = /^[a-z0-9_.-]{1,80}$/;
const MODES = new Set(["dry_run", "simulate"]);

function id(form: FormData, name: string): string {
  const value = str(form, name);
  if (!ID.test(value)) throw new Error(`invalid ${name}`);
  return value;
}

function optionalId(form: FormData, name: string): string | null {
  const value = str(form, name);
  return value && ID.test(value) ? value : null;
}

function fail(r: { problem: { code: string; detail?: string | null; title: string } }): FormState {
  const hint = r.problem.code === "auth.step_up_required" ? " Enter your authenticator code." : "";
  return { ok: false, error: `${r.problem.detail ?? r.problem.title}${hint}` };
}

/** Runs a fresh step-up first when the form carries an authenticator code. */
async function withStepUp<T>(form: FormData, call: () => Promise<ApiResult<T>>): Promise<ApiResult<T> | FormState> {
  const code = str(form, "mfa_code");
  if (code) {
    const s = await apiFetch("/auth/step-up", { method: "POST", body: { code } });
    if (!s.ok) return { ok: false, error: s.problem.detail ?? s.problem.title };
  }
  return call();
}

function failed<T>(r: ApiResult<T> | FormState): FormState | null {
  if ("problem" in r) return fail(r);
  if ("error" in r && r.error) return r as FormState;
  return null;
}

function refresh(incidentId?: string | null, requestId?: string | null) {
  revalidatePath("/automation");
  revalidatePath("/automation/approvals");
  if (requestId) revalidatePath(`/automation/requests/${requestId}`);
  if (incidentId) revalidatePath(`/incidents/${incidentId}`);
}

function mode(form: FormData): string | null {
  const m = str(form, "mode") || "simulate";
  return MODES.has(m) ? m : null;
}

// ---------------------------------------------------------------- action requests
export async function requestAction(_: FormState, form: FormData): Promise<FormState> {
  const actionKey = str(form, "action_key");
  if (!ACTION_KEY.test(actionKey)) return { ok: false, error: "Choose an action." };
  const m = mode(form);
  if (!m) return { ok: false, error: "Only dry run and simulate are available. Live execution is disabled in this build." };
  let params: unknown = {};
  const raw = str(form, "params");
  if (raw) {
    try {
      params = JSON.parse(raw);
    } catch {
      return { ok: false, error: "Parameters must be a JSON object, for example {\"reason\": \"…\"}." };
    }
    if (typeof params !== "object" || params === null || Array.isArray(params)) {
      return { ok: false, error: "Parameters must be a JSON object." };
    }
  }
  const incidentId = optionalId(form, "incident_id");
  const assetId = optionalId(form, "asset_id");
  const aiRunId = optionalId(form, "ai_run_id");
  const r = await apiFetch<Schemas["RequestOut"]>("/actions/requests", {
    method: "POST",
    body: {
      action_key: actionKey,
      incident_id: incidentId,
      asset_id: assetId,
      ai_run_id: aiRunId,
      params,
      justification: str(form, "justification"),
      mode: m,
    },
  });
  if (!r.ok) return fail(r);
  refresh(incidentId, r.data.id);
  const d = r.data;
  if (d.status === "denied") {
    const reasons = (d.policy_decision as { reasons?: string[] }).reasons ?? [];
    return { ok: false, error: `Refused by policy. ${reasons.join(" ")}` };
  }
  const next =
    d.status === "pending_approval"
      ? `Waiting for ${d.required_approvals} approval${d.required_approvals > 1 ? "s from different people" : ""}.`
      : "Runs now (no approval needed for this tier).";
  return { ok: true, message: `${d.action_key} requested (${d.tier}, ${d.execution_mode.replace("_", " ")}). ${next}` };
}

async function decide(form: FormData, decision: "approve" | "deny"): Promise<FormState> {
  const requestId = id(form, "request_id");
  const comment = str(form, "comment");
  if (decision === "deny" && !comment) return { ok: false, error: "Say why you are denying it." };
  const r = await withStepUp(form, () =>
    apiFetch<Schemas["RequestOut"]>(`/actions/requests/${requestId}/${decision}`, { method: "POST", body: { comment } }),
  );
  const bad = failed(r);
  if (bad) return bad;
  const d = (r as { data: Schemas["RequestOut"] }).data;
  refresh(d.incident_id, requestId);
  if (decision === "deny") return { ok: true, message: "Denied. The request will not run." };
  const approvals = (d.approvals ?? []).filter((a) => a.decision === "approve").length;
  return {
    ok: true,
    message:
      d.status === "pending_approval"
        ? `Approved (${approvals} of ${d.required_approvals}). A different approver must also approve.`
        : "Approved. It now runs in simulate mode.",
  };
}

export async function approveRequest(_: FormState, form: FormData): Promise<FormState> {
  return decide(form, "approve");
}

export async function denyRequest(_: FormState, form: FormData): Promise<FormState> {
  return decide(form, "deny");
}

export async function cancelRequest(_: FormState, form: FormData): Promise<FormState> {
  const requestId = id(form, "request_id");
  const r = await apiFetch<Schemas["RequestOut"]>(`/actions/requests/${requestId}/cancel`, { method: "POST" });
  if (!r.ok) return fail(r);
  refresh(r.data.incident_id, requestId);
  return { ok: true, message: "Request cancelled." };
}

// ---------------------------------------------------------------- policies and kill switch
export async function setActionPolicy(_: FormState, form: FormData): Promise<FormState> {
  const actionKey = str(form, "action_key");
  if (!ACTION_KEY.test(actionKey)) return { ok: false, error: "Unknown action." };
  const tier = str(form, "tier_override");
  if (tier && !["T0", "T1", "T2", "T3"].includes(tier)) return { ok: false, error: "Choose a tier." };
  const r = await withStepUp(form, () =>
    apiFetch(`/actions/policies/${encodeURIComponent(actionKey)}`, {
      method: "PUT",
      body: {
        allowed: form.get("allowed") === "on",
        require_justification: form.get("require_justification") === "on",
        tier_override: tier || null,
      },
    }),
  );
  const bad = failed(r);
  if (bad) return bad;
  revalidatePath("/automation");
  return { ok: true, message: "Policy saved. Tiers can only be raised, never lowered below the catalog tier." };
}

export async function setKillSwitch(_: FormState, form: FormData): Promise<FormState> {
  const engaged = str(form, "engaged") === "true";
  const reason = str(form, "reason");
  if (!reason) return { ok: false, error: "Give a reason (it is recorded in the audit log)." };
  const r = await withStepUp(form, () => apiFetch("/killswitch", { method: "POST", body: { engaged, reason } }));
  const bad = failed(r);
  if (bad) return bad;
  revalidatePath("/automation");
  return {
    ok: true,
    message: engaged
      ? "Kill switch engaged. Running playbooks stop at their next step and nothing new executes."
      : "Kill switch released. Halted runs stay halted; start them again if needed.",
  };
}

// ---------------------------------------------------------------- playbooks
export async function publishVersion(_: FormState, form: FormData): Promise<FormState> {
  const playbookId = id(form, "playbook_id");
  const version = Number(str(form, "version"));
  if (!Number.isInteger(version) || version < 1) return { ok: false, error: "Invalid version." };
  const r = await withStepUp(form, () =>
    apiFetch(`/playbooks/${playbookId}/versions/${version}/publish`, { method: "POST" }),
  );
  const bad = failed(r);
  if (bad) return bad;
  revalidatePath("/automation");
  revalidatePath(`/automation/playbooks/${playbookId}`);
  return { ok: true, message: `Version ${version} published. The previous version is retired; running playbooks keep the version they started with.` };
}

export async function newVersion(_: FormState, form: FormData): Promise<FormState> {
  const playbookId = id(form, "playbook_id");
  let definition: unknown;
  try {
    definition = JSON.parse(str(form, "definition"));
  } catch {
    return { ok: false, error: "The definition is not valid JSON." };
  }
  const r = await apiFetch(`/playbooks/${playbookId}/versions`, { method: "POST", body: { definition } });
  if (!r.ok) return fail(r);
  revalidatePath(`/automation/playbooks/${playbookId}`);
  return { ok: true, message: "Draft saved. Review it, then publish it with your authenticator code." };
}

export async function runPlaybook(_: FormState, form: FormData): Promise<FormState> {
  const playbookId = id(form, "playbook_id");
  const incidentId = id(form, "incident_id");
  const m = mode(form);
  if (!m) return { ok: false, error: "Only dry run and simulate are available. Live execution is disabled in this build." };
  const r = await apiFetch<Schemas["WorkflowRunOut"]>(`/playbooks/${playbookId}/run`, {
    method: "POST",
    body: { incident_id: incidentId, mode: m },
  });
  if (!r.ok) return fail(r);
  refresh(incidentId);
  redirect(`/automation/runs/${r.data.id}`);
}

export async function cancelRun(_: FormState, form: FormData): Promise<FormState> {
  const runId = id(form, "run_id");
  const r = await apiFetch(`/workflow-runs/${runId}/cancel`, { method: "POST" });
  if (!r.ok) return fail(r);
  revalidatePath(`/automation/runs/${runId}`);
  revalidatePath("/automation");
  return { ok: true, message: "Run cancelled. Steps already done are not undone." };
}
