"use server";

import { revalidatePath } from "next/cache";

import type { FormState } from "@/lib/forms";
import { str } from "@/lib/forms";
import { apiFetch, type ApiResult, type Schemas } from "@/lib/server/api";

/**
 * AI assistance. Requests go server-side with the session; the API assembles evidence, the AI
 * gateway produces a structured answer, and the API validates it before anything is stored.
 * Nothing here changes an incident or alert.
 */
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TASKS = new Set(["summary", "triage", "rca", "pir-draft"]);

function id(form: FormData, name: string): string {
  const value = str(form, name);
  if (!ID.test(value)) throw new Error(`invalid ${name}`);
  return value;
}

function fail(r: { problem: { code: string; detail?: string | null; title: string } }): FormState {
  const hint = r.problem.code === "auth.step_up_required" ? " Enter your authenticator code." : "";
  return { ok: false, error: `${r.problem.detail ?? r.problem.title}${hint}` };
}

const STATUS_TEXT: Record<string, string> = {
  grounded: "Done: every statement cites evidence.",
  partially_grounded: "Done, with some unsupported statements removed.",
  insufficient_evidence: "The evidence was not enough for an answer.",
  rejected: "The answer could not be used.",
};

export async function runIncidentAi(_: FormState, form: FormData): Promise<FormState> {
  const incidentId = id(form, "incident_id");
  const task = str(form, "task");
  if (!TASKS.has(task)) return { ok: false, error: "Unknown AI task." };
  const r = await apiFetch<Schemas["AiRunOut"]>(`/ai/incidents/${incidentId}/${task}`, { method: "POST" });
  if (!r.ok) return fail(r);
  revalidatePath(`/incidents/${incidentId}`);
  return { ok: true, message: STATUS_TEXT[r.data.validation_status] };
}

export async function askIncidentAi(_: FormState, form: FormData): Promise<FormState> {
  const incidentId = id(form, "incident_id");
  const question = str(form, "question");
  if (question.length < 2) return { ok: false, error: "Ask a question." };
  const r = await apiFetch<Schemas["AiRunOut"]>("/ai/chat", {
    method: "POST",
    body: { subject_type: "incident", subject_id: incidentId, question },
  });
  if (!r.ok) return fail(r);
  revalidatePath(`/incidents/${incidentId}`);
  return { ok: true, message: STATUS_TEXT[r.data.validation_status] };
}

export async function rateRun(_: FormState, form: FormData): Promise<FormState> {
  const runId = id(form, "run_id");
  const rating = str(form, "rating") === "1" ? 1 : -1;
  const r = await apiFetch(`/ai/runs/${runId}/feedback`, { method: "POST", body: { rating, comment: "" } });
  if (!r.ok) return fail(r);
  const back = str(form, "back");
  if (back.startsWith("/")) revalidatePath(back);
  return { ok: true, message: "Thanks for the feedback." };
}

async function withStepUp<T>(form: FormData, call: () => Promise<ApiResult<T>>): Promise<ApiResult<T> | FormState> {
  const code = str(form, "mfa_code");
  if (code) {
    const s = await apiFetch("/auth/step-up", { method: "POST", body: { code } });
    if (!s.ok) return { ok: false, error: s.problem.detail ?? s.problem.title };
  }
  return call();
}

export async function saveAiSettings(_: FormState, form: FormData): Promise<FormState> {
  const provider = str(form, "provider");
  if (!["mock", "ollama", "anthropic"].includes(provider)) return { ok: false, error: "Choose a provider." };
  const body = {
    provider,
    allow_cloud: form.get("allow_cloud") === "on",
    redact_pii: form.get("redact_pii") === "on",
    daily_token_budget: Math.max(0, Math.min(100_000_000, Number(str(form, "daily_token_budget") || 0))),
    auto_summarize: false,
  };
  const r = await withStepUp(form, () => apiFetch("/ai/settings", { method: "PUT", body }));
  if ("problem" in r) return fail(r);
  if ("error" in r && r.error) return r as FormState;
  revalidatePath("/admin/ai");
  return { ok: true, message: "AI settings saved." };
}

export async function publishDoc(_: FormState, form: FormData): Promise<FormState> {
  const body = { kind: str(form, "kind") || "runbook", title: str(form, "title"), body: str(form, "body") };
  if (!body.title || !body.body) return { ok: false, error: "Add a title and content." };
  const r = await withStepUp(form, () => apiFetch("/knowledge/docs", { method: "POST", body }));
  if ("problem" in r) return fail(r);
  if ("error" in r && r.error) return r as FormState;
  revalidatePath("/knowledge");
  return { ok: true, message: "Published. It is now available as AI evidence." };
}

export async function suggestQuery(_: FormState, form: FormData): Promise<FormState> {
  const intent = str(form, "intent");
  if (intent.length < 3) return { ok: false, error: "Describe what you are looking for." };
  const r = await apiFetch<Schemas["AiRunOut"]>("/ai/query-assist", { method: "POST", body: { intent } });
  if (!r.ok) return fail(r);
  const q = (r.data.output as { query?: { target: string; filters: Record<string, unknown> } | null }).query;
  if (!q) return { ok: false, error: "No search could be suggested for that request." };
  const f = q.filters as { severity?: string[]; status?: string[]; domain?: string; connector?: string; q?: string };
  const parts = [
    f.severity?.length ? `severity: ${f.severity.join(", ")}` : null,
    f.status?.length ? `status: ${f.status.join(", ")}` : null,
    f.domain ? `domain: ${f.domain.toUpperCase()}` : null,
    f.connector ? `source: ${f.connector}` : null,
    f.q ? `text: "${f.q}"` : null,
  ].filter(Boolean);
  const terms = [f.q, f.connector].filter(Boolean).join(" ").trim();
  return {
    ok: true,
    message: `Suggested ${q.target} search (not run): ${parts.join(" · ") || "no filters"}.${terms ? ` Search text: ${terms}` : ""}`,
  };
}
