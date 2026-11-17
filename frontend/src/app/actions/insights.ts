"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import type { FormState } from "@/lib/forms";
import { str } from "@/lib/forms";
import { apiFetch, type Schemas } from "@/lib/server/api";

/**
 * P6 actions: AI briefing, saved reports, hunts. Server-side only (session token); the API
 * checks permissions, quotas and tenant scope on every call.
 */
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function id(form: FormData, name: string): string {
  const value = str(form, name);
  if (!ID.test(value)) throw new Error(`invalid ${name}`);
  return value;
}

function fail(r: { problem: { detail?: string | null; title: string } }): FormState {
  return { ok: false, error: r.problem.detail ?? r.problem.title };
}

// ---------------------------------------------------------------- AI briefing
export async function generateBriefing(): Promise<FormState> {
  const r = await apiFetch<Schemas["AiRunOut"]>("/ai/briefing", { method: "POST" });
  if (!r.ok) return fail(r);
  revalidatePath("/command");
  const status = r.data.validation_status.replace(/_/g, " ");
  return { ok: true, message: `Briefing generated (${status}). Check every statement against its cited KPI or record.` };
}

// ---------------------------------------------------------------- reports
const KINDS = new Set(["kpi_summary", "incident_register", "sla_report"]);

export async function createReport(_: FormState, form: FormData): Promise<FormState> {
  const name = str(form, "name");
  const kind = str(form, "kind");
  const domain = str(form, "domain") || "all";
  const period = str(form, "period") || "7d";
  if (!name) return { ok: false, error: "Name the report." };
  if (!KINDS.has(kind)) return { ok: false, error: "Choose a report type." };
  if (!["all", "noc", "soc"].includes(domain) || !["24h", "7d", "30d", "90d"].includes(period)) {
    return { ok: false, error: "Choose a domain and period." };
  }
  const r = await apiFetch("/reports", { method: "POST", body: { name, kind, domain, period } });
  if (!r.ok) return fail(r);
  revalidatePath("/reports");
  return { ok: true, message: "Report saved. Export it as CSV or PDF; every export is computed fresh and audited." };
}

export async function deleteReport(_: FormState, form: FormData): Promise<FormState> {
  const r = await apiFetch(`/reports/${id(form, "report_id")}`, { method: "DELETE" });
  if (!r.ok) return fail(r);
  revalidatePath("/reports");
  return { ok: true, message: "Report deleted." };
}

// ---------------------------------------------------------------- hunting
const CLASSES = new Set(["alert", "detection", "authentication", "process", "network", "api_activity", "ticket"]);
const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

/** The constrained event query the API accepts; anything else is dropped here and refused there. */
function queryFrom(form: FormData): Record<string, unknown> {
  const q: Record<string, unknown> = {};
  const text = str(form, "text");
  if (text) q.text = text.slice(0, 300);
  const domain = str(form, "domain");
  if (domain === "noc" || domain === "soc") q.domain = domain;
  const classes = form.getAll("classes").map(String).filter((c) => CLASSES.has(c));
  if (classes.length) q.classes = classes;
  const severity = form.getAll("severity").map(String).filter((c) => SEVERITIES.has(c));
  if (severity.length) q.severity = severity;
  for (const field of ["asset", "actor_user", "ip", "connector"] as const) {
    const v = str(form, field);
    if (v) q[field] = v.slice(0, 200);
  }
  const mitre = str(form, "mitre")
    .split(/[\s,]+/)
    .filter(Boolean);
  if (mitre.length) q.mitre = mitre.slice(0, 10);
  const hours = Number(str(form, "hours") || 24);
  if (Number.isFinite(hours) && hours > 0 && hours !== 24) {
    // Both ends from one clock reading, so "last 30 days" never exceeds the API's 30-day limit.
    const now = Date.now();
    q.until = new Date(now).toISOString();
    q.since = new Date(now - Math.min(hours, 720) * 3_600_000).toISOString();
  }
  return q;
}

export async function saveHunt(_: FormState, form: FormData): Promise<FormState> {
  const name = str(form, "name");
  if (!name) return { ok: false, error: "Name the hunt." };
  const query = queryFrom(form);
  delete query.since; // saved hunts use a rolling window: the last 24 hours when run
  delete query.until;
  const r = await apiFetch("/hunts", {
    method: "POST",
    body: { name, description: str(form, "description"), query },
  });
  if (!r.ok) return fail(r);
  revalidatePath("/soc/hunting");
  return { ok: true, message: "Hunt saved. Run it any time; each run is kept with its results." };
}

export async function deleteHunt(_: FormState, form: FormData): Promise<FormState> {
  const r = await apiFetch(`/hunts/${id(form, "hunt_id")}`, { method: "DELETE" });
  if (!r.ok) return fail(r);
  revalidatePath("/soc/hunting");
  return { ok: true, message: "Hunt deleted. Its past runs are kept." };
}

export async function runHunt(_: FormState, form: FormData): Promise<FormState> {
  const huntId = str(form, "hunt_id");
  const body = ID.test(huntId) ? { hunt_id: huntId } : { query: queryFrom(form) };
  const r = await apiFetch<Schemas["HuntRunOut"]>("/hunt/queries", { method: "POST", body });
  if (!r.ok) return fail(r);
  revalidatePath("/soc/hunting");
  redirect(`/soc/hunting?run=${r.data.id}`);
}

export async function attachHunt(_: FormState, form: FormData): Promise<FormState> {
  const runId = id(form, "hunt_run_id");
  const r = await apiFetch(`/hunt/queries/${runId}/attach`, {
    method: "POST",
    body: { incident_id: id(form, "incident_id"), note: str(form, "note") },
  });
  if (!r.ok) return fail(r);
  return { ok: true, message: "Results summary added to the incident timeline." };
}
