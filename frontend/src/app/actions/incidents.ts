"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import type { FormState } from "@/lib/forms";
import { str } from "@/lib/forms";
import { apiFetch, type ApiResult, type Schemas } from "@/lib/server/api";

/**
 * Incident workflow, maintenance windows, suppression and correlation tuning. Every call goes
 * server-side with the session token; the API enforces permissions, versions and audit.
 */
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function id(form: FormData, name: string): string {
  const value = str(form, name);
  if (!ID.test(value)) throw new Error(`invalid ${name}`);
  return value;
}

function fail(r: { problem: { code: string; detail?: string | null; title: string } }): FormState {
  const hint =
    r.problem.code === "auth.step_up_required"
      ? " Enter your authenticator code."
      : r.problem.code === "conflict.version"
        ? " Reload the page to see the latest version."
        : "";
  return { ok: false, error: `${r.problem.detail ?? r.problem.title}${hint}` };
}

async function withStepUp<T>(form: FormData, call: () => Promise<ApiResult<T>>): Promise<ApiResult<T> | FormState> {
  const code = str(form, "mfa_code");
  if (code) {
    const s = await apiFetch("/auth/step-up", { method: "POST", body: { code } });
    if (!s.ok) return { ok: false, error: s.problem.detail ?? s.problem.title };
  }
  return call();
}

function refreshIncident(incidentId?: string) {
  revalidatePath("/incidents");
  if (incidentId) revalidatePath(`/incidents/${incidentId}`);
  revalidatePath("/noc/alerts");
  revalidatePath("/soc/siem");
}

// ---------------------------------------------------------------- incidents
const STATUSES = new Set(["investigating", "contained", "mitigated", "resolved", "closed"]);

export async function changeStatus(_: FormState, form: FormData): Promise<FormState> {
  const incidentId = id(form, "incident_id");
  const to = str(form, "to");
  if (!STATUSES.has(to)) return { ok: false, error: "Choose a status." };
  const r = await apiFetch<Schemas["IncidentOut"]>(`/incidents/${incidentId}/status`, {
    method: "POST",
    body: { to, version: Number(str(form, "version")), reason: str(form, "reason") || null },
  });
  if (!r.ok) return fail(r);
  refreshIncident(incidentId);
  return { ok: true, message: `Status is now ${to}.` };
}

export async function escalateIncident(_: FormState, form: FormData): Promise<FormState> {
  const incidentId = id(form, "incident_id");
  const reason = str(form, "reason");
  if (!reason) return { ok: false, error: "Say why the other team is needed." };
  const r = await apiFetch(`/incidents/${incidentId}/escalate`, { method: "POST", body: { to_domain: "joint", reason } });
  if (!r.ok) return fail(r);
  refreshIncident(incidentId);
  return { ok: true, message: "Escalated: the incident is now visible in both the NOC and SOC portals." };
}

export async function addComment(_: FormState, form: FormData): Promise<FormState> {
  const incidentId = id(form, "incident_id");
  const body = str(form, "body");
  if (!body) return { ok: false, error: "Write a comment first." };
  const r = await apiFetch(`/incidents/${incidentId}/comments`, { method: "POST", body: { body } });
  if (!r.ok) return fail(r);
  refreshIncident(incidentId);
  return { ok: true, message: "Comment added." };
}

export async function assignToMe(_: FormState, form: FormData): Promise<FormState> {
  const incidentId = id(form, "incident_id");
  const me = await apiFetch<Schemas["MeResponse"]>("/auth/me");
  if (!me.ok) return fail(me);
  const r = await apiFetch(`/incidents/${incidentId}`, {
    method: "PATCH",
    body: { assignee_id: me.data.user_id, version: Number(str(form, "version")) },
  });
  if (!r.ok) return fail(r);
  refreshIncident(incidentId);
  return { ok: true, message: "Assigned to you." };
}

export async function addTask(_: FormState, form: FormData): Promise<FormState> {
  const incidentId = id(form, "incident_id");
  const title = str(form, "title");
  if (!title) return { ok: false, error: "Name the task." };
  const r = await apiFetch(`/incidents/${incidentId}/tasks`, { method: "POST", body: { title } });
  if (!r.ok) return fail(r);
  refreshIncident(incidentId);
  return { ok: true, message: "Task added." };
}

export async function setTaskStatus(_: FormState, form: FormData): Promise<FormState> {
  const incidentId = id(form, "incident_id");
  const taskId = id(form, "task_id");
  const status = str(form, "status");
  if (!["open", "in_progress", "done"].includes(status)) return { ok: false, error: "Invalid task status." };
  const r = await apiFetch(`/incidents/${incidentId}/tasks/${taskId}`, {
    method: "PATCH",
    body: { status, version: Number(str(form, "version")) },
  });
  if (!r.ok) return fail(r);
  refreshIncident(incidentId);
  return { ok: true, message: status === "done" ? "Task done." : "Task reopened." };
}

export async function openServiceNowTicket(_: FormState, form: FormData): Promise<FormState> {
  const incidentId = id(form, "incident_id");
  const r = await apiFetch<Schemas["IncidentOut"]>(`/incidents/${incidentId}/external-tickets`, {
    method: "POST",
    body: { system: "servicenow" },
  });
  if (!r.ok) return fail(r);
  refreshIncident(incidentId);
  const t = r.data.external_tickets[0];
  return { ok: true, message: `Linked ServiceNow ${t?.external_number ?? ""} (sandbox, simulated). Status changes now sync both ways.` };
}

export async function createIncident(_: FormState, form: FormData): Promise<FormState> {
  const domain = str(form, "domain");
  const severity = str(form, "severity");
  const title = str(form, "title");
  if (!title) return { ok: false, error: "Give the incident a title." };
  if (!["noc", "soc"].includes(domain) || !["critical", "high", "medium", "low"].includes(severity)) {
    return { ok: false, error: "Choose a domain and severity." };
  }
  const r = await apiFetch<Schemas["IncidentOut"]>("/incidents", {
    method: "POST",
    body: { title, domain, severity, summary: str(form, "summary") },
  });
  if (!r.ok) return fail(r);
  refreshIncident();
  redirect(`/incidents/${r.data.id}`);
}

// ---------------------------------------------------------------- maintenance and suppression
export async function createMaintenance(_: FormState, form: FormData): Promise<FormState> {
  const serviceIds = form.getAll("service_ids").map(String).filter((v) => ID.test(v));
  const hours = Math.min(168, Math.max(1, Number(str(form, "hours") || 2)));
  const startsIn = Math.min(10_080, Math.max(0, Number(str(form, "starts_in_minutes") || 0)));
  const starts = new Date(Date.now() + startsIn * 60_000);
  const ends = new Date(starts.getTime() + hours * 3_600_000);
  const r = await apiFetch("/maintenance-windows", {
    method: "POST",
    body: {
      title: str(form, "title"),
      service_ids: serviceIds,
      starts_at: starts.toISOString(),
      ends_at: ends.toISOString(),
      reason: str(form, "reason"),
    },
  });
  if (!r.ok) return fail(r);
  revalidatePath("/noc/maintenance");
  revalidatePath("/noc/topology");
  return { ok: true, message: "Maintenance window saved. Alerts on these services will not open incidents while it is active." };
}

export async function cancelMaintenance(_: FormState, form: FormData): Promise<FormState> {
  const r = await apiFetch(`/maintenance-windows/${id(form, "window_id")}`, { method: "DELETE" });
  if (!r.ok) return fail(r);
  revalidatePath("/noc/maintenance");
  revalidatePath("/noc/topology");
  return { ok: true, message: "Maintenance window cancelled." };
}

export async function createSuppression(_: FormState, form: FormData): Promise<FormState> {
  const match: Record<string, unknown> = {};
  const connector = str(form, "connector");
  const contains = str(form, "title_contains");
  const severity = str(form, "severity");
  if (connector) match.connector = connector;
  if (contains) match.title_contains = contains;
  if (severity) match.severity = [severity];
  if (!Object.keys(match).length) return { ok: false, error: "Add at least one condition." };
  const r = await apiFetch("/suppression-rules", {
    method: "POST",
    body: {
      name: str(form, "name"),
      match,
      reason: str(form, "reason"),
      expires_in_hours: Math.min(720, Math.max(1, Number(str(form, "hours") || 24))),
    },
  });
  if (!r.ok) return fail(r);
  revalidatePath("/noc/maintenance");
  return { ok: true, message: "Suppression rule active. Matching new alerts are kept but marked suppressed." };
}

export async function disableSuppression(_: FormState, form: FormData): Promise<FormState> {
  const r = await apiFetch(`/suppression-rules/${id(form, "rule_id")}`, { method: "DELETE" });
  if (!r.ok) return fail(r);
  revalidatePath("/noc/maintenance");
  return { ok: true, message: "Suppression rule disabled." };
}

export async function setCorrelationRule(_: FormState, form: FormData): Promise<FormState> {
  const key = str(form, "key");
  if (!["same_asset", "service_topology", "shared_observable"].includes(key)) return { ok: false, error: "Unknown rule." };
  const r = await withStepUp(form, () =>
    apiFetch(`/correlation-rules/${key}`, {
      method: "PATCH",
      body: { enabled: form.get("enabled") === "on", window_minutes: Number(str(form, "window_minutes") || 30) },
    }),
  );
  if ("problem" in r) return fail(r);
  if ("error" in r && r.error) return r as FormState;
  revalidatePath("/noc/maintenance");
  return { ok: true, message: "Correlation rule updated. It applies to alerts from now on." };
}
