"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import type { FormState } from "@/lib/forms";
import { str } from "@/lib/forms";
import { apiFetch, type ApiResult, type Schemas } from "@/lib/server/api";

/**
 * Integration administration. All calls go server-side with the session token; credentials
 * pass through once and are never read back (the API has no endpoint that returns them).
 */
async function withStepUp<T>(form: FormData, call: () => Promise<ApiResult<T>>): Promise<ApiResult<T> | FormState> {
  const code = str(form, "mfa_code");
  if (code) {
    const s = await apiFetch("/auth/step-up", { method: "POST", body: { code } });
    if (!s.ok) return { ok: false, error: s.problem.detail ?? s.problem.title };
  }
  return call();
}

function fail(r: { problem: { code: string; detail?: string | null; title: string } }): FormState {
  const hint = r.problem.code === "auth.step_up_required" ? " Enter your authenticator code." : "";
  return { ok: false, error: `${r.problem.detail ?? r.problem.title}${hint}` };
}

function refresh(id?: string) {
  revalidatePath("/connectors");
  if (id) revalidatePath(`/connectors/${id}`);
}

const ID = /^[0-9a-f-]{36}$/i;

function instanceId(form: FormData): string {
  const id = str(form, "instance_id");
  if (!ID.test(id)) throw new Error("invalid instance id");
  return id;
}

export async function createInstance(_: FormState, form: FormData): Promise<FormState> {
  const r = await apiFetch<Schemas["InstanceCreated"]>("/connectors/instances", {
    method: "POST",
    body: { definition_id: str(form, "definition_id"), name: str(form, "name"), config: {} },
  });
  if (!r.ok) return fail(r);
  refresh();
  return {
    ok: true,
    message: `Added "${r.data.name}" in sandbox mode. The runner reports its health after the first run.`,
    secret: r.data.webhook_secret
      ? `Webhook secret: ${r.data.webhook_secret}\nIngress: POST /api/v1/ingest/webhooks/${r.data.id}`
      : undefined,
  };
}

export async function setEnabled(_: FormState, form: FormData): Promise<FormState> {
  const id = instanceId(form);
  const enabled = str(form, "enabled") === "true";
  const r = await apiFetch(`/connectors/instances/${id}`, {
    method: "PATCH",
    body: { enabled, version: Number(str(form, "version")) },
  });
  if (!r.ok) return fail(r);
  refresh(id);
  return { ok: true, message: enabled ? "Enabled. Awaiting the next run." : "Disabled." };
}

export async function requestSync(_: FormState, form: FormData): Promise<FormState> {
  const id = instanceId(form);
  const r = await apiFetch(`/connectors/instances/${id}/sync`, { method: "POST" });
  if (!r.ok) return fail(r);
  refresh(id);
  return { ok: true, message: "Sync requested. The runner picks it up within a few seconds." };
}

export async function testInstance(_: FormState, form: FormData): Promise<FormState> {
  const id = instanceId(form);
  const r = await apiFetch<Schemas["ConnectionTestOut"]>(`/connectors/instances/${id}/test`, { method: "POST" });
  if (!r.ok) return fail(r);
  return r.data.ok ? { ok: true, message: r.data.detail } : { ok: false, error: r.data.detail };
}

export async function setFaults(_: FormState, form: FormData): Promise<FormState> {
  const id = instanceId(form);
  const current = await apiFetch<Schemas["InstanceOut"]>(`/connectors/instances/${id}`);
  if (!current.ok) return fail(current);
  const rate = (k: string) => Math.min(1, Math.max(0, Number(str(form, k) || 0) / 100));
  const faults = {
    auth_failure: form.get("auth_failure") === "on",
    error_rate: rate("error_rate"),
    rate_limit_rate: rate("rate_limit_rate"),
    schema_drift_rate: rate("schema_drift_rate"),
    latency_ms: Math.min(10_000, Math.max(0, Number(str(form, "latency_ms") || 0))),
  };
  const active = faults.auth_failure || faults.error_rate || faults.rate_limit_rate || faults.schema_drift_rate || faults.latency_ms;
  const config: Record<string, unknown> = { ...(current.data.config as Record<string, unknown>) };
  delete config.sandbox_faults;
  if (active) config.sandbox_faults = faults;
  const r = await apiFetch(`/connectors/instances/${id}`, {
    method: "PATCH",
    body: { config, version: current.data.version },
  });
  if (!r.ok) return fail(r);
  // Request a run now so the health change is visible without waiting for the schedule.
  await apiFetch(`/connectors/instances/${id}/sync`, { method: "POST" });
  refresh(id);
  return { ok: true, message: active ? "Fault injection applied. Watch the status after the next run." : "Faults cleared." };
}

export async function setCredentials(_: FormState, form: FormData): Promise<FormState> {
  const id = instanceId(form);
  const secrets: Record<string, string> = {};
  for (const [key, value] of form.entries()) {
    if (key.startsWith("secret:") && typeof value === "string" && value.length > 0) secrets[key.slice(7)] = value;
  }
  if (!Object.keys(secrets).length) return { ok: false, error: "Enter at least one value." };
  const r = await withStepUp(form, () => apiFetch(`/connectors/instances/${id}/credentials`, { method: "PUT", body: { secrets } }));
  if ("problem" in r) return fail(r);
  if ("error" in r) return r;
  refresh(id);
  return { ok: true, message: "Credentials saved (encrypted). They cannot be viewed again." };
}

export async function rotateWebhookSecret(_: FormState, form: FormData): Promise<FormState> {
  const id = instanceId(form);
  const r = await withStepUp(form, () =>
    apiFetch<Schemas["WebhookSecretOut"]>(`/connectors/instances/${id}/webhook-secret`, { method: "POST" }),
  );
  if ("problem" in r) return fail(r);
  if (!("data" in r)) return r;
  refresh(id);
  return { ok: true, message: "New webhook secret issued. The previous one no longer works.", secret: r.data.webhook_secret };
}

export async function deleteInstance(_: FormState, form: FormData): Promise<FormState> {
  const id = instanceId(form);
  const r = await withStepUp(form, () => apiFetch(`/connectors/instances/${id}`, { method: "DELETE" }));
  if ("problem" in r) return fail(r);
  if (!("data" in r)) return r;
  refresh();
  redirect("/connectors");
}

export async function replayScenario(_: FormState, form: FormData): Promise<FormState> {
  const key = str(form, "scenario");
  if (!/^[a-z_]{1,64}$/.test(key)) return { ok: false, error: "Unknown scenario." };
  const times = Math.min(10, Math.max(1, Number(str(form, "times") || 1)));
  const r = await apiFetch<Schemas["ReplayOut"]>(`/connectors/scenarios/${key}/replay?times=${times}`, { method: "POST" });
  if (!r.ok) return fail(r);
  revalidatePath("/", "layout");
  const missing = r.data.missing.length ? ` Not included (no sandbox instance): ${r.data.missing.join(", ")}.` : "";
  return { ok: true, message: `Published ${r.data.published} records through the pipeline.${missing}` };
}
