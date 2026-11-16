"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import type { FormState } from "@/lib/forms";
import { str } from "@/lib/forms";
import { apiFetch } from "@/lib/server/api";
import {
  clearChallenge,
  clearSession,
  getChallenge,
  setChallenge,
  setSessionToken,
} from "@/lib/server/session";

/** Only same-site relative paths are accepted as a post-login destination (no open redirect). */
function safeNext(value: string): string {
  return value.startsWith("/") && !value.startsWith("//") && !value.startsWith("/\\") ? value : "/";
}

interface LoginResponse {
  status: "authenticated" | "mfa_required" | "mfa_enrollment_required";
  session_token: string | null;
  challenge: string | null;
}

export async function login(_: FormState, form: FormData): Promise<FormState> {
  const next = safeNext(str(form, "next"));
  const r = await apiFetch<LoginResponse>("/auth/login", {
    method: "POST",
    auth: false,
    body: { email: str(form, "email"), password: form.get("password") ?? "" },
  });
  if (!r.ok) {
    return { ok: false, error: r.status === 422 ? "Enter a valid email and password." : (r.problem.detail ?? r.problem.title) };
  }
  if (r.data.status === "authenticated" && r.data.session_token) {
    await setSessionToken(r.data.session_token);
    redirect(next);
  }
  await setChallenge(r.data.challenge ?? "");
  redirect(`${r.data.status === "mfa_required" ? "/login/mfa" : "/login/enroll"}?next=${encodeURIComponent(next)}`);
}

async function finishWithCode(path: string, form: FormData): Promise<FormState> {
  const challenge = await getChallenge();
  if (!challenge) return { ok: false, error: "Your sign-in expired. Start again." };
  const r = await apiFetch<{ session_token: string }>(path, {
    method: "POST",
    auth: false,
    body: { challenge, code: str(form, "code") },
  });
  if (!r.ok) return { ok: false, error: r.problem.detail ?? r.problem.title };
  await clearChallenge();
  await setSessionToken(r.data.session_token);
  redirect(safeNext(str(form, "next")));
}

export async function verifyMfa(_: FormState, form: FormData): Promise<FormState> {
  return finishWithCode("/auth/mfa/verify", form);
}

export async function confirmEnrollment(_: FormState, form: FormData): Promise<FormState> {
  return finishWithCode("/auth/mfa/confirm", form);
}

export async function acceptInvitation(_: FormState, form: FormData): Promise<FormState> {
  const password = String(form.get("password") ?? "");
  if (password !== String(form.get("confirm") ?? "")) return { ok: false, error: "The passwords do not match." };
  const r = await apiFetch<{ email: string }>("/auth/invitations/accept", {
    method: "POST",
    auth: false,
    body: { token: str(form, "token"), password },
  });
  if (!r.ok) return { ok: false, error: r.problem.detail ?? r.problem.title };
  redirect(`/login?invited=${encodeURIComponent(r.data.email)}`);
}

export async function logout(): Promise<void> {
  await apiFetch("/auth/logout", { method: "POST" });
  await clearSession();
  redirect("/login");
}

export async function switchTenant(form: FormData): Promise<void> {
  const value = str(form, "tenant");
  const [tenantId, mode] = value.split(":");
  await apiFetch("/auth/switch-tenant", {
    method: "POST",
    body: { tenant_id: tenantId, aggregate: mode === "aggregate" },
  });
  // The header (tenant, mode badges, portal links) lives in the layout, which Next.js keeps
  // across navigations. Refresh the whole tree so it reflects the new tenant.
  revalidatePath("/", "layout");
  redirect(safeNext(str(form, "return_to")));
}
