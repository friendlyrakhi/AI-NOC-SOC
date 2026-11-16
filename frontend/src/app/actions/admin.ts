"use server";

import { revalidatePath } from "next/cache";

import type { FormState } from "@/lib/forms";
import { all, str } from "@/lib/forms";
import { apiFetch, type ApiResult } from "@/lib/server/api";

/**
 * Admin mutations. Sensitive endpoints need a recent step-up, so forms for them carry an
 * authenticator code: we step up first, then call the endpoint.
 */
async function withStepUp<T>(form: FormData, call: () => Promise<ApiResult<T>>): Promise<ApiResult<T> | FormState> {
  const code = str(form, "mfa_code");
  if (code) {
    const s = await apiFetch("/auth/step-up", { method: "POST", body: { code } });
    if (!s.ok) return { ok: false, error: s.problem.detail ?? s.problem.title };
  }
  return call();
}

function done<T>(r: ApiResult<T> | FormState, message: string, path: string): FormState {
  if ("problem" in r) {
    const hint = r.problem.code === "auth.step_up_required" ? " Enter your authenticator code." : "";
    return { ok: false, error: `${r.problem.detail ?? r.problem.title}${hint}` };
  }
  if ("data" in r) {
    revalidatePath(path);
    return { ok: true, message };
  }
  return r;
}

export async function renameTenant(_: FormState, form: FormData): Promise<FormState> {
  const r = await withStepUp(form, () =>
    apiFetch("/tenant", { method: "PATCH", body: { name: str(form, "name") } }),
  );
  return done(r, "Tenant renamed.", "/admin");
}

export async function inviteMember(_: FormState, form: FormData): Promise<FormState> {
  const r = await apiFetch<{ invitation_sent: boolean }>("/users", {
    method: "POST",
    body: { email: str(form, "email"), display_name: str(form, "display_name"), role_ids: all(form, "role_ids") },
  });
  if (!r.ok) return done(r, "", "/admin/users");
  revalidatePath("/admin/users");
  return {
    ok: true,
    message: r.data.invitation_sent
      ? "Invitation sent. In development it appears in Mailpit (http://127.0.0.1:8025)."
      : "Existing user added to this tenant.",
  };
}

export async function assignRoles(_: FormState, form: FormData): Promise<FormState> {
  const userId = str(form, "user_id");
  const r = await withStepUp(form, () =>
    apiFetch(`/users/${userId}/roles`, { method: "PUT", body: { role_ids: all(form, "role_ids") } }),
  );
  return done(r, "Roles updated.", `/admin/users/${userId}`);
}

export async function setMemberStatus(_: FormState, form: FormData): Promise<FormState> {
  const userId = str(form, "user_id");
  const r = await withStepUp(form, () =>
    apiFetch(`/users/${userId}`, { method: "PATCH", body: { status: str(form, "status") } }),
  );
  return done(r, "Membership updated.", `/admin/users/${userId}`);
}

export async function removeMember(_: FormState, form: FormData): Promise<FormState> {
  const userId = str(form, "user_id");
  const r = await withStepUp(form, () => apiFetch(`/users/${userId}`, { method: "DELETE" }));
  return done(r, "Member removed.", "/admin/users");
}

export async function createRole(_: FormState, form: FormData): Promise<FormState> {
  const r = await withStepUp(form, () =>
    apiFetch("/roles", {
      method: "POST",
      body: {
        key: str(form, "key"),
        name: str(form, "name"),
        description: str(form, "description"),
        permissions: all(form, "permissions"),
      },
    }),
  );
  return done(r, "Role created.", "/admin/roles");
}

export async function deleteRole(_: FormState, form: FormData): Promise<FormState> {
  const r = await withStepUp(form, () => apiFetch(`/roles/${str(form, "role_id")}`, { method: "DELETE" }));
  return done(r, "Role deleted.", "/admin/roles");
}

export async function createApiKey(_: FormState, form: FormData): Promise<FormState> {
  const r = await withStepUp(form, () =>
    apiFetch<{ key: string }>("/api-keys", {
      method: "POST",
      body: {
        name: str(form, "name"),
        permissions: all(form, "permissions"),
        expires_in_days: Number(str(form, "expires_in_days") || 90),
      },
    }),
  );
  if ("data" in r && r.ok) {
    revalidatePath("/admin/api-keys");
    return { ok: true, message: "API key created. Copy it now; it is shown only once.", secret: r.data.key };
  }
  return done(r, "", "/admin/api-keys");
}

export async function revokeApiKey(_: FormState, form: FormData): Promise<FormState> {
  const r = await withStepUp(form, () => apiFetch(`/api-keys/${str(form, "key_id")}`, { method: "DELETE" }));
  return done(r, "API key revoked.", "/admin/api-keys");
}

export async function onboardCustomer(_: FormState, form: FormData): Promise<FormState> {
  const r = await withStepUp(form, () =>
    apiFetch("/customers", {
      method: "POST",
      body: {
        name: str(form, "name"),
        slug: str(form, "slug"),
        admin_email: str(form, "admin_email"),
        admin_name: str(form, "admin_name"),
      },
    }),
  );
  return done(r, "Customer onboarded. Their administrator has been invited.", "/admin/customers");
}

export async function createDelegation(_: FormState, form: FormData): Promise<FormState> {
  const expires = str(form, "expires_at");
  const r = await withStepUp(form, () =>
    apiFetch("/delegations", {
      method: "POST",
      body: {
        customer_tenant_id: str(form, "customer_tenant_id"),
        msp_role_id: str(form, "msp_role_id"),
        customer_role_key: str(form, "customer_role_key"),
        aggregate_read: form.get("aggregate_read") === "on",
        expires_at: expires ? new Date(expires).toISOString() : null,
      },
    }),
  );
  return done(r, "Delegation granted.", "/admin/delegations");
}

export async function revokeDelegation(_: FormState, form: FormData): Promise<FormState> {
  const r = await withStepUp(form, () =>
    apiFetch(`/delegations/${str(form, "delegation_id")}/revoke`, { method: "POST" }),
  );
  return done(r, "Delegation revoked. It takes effect immediately.", "/admin/delegations");
}

export async function createMsp(_: FormState, form: FormData): Promise<FormState> {
  const r = await apiFetch("/platform/tenants", {
    method: "POST",
    body: {
      name: str(form, "name"),
      slug: str(form, "slug"),
      admin_email: str(form, "admin_email"),
      admin_name: str(form, "admin_name"),
    },
  });
  return done(r, "MSP tenant created and its administrator invited.", "/admin/platform");
}
