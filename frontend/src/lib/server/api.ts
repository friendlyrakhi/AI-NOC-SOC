import "server-only";

import { redirect } from "next/navigation";
import { cache } from "react";

import type { components } from "@/lib/api/schema";
import { getSessionToken } from "@/lib/server/session";

export type Schemas = components["schemas"];
export type Me = Schemas["MeResponse"];

const API = process.env.NOCSOC_API_INTERNAL_URL ?? "http://127.0.0.1:8100";

export interface Problem {
  status: number;
  code: string;
  title: string;
  detail?: string | null;
}

export type ApiResult<T> = { ok: true; status: number; data: T } | { ok: false; status: number; problem: Problem };

/** Calls the API from the server with the caller's session token (never from the browser). */
export async function apiFetch<T>(
  path: string,
  init: { method?: string; body?: unknown; token?: string | null; auth?: boolean } = {},
): Promise<ApiResult<T>> {
  const token = init.auth === false ? null : (init.token ?? (await getSessionToken()));
  const res = await fetch(`${API}/api/v1${path}`, {
    method: init.method ?? "GET",
    headers: {
      ...(init.body !== undefined ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    cache: "no-store",
  });
  if (res.status === 204) return { ok: true, status: 204, data: undefined as T };
  const text = await res.text();
  const json = text ? JSON.parse(text) : undefined;
  if (res.ok) return { ok: true, status: res.status, data: json as T };
  return {
    ok: false,
    status: res.status,
    problem: {
      status: res.status,
      code: json?.code ?? "http.error",
      title: json?.title ?? res.statusText,
      detail: json?.detail ?? null,
    },
  };
}

/** GET that redirects to sign-in on 401 and throws on other failures. */
export async function apiGet<T>(path: string): Promise<T> {
  const r = await apiFetch<T>(path);
  if (r.ok) return r.data;
  if (r.status === 401) redirect("/login?expired=1");
  throw new Error(`${r.problem.code}: ${r.problem.detail ?? r.problem.title}`);
}

/** GET that returns null for 403/404/409 (the page shows an empty or "not available" state). */
export async function apiGetOptional<T>(path: string): Promise<T | null> {
  const r = await apiFetch<T>(path);
  if (r.ok) return r.data;
  if (r.status === 401) redirect("/login?expired=1");
  if ([403, 404, 409].includes(r.status)) return null;
  throw new Error(`${r.problem.code}: ${r.problem.detail ?? r.problem.title}`);
}

/** The signed-in user and their context. One API call per request. */
export const getMe = cache(async (): Promise<Me> => {
  const token = await getSessionToken();
  if (!token) redirect("/login");
  return apiGet<Me>("/auth/me");
});

export function has(me: Me, permission: string): boolean {
  return me.permissions.includes(permission);
}
