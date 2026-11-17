import { setSessionToken } from "@/lib/server/session";

/**
 * Identity provider redirect target (P7). The API validates state, nonce, PKCE and the ID token and
 * returns a platform session, which is stored in the HttpOnly cookie; the token never reaches scripts.
 */
export const dynamic = "force-dynamic";

/** Relative redirects: behind the TLS edge or in a container, request.url has the internal host. */
const redirect = (location: string) => new Response(null, { status: 303, headers: { Location: location } });

const API = process.env.NOCSOC_API_INTERNAL_URL ?? "http://127.0.0.1:8100";

export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code") ?? "";
  const state = url.searchParams.get("state") ?? "";
  const failure = (reason: string) => redirect(`/login?sso=${reason}`);
  if (!code || !state || code.length > 4096 || state.length > 256) return failure("failed");
  try {
    const r = await fetch(`${API}/api/v1/auth/oidc/callback`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code, state }),
      cache: "no-store",
    });
    if (r.status === 403) return failure("no-account");
    if (!r.ok) return failure("failed");
    const { session_token: token } = (await r.json()) as { session_token: string };
    await setSessionToken(token);
  } catch {
    return failure("failed");
  }
  return redirect("/");
}
