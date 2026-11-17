/**
 * Optional single sign-on (P7): asks the API for an authorization URL (state, nonce and PKCE are
 * created and kept server-side by the API) and sends the browser to the identity provider.
 */
export const dynamic = "force-dynamic";

const API = process.env.NOCSOC_API_INTERNAL_URL ?? "http://127.0.0.1:8100";

/** Relative redirects: behind the TLS edge or in a container, request.url has the internal host. */
const redirect = (location: string) => new Response(null, { status: 303, headers: { Location: location } });

export async function GET(): Promise<Response> {
  const failed = "/login?sso=failed";
  try {
    const r = await fetch(`${API}/api/v1/auth/oidc/start`, { method: "POST", cache: "no-store" });
    if (!r.ok) return redirect(failed);
    const { authorization_url: target } = (await r.json()) as { authorization_url: string };
    if (!/^https?:\/\//.test(target)) return redirect(failed);
    return redirect(target);
  } catch {
    return redirect(failed);
  }
}
