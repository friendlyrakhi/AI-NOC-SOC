import { getSessionToken } from "@/lib/server/session";

/**
 * Live updates for the browser: proxies the API's SSE stream (GET /api/v1/stream) with the
 * HttpOnly session, so the token never reaches client code. Events carry only types and ids;
 * pages re-fetch through the normal permission-checked server calls.
 */
export const dynamic = "force-dynamic";

const API = process.env.NOCSOC_API_INTERNAL_URL ?? "http://127.0.0.1:8100";

export async function GET(request: Request): Promise<Response> {
  const token = await getSessionToken();
  if (!token) return new Response(null, { status: 401 });
  let upstream: Response;
  try {
    upstream = await fetch(`${API}/api/v1/stream`, {
      headers: { authorization: `Bearer ${token}`, accept: "text/event-stream" },
      cache: "no-store",
      signal: request.signal,
    });
  } catch {
    return new Response(null, { status: 503 });
  }
  if (!upstream.ok || !upstream.body) return new Response(null, { status: upstream.status === 200 ? 502 : upstream.status });
  return new Response(upstream.body, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store, no-transform",
      "x-accel-buffering": "no",
    },
  });
}
