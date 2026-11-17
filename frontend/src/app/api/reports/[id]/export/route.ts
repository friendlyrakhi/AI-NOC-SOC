import { getSessionToken } from "@/lib/server/session";

/**
 * Report download (CSV or PDF) through the BFF: the HttpOnly session stays server-side and the
 * API checks permission, tenant and audit on every export. Only a UUID and a known format pass.
 */
export const dynamic = "force-dynamic";

const API = process.env.NOCSOC_API_INTERNAL_URL ?? "http://127.0.0.1:8100";
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await params;
  const format = new URL(request.url).searchParams.get("format") === "pdf" ? "pdf" : "csv";
  if (!ID.test(id)) return new Response(null, { status: 404 });
  const token = await getSessionToken();
  if (!token) return new Response(null, { status: 401 });
  let upstream: Response;
  try {
    upstream = await fetch(`${API}/api/v1/reports/${id}/export?format=${format}`, {
      headers: { authorization: `Bearer ${token}` },
      cache: "no-store",
    });
  } catch {
    return new Response("The API is not reachable.", { status: 503 });
  }
  if (!upstream.ok) {
    return new Response(upstream.status === 404 ? "Report not found." : "Export failed.", {
      status: upstream.status,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }
  return new Response(upstream.body, {
    headers: {
      "content-type": upstream.headers.get("content-type") ?? "application/octet-stream",
      "content-disposition": upstream.headers.get("content-disposition") ?? `attachment; filename="report.${format}"`,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}
