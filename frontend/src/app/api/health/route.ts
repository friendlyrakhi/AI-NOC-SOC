import { connection } from "next/server";

/** Liveness probe for the web container. No details are exposed. */
export async function GET() {
  await connection();
  return Response.json({ status: "ok", service: "web" });
}
