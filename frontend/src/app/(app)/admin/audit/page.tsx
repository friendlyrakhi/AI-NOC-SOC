import Link from "next/link";

import { AdminGuard } from "@/components/admin-guard";
import { Badge, Card, PageHeader, Table, Td, formatDate } from "@/components/ui";
import { apiGet, getMe, type Schemas } from "@/lib/server/api";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function AuditPage({ searchParams }: { searchParams: SearchParams }) {
  const me = await getMe();
  const sp = await searchParams;
  const before = typeof sp.before === "string" && /^\d+$/.test(sp.before) ? sp.before : null;
  const action = typeof sp.action === "string" && /^[a-z0-9_.]+$/.test(sp.action) ? sp.action : null;
  return (
    <>
      <PageHeader
        title="Audit log"
        description="Append-only and hash-chained. Each entry's hash covers the previous one, so modified or missing entries are detected."
      />
      <AdminGuard me={me} permission="audit:read">
        <Audit before={before} action={action} />
      </AdminGuard>
    </>
  );
}

async function Audit({ before, action }: { before: string | null; action: string | null }) {
  const params = new URLSearchParams({ limit: "50" });
  if (before) params.set("before", before);
  if (action) params.set("action", action);
  const [entries, verify] = await Promise.all([
    apiGet<Schemas["AuditOut"][]>(`/audit?${params}`),
    apiGet<Schemas["AuditVerifyOut"]>("/audit/verify"),
  ]);
  const last = entries.at(-1);
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <span>Chain integrity:</span>
          {verify.ok ? (
            <Badge tone="success">verified · {verify.checked} entries</Badge>
          ) : (
            <Badge tone="danger">
              broken at entry {verify.first_bad_seq}: {verify.reason}
            </Badge>
          )}
          <form className="ml-auto flex gap-2">
            <input name="action" defaultValue={action ?? ""} placeholder="filter: e.g. auth." className="input w-56 font-mono" />
            <button className="btn btn-ghost">Filter</button>
          </form>
        </div>
      </Card>
      <Table head={["#", "When", "Actor", "Action", "Target", "Outcome", "Details"]} empty={entries.length === 0}>
        {entries.map((e) => (
          <tr key={e.id}>
            <Td className="text-muted font-mono text-xs">{e.seq}</Td>
            <Td className="text-muted text-xs whitespace-nowrap">{formatDate(e.at)}</Td>
            <Td className="text-xs">
              {e.actor_type}
              {e.via_tenant_id && (
                <span className="ml-1">
                  <Badge tone="info">via MSP</Badge>
                </span>
              )}
              <span className="text-muted block font-mono">{e.actor_ip ?? ""}</span>
            </Td>
            <Td className="font-mono text-xs">{e.action}</Td>
            <Td className="text-xs">{e.target_type ? `${e.target_type} ${e.target_id?.slice(0, 8) ?? ""}` : "—"}</Td>
            <Td>
              <Badge tone={e.outcome === "success" ? "success" : e.outcome === "denied" ? "warning" : "danger"}>
                {e.outcome}
              </Badge>
            </Td>
            <Td className="max-w-xs">
              <code className="text-muted block truncate text-xs" title={JSON.stringify(e.details)}>
                {Object.keys(e.details).length ? JSON.stringify(e.details) : ""}
              </code>
            </Td>
          </tr>
        ))}
      </Table>
      {last && entries.length === 50 && (
        <Link
          href={`/admin/audit?before=${last.id}${action ? `&action=${action}` : ""}`}
          className="text-primary text-sm hover:underline"
        >
          Older entries →
        </Link>
      )}
    </div>
  );
}
