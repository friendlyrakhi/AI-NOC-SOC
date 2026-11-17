import Link from "next/link";

import { CLASSES, EventResults, QueryFields, SEVERITIES, type EventItem } from "@/components/events";
import { SandboxNotice } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { apiFetch, getMe } from "@/lib/server/api";
import type { EventSearch } from "@/lib/server/insights";

import { DemoInvestigations } from "./_demo";

type Params = Record<string, string | string[] | undefined>;

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.trim() || undefined;
const many = (v: string | string[] | undefined) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

/** Builds the constrained event query from the URL; unknown values are dropped (the API also refuses them). */
function queryOf(sp: Params): Record<string, unknown> {
  const q: Record<string, unknown> = {};
  const text = one(sp.text);
  if (text) q.text = text.slice(0, 300);
  const domain = one(sp.domain);
  if (domain === "noc" || domain === "soc") q.domain = domain;
  const severity = many(sp.severity).filter((s) => (SEVERITIES as readonly string[]).includes(s));
  if (severity.length) q.severity = severity;
  const classes = many(sp.classes).filter((c) => (CLASSES as readonly string[]).includes(c));
  if (classes.length) q.classes = classes;
  for (const f of ["asset", "actor_user", "ip", "connector"] as const) {
    const v = one(sp[f]);
    if (v) q[f] = v.slice(0, 200);
  }
  const mitre = (one(sp.mitre) ?? "").split(/[\s,]+/).filter(Boolean);
  if (mitre.length) q.mitre = mitre.slice(0, 10);
  const hours = Number(one(sp.hours) ?? 24);
  if (Number.isFinite(hours) && hours > 0 && hours !== 24) {
    const now = Date.now(); // one clock reading for both ends (the API allows at most 30 days)
    q.until = new Date(now).toISOString();
    q.since = new Date(now - Math.min(hours, 720) * 3_600_000).toISOString();
  }
  return q;
}

export default async function InvestigatePage({ searchParams }: { searchParams: Promise<Params> }) {
  const me = await getMe();
  const denied = gate(me, "search:read", "Investigate");
  if (denied) return denied;
  const sp = await searchParams;
  const query = queryOf(sp);
  if (me.mode !== "tenant") return <DemoInvestigations />;
  const r = await apiFetch<EventSearch>("/search/events", { method: "POST", body: { query, limit: 200 } });
  // Search not running or not permitted: demo content. A rejected query: say why, keep the form.
  if (!r.ok && r.status !== 422) return <DemoInvestigations />;
  const result = r.ok ? r.data : null;
  const values = {
    text: one(sp.text),
    domain: one(sp.domain),
    severity: many(sp.severity),
    classes: many(sp.classes),
    asset: one(sp.asset),
    actor_user: one(sp.actor_user),
    ip: one(sp.ip),
    mitre: one(sp.mitre),
    hours: one(sp.hours),
  };
  return (
    <>
      <PageHeader
        title="Investigate"
        description="Search this tenant's security and operations events (last 30 days). Select an asset, user or source on the left to pivot."
        actions={
          <Link href="/incidents?portal=soc" className="btn btn-ghost border-border border text-xs">
            Open cases →
          </Link>
        }
      />
      <SandboxNotice>Events come from sandbox connectors processed by the real platform.</SandboxNotice>
      <Card className="mb-6">
        <form method="get" action="/soc/investigations" className="space-y-3">
          <QueryFields values={values} />
          <div className="flex items-center gap-3">
            <button type="submit" className="btn btn-primary">
              Search events
            </button>
            <Link href="/soc/investigations" className="text-muted text-xs hover:underline">
              Clear
            </Link>
          </div>
        </form>
      </Card>
      {result ? (
        <EventResults items={result.items as unknown as EventItem[]} total={result.total} facets={result.facets} caption="Matching events" />
      ) : (
        <p role="alert" className="text-danger text-sm">
          The search was not accepted: {!r.ok ? (r.problem.detail ?? r.problem.title) : ""}
        </p>
      )}
    </>
  );
}
