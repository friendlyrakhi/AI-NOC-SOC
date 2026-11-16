import Link from "next/link";

import { DemoBadge, SeverityBadge } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { getDemo } from "@/lib/server/demo";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

interface Hit {
  key: string;
  title: string;
  meta: string;
  href: string;
  severity?: "critical" | "high" | "medium" | "low" | "info";
}

export default async function SearchPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const q = (typeof sp.q === "string" ? sp.q : "").trim().slice(0, 100);
  const { me, data } = await getDemo();
  const denied = gate(me, "search:read", "Search");
  if (denied) return denied;
  const term = q.toLowerCase();
  const match = (...fields: (string | null | undefined)[]) => fields.some((f) => f?.toLowerCase().includes(term));
  const has = (p: string) => me.permissions.includes(p);

  const groups: { title: string; hits: Hit[] }[] = !term
    ? []
    : [
        {
          title: "Incidents",
          hits: has("incident:read")
            ? data.incidents
                .filter((i) => match(i.number, i.title, i.service))
                .map((i) => ({ key: i.id, title: `${i.number}: ${i.title}`, meta: `${i.status} · ${i.tenant.name}`, href: `/incidents/${i.id}`, severity: i.severity }))
            : [],
        },
        {
          title: "Assets",
          hits: has("asset:read")
            ? data.assets
                .filter((a) => match(a.name, a.ip, a.service, a.kind))
                .map((a) => ({ key: a.id, title: a.name, meta: `${a.kind} · ${a.ip} · ${a.service}`, href: `/noc/assets/${a.id}` }))
            : [],
        },
        {
          title: "Alerts",
          hits: has("alert:read")
            ? data.alerts
                .filter((a) => match(a.title, a.assetName))
                .map((a) => ({
                  key: a.id,
                  title: a.title,
                  meta: `${a.assetName} · ${a.domain.toUpperCase()}`,
                  href: a.domain === "noc" ? "/noc/alerts" : "/soc/siem",
                  severity: a.severity,
                }))
            : [],
        },
        {
          title: "Indicators",
          hits: has("alert:read")
            ? data.indicators
                .filter((i) => match(i.value, i.actor))
                .map((i) => ({ key: i.id, title: i.value, meta: `${i.type} · ${i.actor}`, href: "/soc/threat-intel" }))
            : [],
        },
        {
          title: "Vulnerabilities",
          hits: has("vuln:read")
            ? data.vulns
                .filter((v) => match(v.cve, v.title, v.assetName))
                .map((v) => ({ key: v.id, title: `${v.cve}: ${v.title}`, meta: v.assetName, href: "/soc/vulnerabilities", severity: v.severity }))
            : [],
        },
      ];
  const total = groups.reduce((s, g) => s + g.hits.length, 0);

  return (
    <>
      <PageHeader title="Search" description="Across incidents, assets, alerts, indicators and vulnerabilities in your current scope." actions={<DemoBadge />} />
      <form role="search" className="mb-6 flex max-w-xl gap-2">
        <label htmlFor="search-q" className="sr-only">
          Search terms
        </label>
        <input id="search-q" name="q" type="search" defaultValue={q} placeholder="e.g. payments, 10.12., T1059, CVE-DEMO" className="input flex-1" />
        <button className="btn btn-primary">Search</button>
      </form>
      {term && (
        <p role="status" className="text-muted mb-4 text-sm">
          {total} result{total === 1 ? "" : "s"} for “{q}”
        </p>
      )}
      <div className="space-y-6">
        {groups
          .filter((g) => g.hits.length)
          .map((g) => (
            <Card key={g.title} title={`${g.title} (${g.hits.length})`}>
              <ul className="divide-border divide-y">
                {g.hits.slice(0, 10).map((h) => (
                  <li key={h.key} className="flex items-center justify-between gap-3 py-2">
                    <div className="min-w-0">
                      <Link href={h.href} className="text-primary block truncate text-sm hover:underline">
                        {h.title}
                      </Link>
                      <p className="text-muted truncate text-xs">{h.meta}</p>
                    </div>
                    {h.severity && <SeverityBadge severity={h.severity} />}
                  </li>
                ))}
              </ul>
              {g.hits.length > 10 && <p className="text-muted mt-2 text-xs">Showing 10 of {g.hits.length}. Refine your search.</p>}
            </Card>
          ))}
      </div>
    </>
  );
}
