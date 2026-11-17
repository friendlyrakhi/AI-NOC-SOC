import Link from "next/link";
import { notFound } from "next/navigation";

import { DataTable } from "@/components/data-table";
import { KpiTile, SandboxNotice } from "@/components/indicators";
import { PeriodNav } from "@/components/insights";
import { gate } from "@/components/page-states";
import { NotAvailable, PageHeader } from "@/components/ui";
import { getMe } from "@/lib/server/api";
import { domain as toDomain, getDrill, getKpis, kpiBasis, kpiValue, period as toPeriod } from "@/lib/server/insights";

const COUNTED: Record<string, string> = {
  ack_sla: "Acknowledged in time",
  resolve_sla: "Resolved in time",
  automation_rate: "Automated action",
  noise_ratio: "Not escalated",
};

/** The records behind one KPI: its basis, with the flag that makes up the numerator. */
export default async function KpiRecords({
  params,
  searchParams,
}: {
  params: Promise<{ key: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const me = await getMe();
  const denied = gate(me, "analytics:read", "KPI records");
  if (denied) return denied;
  const { key } = await params;
  const sp = await searchParams;
  const p = toPeriod(sp.period);
  const d = toDomain(sp.domain);
  const [set, drill] = await Promise.all([getKpis(d, p), getDrill(key, d, p)]);
  const kpi = set?.kpis.find((k) => k.key === key);
  if (set && !kpi) notFound();
  if (!set || !drill || !kpi) {
    return (
      <>
        <PageHeader title="KPI records" />
        <NotAvailable what="Analytics" />
      </>
    );
  }
  const v = kpiValue(kpi);
  const counted = COUNTED[key];
  const seconds = key === "mtta" || key === "mttr";
  const isIncident = drill.records === "incident";
  return (
    <>
      <p className="mb-2 text-xs">
        <Link href={`/command?period=${p}`} className="text-primary hover:underline">
          ← Command Center
        </Link>
      </p>
      <PageHeader
        title={`${kpi.label} · ${d === "all" ? "all domains" : d.toUpperCase()}`}
        description={kpi.description}
        actions={<PeriodNav current={p} base={`/command/kpi/${key}`} extra={`&domain=${d}`} />}
      />
      <SandboxNotice>Records from sandbox connector data and demo seed content processed by the real platform.</SandboxNotice>
      <div className="mb-6 max-w-sm">
        <KpiTile label={kpi.label} value={v.value} unit={v.unit} hint={`${kpiBasis(kpi)}; listed below`} />
      </div>
      <DataTable
        caption={`${drill.total} ${isIncident ? "incidents" : "alerts"} behind ${kpi.label}`}
        rows={drill.items.map((i) => ({
          _id: i.id,
          _href: isIncident ? `/incidents/${i.id}` : `/search?q=${encodeURIComponent(i.title)}`,
          ref: i.number ?? i.title,
          title: i.title,
          severity: i.severity,
          status: i.status,
          domain: i.domain.toUpperCase(),
          at: i.at,
          seconds: i.seconds === null || i.seconds === undefined ? null : Math.round(i.seconds / 60),
          counted: i.counted ?? null,
        }))}
        columns={[
          { key: "ref", header: isIncident ? "Incident" : "Alert", type: "link" },
          ...(isIncident ? [{ key: "title", header: "Title" }] : []),
          { key: "severity", header: "Severity", type: "severity" as const, filter: true },
          { key: "status", header: "Status", type: "state" as const, filter: true },
          { key: "domain", header: "Domain", filter: true, hideOnMobile: true },
          { key: "at", header: isIncident ? "Detected" : "First seen", type: "time" as const },
          ...(seconds ? [{ key: "seconds", header: key === "mtta" ? "Minutes to acknowledge" : "Minutes to resolve", type: "number" as const, align: "right" as const }] : []),
          ...(counted ? [{ key: "counted", header: counted, type: "bool" as const, filter: true }] : []),
        ]}
        exportName={`kpi-${key}-${d}-${p}`}
        dataSource="sandbox"
        emptyText="No records in this period."
      />
    </>
  );
}
