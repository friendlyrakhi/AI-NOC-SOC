import Link from "next/link";
import { notFound } from "next/navigation";

import { TimeSeriesChart } from "@/components/charts";
import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice, HealthBadge } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { assetSeries } from "@/lib/demo/generate";
import { alertColumns, alertRow, incidentColumns, incidentRow, vulnColumns, vulnRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";

const LIST: Record<string, { href: string; label: string }> = {
  server: { href: "/noc/servers", label: "Servers" },
  network: { href: "/noc/network", label: "Network" },
  cloud: { href: "/noc/cloud", label: "Cloud operations" },
  application: { href: "/noc/applications", label: "Applications" },
  database: { href: "/noc/databases", label: "Databases" },
};

export default async function AssetPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { me, data } = await getDemo();
  const denied = gate(me, "asset:read", "Asset");
  if (denied) return denied;
  // Only assets in the caller's current scope are reachable.
  const asset = data.assets.find((a) => a.id === id);
  if (!asset) notFound();
  const series = assetSeries(asset);
  const alerts = data.alerts.filter((a) => a.assetId === asset.id);
  const incidents = data.incidents.filter((i) => i.assetIds.includes(asset.id));
  const vulns = data.vulns.filter((v) => v.assetId === asset.id);
  const back = LIST[asset.type];

  const attributes: [string, string][] = [
    ["Kind", asset.kind],
    ["Environment", asset.environment],
    [asset.type === "cloud" ? "Region" : "Site", asset.location],
    ["IP address", asset.ip],
    ["Business service", asset.service],
    ["Owner", asset.owner],
    ["Criticality", `${asset.criticality} / 5`],
    ["Availability (30 d)", `${asset.availability30d}%`],
    ["Telemetry source", `${asset.source} (planned; no connector configured)`],
    ["Customer", asset.tenant.name],
  ];

  return (
    <>
      <nav aria-label="Breadcrumb" className="text-muted mb-2 text-sm">
        <Link href={back.href} className="hover:text-foreground">
          ← {back.label}
        </Link>
      </nav>
      <PageHeader
        title={asset.name}
        description={`${asset.kind} · ${asset.service}`}
        actions={
          <div className="flex items-center gap-3">
            <HealthBadge status={asset.status} />
            <DemoBadge />
          </div>
        }
      />
      <DemoNotice />
      <div className="grid gap-6 xl:grid-cols-3">
        <Card title="Attributes">
          <dl className="grid grid-cols-[9rem_1fr] gap-y-2 text-sm">
            {attributes.map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-muted">{k}</dt>
                <dd className="break-words">{v}</dd>
              </div>
            ))}
          </dl>
        </Card>
        {series.map((s, i) => (
          <Card key={s.name} title={`${s.name} (48 h)`}>
            <TimeSeriesChart
              title={`${s.name} for ${asset.name} over the last 48 hours`}
              series={[{ name: s.name, slot: i === 0 ? 1 : 3, points: s.points }]}
              format={s.unit}
              granularity="hour"
              height={180}
            />
          </Card>
        ))}
      </div>
      <section className="mt-6">
        <h2 className="mb-3 text-sm font-semibold">Alerts on this asset</h2>
        <DataTable caption="Alerts on this asset" rows={alerts.map((a) => alertRow(a))} columns={alertColumns(false, asset.type !== "network" && alerts.some((a) => a.domain === "soc"))} pageSize={10} />
      </section>
      <div className="mt-6 grid gap-6 xl:grid-cols-2">
        <section>
          <h2 className="mb-3 text-sm font-semibold">Related incidents</h2>
          <DataTable caption="Incidents involving this asset" rows={incidents.map(incidentRow)} columns={incidentColumns(false)} pageSize={5} emptyText="No incidents involve this asset." />
        </section>
        <section>
          <h2 className="mb-3 text-sm font-semibold">Vulnerabilities</h2>
          <DataTable caption="Vulnerabilities on this asset" rows={vulns.map(vulnRow)} columns={vulnColumns(false)} pageSize={5} emptyText="No open findings for this asset." />
        </section>
      </div>
    </>
  );
}
