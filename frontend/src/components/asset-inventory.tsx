import { BarList, SegmentBar } from "@/components/charts";
import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice, KpiTile } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import type { Asset, AssetType } from "@/lib/demo/types";
import { assetColumns, assetRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";
import { OPEN_ALERT, countBy, healthParts } from "@/lib/severity";

const TEXT: Record<AssetType, { title: string; description: string; sources: string }> = {
  server: { title: "Server monitoring", description: "Physical, virtual and Kubernetes hosts.", sources: "SolarWinds, Prometheus, Datadog" },
  network: { title: "Network monitoring", description: "Switches, routers, firewalls, load balancers and WAN links.", sources: "SolarWinds" },
  cloud: { title: "Cloud operations", description: "Compute, serverless, containers and storage across cloud providers.", sources: "AWS CloudWatch, Azure Monitor, Google Cloud Ops" },
  application: { title: "Application performance", description: "Latency, errors and throughput per application component (APM).", sources: "Datadog" },
  database: { title: "Databases", description: "Relational and cache databases: connections, throughput and replication.", sources: "Prometheus, Datadog, SolarWinds" },
};

function headline(type: AssetType, assets: Asset[]): { label: string; value: string; unit?: string }[] {
  const avg = (f: (a: Asset) => number) => (assets.length ? assets.reduce((s, a) => s + f(a), 0) / assets.length : 0);
  const up = assets.filter((a) => a.status !== "down");
  switch (type) {
    case "network":
      return [
        { label: "Avg bandwidth utilisation", value: avg((a) => a.metrics.bandwidthUtil).toFixed(0), unit: "%" },
        { label: "Interfaces down", value: String(assets.reduce((s, a) => s + (a.metrics.interfacesDown ?? 0), 0)) },
      ];
    case "cloud":
      return [
        { label: "Monthly run-rate", value: `€${Math.round(assets.reduce((s, a) => s + (a.metrics.monthlyCost ?? 0), 0)).toLocaleString("en-GB")}` },
        { label: "Avg utilisation", value: avg((a) => a.metrics.utilisation).toFixed(0), unit: "%" },
      ];
    case "application":
      return [
        { label: "Median p95 latency", value: String([...assets].sort((a, b) => a.metrics.p95Ms - b.metrics.p95Ms)[Math.floor(assets.length / 2)]?.metrics.p95Ms ?? 0), unit: "ms" },
        { label: "Avg error rate", value: avg((a) => a.metrics.errorRate).toFixed(2), unit: "%" },
      ];
    case "database":
      return [
        { label: "Max replication lag", value: Math.max(0, ...assets.map((a) => a.metrics.replicationLagS)).toFixed(1), unit: "s" },
        { label: "Total QPS", value: assets.reduce((s, a) => s + a.metrics.qps, 0).toLocaleString("en-GB") },
      ];
    default:
      return [
        { label: "Avg CPU (running hosts)", value: (up.length ? up.reduce((s, a) => s + a.cpu, 0) / up.length : 0).toFixed(0), unit: "%" },
        { label: "Hosts above 85% disk", value: String(assets.filter((a) => a.disk > 85).length) },
      ];
  }
}

function hotspots(type: AssetType, assets: Asset[]) {
  const by = (f: (a: Asset) => number, label: string) => ({
    label,
    items: [...assets]
      .sort((a, b) => f(b) - f(a))
      .slice(0, 6)
      .map((a) => ({ label: a.name, value: f(a), href: `/noc/assets/${a.id}` })),
  });
  switch (type) {
    case "network":
      return by((a) => a.metrics.bandwidthUtil, "Highest bandwidth utilisation (%)");
    case "cloud":
      return by((a) => a.metrics.monthlyCost, "Highest monthly cost (€)");
    case "application":
      return by((a) => a.metrics.p95Ms, "Slowest p95 latency (ms)");
    case "database":
      return by((a) => a.metrics.connections, "Most active connections");
    default:
      return by((a) => a.cpu, "Highest CPU (%)");
  }
}

export async function AssetInventory({ type }: { type: AssetType }) {
  const { me, data, aggregate } = await getDemo();
  const t = TEXT[type];
  const denied = gate(me, "asset:read", t.title);
  if (denied) return denied;
  const assets = data.assets.filter((a) => a.type === type);
  const ids = new Set(assets.map((a) => a.id));
  const active = data.alerts.filter((a) => a.domain === "noc" && ids.has(a.assetId) && OPEN_ALERT.has(a.status));
  const avail = assets.length ? assets.reduce((s, a) => s + a.availability30d, 0) / assets.length : 0;
  const hot = hotspots(type, assets);

  return (
    <>
      <PageHeader title={t.title} description={`${t.description} Planned sources: ${t.sources}.`} actions={<DemoBadge />} />
      <DemoNotice />
      <Grid cols={5}>
        <KpiTile label="Monitored" value={assets.length} />
        <KpiTile label="Degraded or down" value={assets.filter((a) => a.status === "degraded" || a.status === "down").length} />
        <KpiTile label="Avg availability (30 d)" value={avail.toFixed(2)} unit="%" />
        {headline(type, assets).map((h) => (
          <KpiTile key={h.label} label={h.label} value={h.value} unit={h.unit} />
        ))}
      </Grid>
      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card title="Health">
          <SegmentBar label={`${t.title} health`} parts={healthParts(assets)} />
          <h3 className="mt-5 mb-2 text-xs font-semibold">Active alerts by service</h3>
          <BarList label="Active alerts by service" items={countBy(active, (a) => a.service, 5)} />
        </Card>
        <Card title={hot.label} className="lg:col-span-2">
          <BarList label={hot.label} items={hot.items} format={type === "network" || type === "server" ? "decimal" : "int"} />
        </Card>
      </div>
      <section className="mt-6">
        <h2 className="mb-3 text-sm font-semibold">Inventory</h2>
        <DataTable
          caption={`${t.title} inventory`}
          rows={assets.map(assetRow)}
          columns={assetColumns(type, aggregate)}
          searchPlaceholder="Search name, site, service…"
          initialSort={{ key: "status", dir: "asc" }}
          exportName={`${type}-inventory`}
        />
      </section>
    </>
  );
}
