import { BarList } from "@/components/charts";
import { DataTable } from "@/components/data-table";
import { DemoBadge, DemoNotice, KpiTile } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { ACTORS, TECHNIQUES } from "@/lib/demo/reference";
import { indicatorColumns, indicatorRow } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";
import { countBy } from "@/lib/severity";

export default async function ThreatIntelPage() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "alert:read", "Threat intelligence");
  if (denied) return denied;
  const iocs = data.indicators;
  const sighted = iocs.filter((i) => i.sightings > 0);
  return (
    <>
      <PageHeader
        title="Threat intelligence"
        description="Indicators of compromise matched against your telemetry, and the threat actors they are associated with."
        actions={<DemoBadge />}
      />
      <DemoNotice>
        Threat actors and feeds are fictional and marked “(demo)”. Indicators use documentation IP ranges and the reserved .example domain.
      </DemoNotice>
      <Grid cols={4}>
        <KpiTile label="Indicators tracked" value={iocs.length} />
        <KpiTile label="Sighted in your telemetry" value={sighted.length} />
        <KpiTile label="High confidence (≥ 80)" value={iocs.filter((i) => i.confidence >= 80).length} />
        <KpiTile label="Actors referenced" value={new Set(iocs.map((i) => i.actor)).size} />
      </Grid>
      <h2 className="mt-8 mb-3 text-sm font-semibold">Threat actors</h2>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {ACTORS.map((a) => (
          <Card key={a.name}>
            <h3 className="text-sm font-semibold">{a.name}</h3>
            <p className="text-muted text-xs">
              {a.motivation} · targets {a.sectors.join(", ")}
            </p>
            <p className="mt-2 text-xs">{a.description}</p>
            <ul className="mt-3 flex flex-wrap gap-1">
              {a.techniques.map((t) => (
                <li key={t} title={TECHNIQUES[t]?.name} className="bg-border/50 rounded px-1.5 py-px font-mono text-[11px]">
                  {t}
                </li>
              ))}
            </ul>
            <p className="text-muted mt-3 text-xs">{iocs.filter((i) => i.actor === a.name && i.sightings > 0).length} indicators sighted</p>
          </Card>
        ))}
      </div>
      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card title="Sightings by indicator type">
          <BarList label="Sighted indicators by type" items={countBy(sighted, (i) => i.type)} />
        </Card>
        <section className="lg:col-span-2">
          <h2 className="mb-3 text-sm font-semibold">Indicators</h2>
          <DataTable
            caption="Indicators of compromise"
            rows={iocs.map(indicatorRow)}
            columns={indicatorColumns(aggregate)}
            initialSort={{ key: "sightings", dir: "desc" }}
            searchPlaceholder="Search indicator, actor, tag…"
            exportName="indicators"
            pageSize={10}
          />
        </section>
      </div>
    </>
  );
}
