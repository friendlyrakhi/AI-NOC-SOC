import { DemoBadge, DemoNotice, KpiTile, StateBadge } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { TECHNIQUES } from "@/lib/demo/reference";
import { formatTime } from "@/lib/format";
import { getDemo } from "@/lib/server/demo";

export async function DemoHunting() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "hunt:run", "AI threat hunting");
  if (denied) return denied;
  const hunts = data.hunts;
  return (
    <>
      <PageHeader
        title="AI threat hunting"
        description="Hypothesis-driven hunts. The AI proposes hunts from recent detections and threat intelligence; analysts review the query before it runs."
        actions={<DemoBadge />}
      />
      <DemoNotice>
        Hunts and AI rationale are generated demo content. Running hunts needs the search engine (phase P6) and the AI engine (phase P4); AI-suggested
        queries are never executed automatically.
      </DemoNotice>
      <Grid cols={4}>
        <KpiTile label="Hunts in library" value={hunts.length} />
        <KpiTile label="AI-suggested" value={hunts.filter((h) => h.origin === "ai_suggested").length} />
        <KpiTile label="Completed with matches" value={hunts.filter((h) => h.matches > 0).length} />
        <KpiTile label="Total matches" value={hunts.reduce((s, h) => s + h.matches, 0)} />
      </Grid>
      <div className="mt-6 grid gap-4 xl:grid-cols-2">
        {hunts.map((h) => (
          <Card key={h.id}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold">{h.name}</h2>
                <p className="text-muted text-xs">
                  <span className="font-mono">{h.technique}</span> {TECHNIQUES[h.technique]?.name} · {h.dataSources.join(", ")}
                  {aggregate && ` · ${h.tenant.name}`}
                </p>
              </div>
              <div className="flex flex-col items-end gap-1">
                <StateBadge value={h.status} />
                <span className={`text-[11px] font-medium ${h.origin === "ai_suggested" ? "text-accent-soc" : "text-muted"}`}>
                  {h.origin === "ai_suggested" ? "AI suggestion" : "Analyst"}
                </span>
              </div>
            </div>
            <p className="mt-3 text-sm">
              <span className="text-muted">Hypothesis: </span>
              {h.hypothesis}
            </p>
            <pre className="bg-background border-border mt-3 overflow-x-auto rounded-md border p-2 font-mono text-xs whitespace-pre-wrap">{h.query}</pre>
            {h.origin === "ai_suggested" && (
              <p className="border-accent-soc/50 text-muted mt-3 border-l-2 pl-3 text-xs">
                <span className="text-foreground font-medium">Why the AI suggests this: </span>
                {h.rationale}
              </p>
            )}
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs">
              <span className="text-muted">
                {h.lastRun ? `Last run ${formatTime(h.lastRun)} · ${h.matches} matches` : "Not run yet"}
              </span>
              <button type="button" disabled className="btn btn-ghost border-border border" title="Hunt execution arrives in phase P6">
                Run hunt (P6)
              </button>
            </div>
          </Card>
        ))}
      </div>
    </>
  );
}
