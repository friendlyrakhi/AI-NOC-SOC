import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { RunCard } from "@/components/ai-panel";
import { KpiTile } from "@/components/indicators";
import { Grid } from "@/components/page-states";
import { Card } from "@/components/ui";
import { generateBriefing } from "@/app/actions/insights";
import { kpiBasis, kpiValue, PERIODS, type AiRun, type Domain, type Kpi, type Period } from "@/lib/server/insights";

const PERIOD_LABEL: Record<Period, string> = { "24h": "24 hours", "7d": "7 days", "30d": "30 days", "90d": "90 days" };

/** Period switcher as plain links (works without JavaScript; the URL is shareable). */
export function PeriodNav({ current, base, extra = "" }: { current: Period; base: string; extra?: string }) {
  return (
    <nav aria-label="Period" className="flex flex-wrap gap-1">
      {PERIODS.map((p) => (
        <Link
          key={p}
          href={`${base}?period=${p}${extra}`}
          aria-current={p === current ? "page" : undefined}
          className={`rounded border px-2 py-1 text-xs ${p === current ? "border-primary text-primary font-medium" : "border-border text-muted hover:text-foreground"}`}
        >
          Last {PERIOD_LABEL[p]}
        </Link>
      ))}
    </nav>
  );
}

/** KPI tiles; each one links to the records behind it. */
export function KpiGrid({ kpis, domain, period }: { kpis: Kpi[]; domain: Domain; period: Period }) {
  return (
    <Grid cols={3}>
      {kpis.map((k) => {
        const v = kpiValue(k);
        return (
          <KpiTile
            key={k.key}
            label={k.label}
            value={v.value}
            unit={v.unit}
            hint={`${kpiBasis(k)} · ${k.description}`}
            href={`/command/kpi/${k.key}?domain=${domain}&period=${period}`}
          />
        );
      })}
    </Grid>
  );
}

export function BriefingCard({ run, canGenerate }: { run: AiRun | null; canGenerate: boolean }) {
  return (
    <Card title="Daily briefing (AI-generated)">
      <p className="text-muted mb-3 text-xs">
        Written from the last 24 hours&apos; KPIs, open P1/P2 incidents and notable alerts. Every statement cites the KPI or record it rests on; the
        AI cannot change anything.
      </p>
      {canGenerate && (
        <div className="mb-3">
          <ActionForm action={generateBriefing} submitLabel={run ? "Generate a fresh briefing" : "Generate briefing"} className="flex items-center gap-3" />
        </div>
      )}
      {run ? <RunCard run={run} back="/command" incidentId="" requestable={null} /> : <p className="text-muted text-sm">No briefing generated yet.</p>}
    </Card>
  );
}
