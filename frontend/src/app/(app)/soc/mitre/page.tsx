import { DataTable, type Row } from "@/components/data-table";
import { DemoBadge, DemoNotice } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { PageHeader } from "@/components/ui";
import { ATTACK_TACTICS, TECHNIQUES } from "@/lib/demo/reference";
import { customerCol } from "@/lib/rows";
import { getDemo } from "@/lib/server/demo";

/** Sequential (one-hue) ramp: darker = more observations. Always shown with the count. */
function step(count: number, max: number): number {
  if (count === 0) return 0;
  return Math.min(5, Math.ceil((count / Math.max(1, max)) * 5));
}

export default async function MitrePage() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "alert:read", "MITRE ATT&CK");
  if (denied) return denied;

  const observations = [
    ...data.alerts.filter((a) => a.technique).map((a) => ({ t: a.technique as string, source: "Alert", id: a.id, what: a.title, host: a.assetName, sev: a.severity, when: a.createdAt, customer: a.tenant.name })),
    ...data.edr.map((d) => ({ t: d.technique, source: "EDR", id: d.id, what: d.file, host: d.host, sev: d.severity, when: d.time, customer: d.tenant.name })),
    ...data.siem.filter((e) => e.technique).map((e) => ({ t: e.technique as string, source: "SIEM", id: e.id, what: e.rule, host: e.host, sev: e.severity, when: e.time, customer: e.tenant.name })),
  ];
  const counts = new Map<string, number>();
  for (const o of observations) counts.set(o.t, (counts.get(o.t) ?? 0) + 1);
  const max = Math.max(1, ...counts.values());

  const rows: Row[] = observations.map((o) => ({
    _id: `${o.source}-${o.id}`,
    technique: `${o.t} ${TECHNIQUES[o.t]?.name ?? ""}`,
    customer: o.customer,
    tactic: TECHNIQUES[o.t]?.tactic ?? "",
    source: o.source,
    what: o.what,
    host: o.host,
    severity: o.sev,
    when: o.when,
  }));

  return (
    <>
      <PageHeader
        title="MITRE ATT&CK"
        description="Techniques observed in alerts, EDR detections and SIEM events over the last 72 hours, mapped to the ATT&CK Enterprise matrix (subset)."
        actions={<DemoBadge />}
      />
      <DemoNotice>Technique IDs are real ATT&CK identifiers; the observations are generated demo data.</DemoNotice>

      <div className="mb-3 flex flex-wrap items-center gap-3 text-xs" aria-label="Colour scale">
        <span className="text-muted">Observations:</span>
        {[0, 1, 2, 3, 4, 5].map((s) => (
          <span key={s} className="flex items-center gap-1">
            <span
              aria-hidden="true"
              className="border-border inline-block h-3 w-5 rounded-sm border"
              style={{ background: s === 0 ? "transparent" : `var(--seq-${s})` }}
            />
            {s === 0 ? "none" : s === 5 ? "most" : ""}
          </span>
        ))}
      </div>
      <div
        role="region"
        aria-label="ATT&CK matrix (scrolls horizontally)"
        tabIndex={0}
        className="focus-visible:ring-primary/50 overflow-x-auto rounded pb-2 outline-none focus-visible:ring-2"
      >
        <div className="grid min-w-[1100px] grid-cols-12 gap-1.5">
          {ATTACK_TACTICS.map((tactic) => (
            <section key={tactic.id} aria-labelledby={`tactic-${tactic.id}`}>
              <h3 id={`tactic-${tactic.id}`} className="bg-surface border-border mb-1.5 rounded border p-1.5 text-[11px] leading-tight font-semibold">
                {tactic.name}
                <span className="text-muted block font-mono font-normal">{tactic.id}</span>
              </h3>
              <ul className="space-y-1.5">
                {tactic.techniques.map((tech) => {
                  const n = counts.get(tech.id) ?? 0;
                  const s = step(n, max);
                  return (
                    <li
                      key={tech.id}
                      title={`${tech.id} ${tech.name}: ${n} observation${n === 1 ? "" : "s"}`}
                      className="border-border rounded border border-l-[6px] p-1.5 text-[11px] leading-tight"
                      style={
                        s
                          ? { borderLeftColor: `var(--seq-${s})`, background: `color-mix(in srgb, var(--seq-${s}) 22%, transparent)` }
                          : undefined
                      }
                    >
                      <span className="block">{tech.name}</span>
                      <span className="mt-0.5 flex justify-between font-mono">
                        <span>{tech.id}</span>
                        <span className="tabular-nums">
                          {n}
                          <span className="sr-only"> observations</span>
                        </span>
                      </span>
                    </li>
                  );
                })}
              </ul>
            </section>
          ))}
        </div>
      </div>

      <section className="mt-6">
        <h2 className="mb-3 text-sm font-semibold">Observations</h2>
        <DataTable
          caption="ATT&CK technique observations"
          rows={rows}
          columns={[
            { key: "technique", header: "Technique", filter: true },
            ...customerCol(aggregate),
            { key: "tactic", header: "Tactic", filter: true },
            { key: "source", header: "Source", filter: true },
            { key: "what", header: "Signal" },
            { key: "host", header: "Host", type: "mono", hideOnMobile: true },
            { key: "severity", header: "Severity", type: "severity", filter: true },
            { key: "when", header: "Time", type: "time" },
          ]}
          exportName="attack-observations"
          pageSize={10}
        />
      </section>
    </>
  );
}
