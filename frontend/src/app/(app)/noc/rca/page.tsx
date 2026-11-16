import Link from "next/link";

import { DemoBadge, DemoNotice, SeverityBadge, StateBadge } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { getDemo } from "@/lib/server/demo";
import { OPEN_INCIDENT } from "@/lib/severity";

export default async function RcaPage() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "incident:read", "Root cause analysis");
  if (denied) return denied;
  const incidents = data.incidents.filter((i) => i.domain !== "soc").slice(0, 24);
  return (
    <>
      <PageHeader
        title="Root cause analysis"
        description="AI-drafted root-cause hypotheses for operational incidents. Each hypothesis cites the alerts it is based on and must be confirmed by an engineer."
        actions={<DemoBadge />}
      />
      <DemoNotice>
        Hypotheses are generated demo content standing in for the evidence-grounded AI engine (phase P4). They are never applied automatically.
      </DemoNotice>
      <div className="grid gap-4 xl:grid-cols-2">
        {incidents.map((i) => {
          const top = [...i.rca.hypotheses].sort((a, b) => b.confidence - a.confidence)[0];
          return (
            <Card key={i.id}>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <Link href={`/incidents/${i.id}`} className="text-primary text-sm font-semibold hover:underline">
                    {i.number}
                  </Link>
                  <p className="truncate text-sm">{i.title}</p>
                  {aggregate && <p className="text-muted text-xs">{i.tenant.name}</p>}
                </div>
                <div className="flex flex-col items-end gap-1">
                  <SeverityBadge severity={i.severity} />
                  <StateBadge value={i.status} />
                </div>
              </div>
              <div className="bg-background border-border mt-3 rounded-md border p-3">
                <p className="text-muted mb-1 text-[11px] font-semibold tracking-wide uppercase">
                  Leading hypothesis · AI draft · {Math.round(top.confidence * 100)}% confidence
                </p>
                <p className="text-sm">{top.text}</p>
                <p className="text-muted mt-2 text-xs">
                  Evidence: {top.evidence.length} cited alert{top.evidence.length === 1 ? "" : "s"}
                </p>
              </div>
              <p className="mt-3 text-xs">
                <Link href={`/incidents/${i.id}`} className="text-primary hover:underline">
                  {OPEN_INCIDENT.has(i.status) ? "Review and confirm RCA →" : "View RCA and timeline →"}
                </Link>
              </p>
            </Card>
          );
        })}
      </div>
    </>
  );
}
