import Link from "next/link";

import { SeverityBadge, StateBadge } from "@/components/indicators";
import { Card } from "@/components/ui";
import type { Alert, CorrelationGroup, Incident } from "@/lib/demo/types";
import { formatTime } from "@/lib/format";

export function CorrelationGroups({ groups, alerts, incidents }: { groups: CorrelationGroup[]; alerts: Alert[]; incidents: Incident[] }) {
  const byId = new Map(alerts.map((a) => [a.id, a]));
  const incidentById = new Map(incidents.map((i) => [i.id, i]));
  if (groups.length === 0) return <p className="text-muted text-sm">No active correlation groups.</p>;
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      {groups.map((g) => {
        const incident = g.incidentId ? incidentById.get(g.incidentId) : undefined;
        return (
          <Card key={g.id}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold">{g.title}</h3>
                <p className="text-muted text-xs">
                  {g.rule} · confidence {Math.round(g.confidence * 100)}% · since {formatTime(g.firstSeen)}
                </p>
              </div>
              <SeverityBadge severity={g.severity} />
            </div>
            <ul className="border-border mt-3 divide-y border-t text-xs">
              {g.alertIds.map((id) => {
                const a = byId.get(id);
                return a ? (
                  <li key={id} className="flex items-center justify-between gap-2 py-1.5">
                    <span className="truncate">
                      {a.title} <span className="text-muted font-mono">{a.assetName}</span>
                    </span>
                    <StateBadge value={a.status} />
                  </li>
                ) : null;
              })}
            </ul>
            <p className="mt-3 text-xs">
              {incident ? (
                <Link href={`/incidents/${incident.id}`} className="text-primary hover:underline">
                  Linked incident {incident.number} →
                </Link>
              ) : (
                <span className="text-muted">Not yet promoted to an incident.</span>
              )}
            </p>
          </Card>
        );
      })}
    </div>
  );
}
