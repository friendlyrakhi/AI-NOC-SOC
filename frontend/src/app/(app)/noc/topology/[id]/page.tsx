import Link from "next/link";
import { notFound } from "next/navigation";

import { DataTable, type ColumnSpec } from "@/components/data-table";
import { HealthBadge, KpiTile, SandboxBadge } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { PageHeader } from "@/components/ui";
import { SERVICE_HEALTH } from "@/lib/pipeline-rows";
import { getMe } from "@/lib/server/api";
import { getService } from "@/lib/server/pipeline";

const columns: ColumnSpec[] = [
  { key: "name", header: "Asset", type: "mono" },
  { key: "role", header: "Role", filter: true },
  { key: "type", header: "Type", filter: true, hideOnMobile: true },
  { key: "worst", header: "Worst open alert", type: "severity", filter: true },
  { key: "openAlerts", header: "Open alerts", type: "number", align: "right" },
];

export default async function ServicePage({ params }: { params: Promise<{ id: string }> }) {
  const me = await getMe();
  const denied = gate(me, "service:read", "Service");
  if (denied) return denied;
  const { id } = await params;
  const s = await getService(id);
  if (!s) notFound();
  return (
    <>
      <p className="mb-2 text-xs">
        <Link href="/noc/topology" className="text-primary hover:underline">
          ← Services & topology
        </Link>
      </p>
      <PageHeader title={s.name} description={`Tier ${s.tier} · ${s.owner_team ?? "No owner"} · aliases: ${s.aliases.join(", ") || "none"}`} actions={s.sandbox ? <SandboxBadge /> : undefined} />
      <Grid cols={4}>
        <KpiTile label="Health" value={s.health}>
          <HealthBadge status={SERVICE_HEALTH[s.health]} />
        </KpiTile>
        <KpiTile label="Open incidents" value={s.open_incidents} />
        <KpiTile label="Open alerts" value={s.open_alerts} />
        <KpiTile label="Maintenance" value={s.in_maintenance ? "Active window" : "None"} />
      </Grid>
      <section className="mt-6">
        <DataTable
          caption={`Assets of ${s.name}`}
          rows={s.assets.map((a) => ({
            _id: `${a.id}-${a.role}`,
            name: a.name,
            role: a.role === "member" ? "Runs the service" : "Dependency",
            type: a.type,
            worst: a.worst_open_severity ?? null,
            openAlerts: a.open_alerts,
          }))}
          columns={columns}
          searchPlaceholder="Search assets…"
        />
      </section>
    </>
  );
}
