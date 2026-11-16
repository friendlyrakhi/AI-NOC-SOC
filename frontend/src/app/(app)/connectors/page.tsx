import { DataTable, type Row } from "@/components/data-table";
import { gate, Grid } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { CATEGORY_LABEL, CONNECTORS, connectorStatus } from "@/lib/connectors";
import { getMe } from "@/lib/server/api";

/**
 * Connector administration. The catalog is product metadata; instance status is never
 * invented. There is no connector backend yet (P2), so every connector reports
 * "Not configured".
 */
export default async function ConnectorsPage() {
  const me = await getMe();
  const denied = gate(me, "connector:read", "Connectors");
  if (denied) return denied;
  const canManage = me.permissions.includes("connector:manage");

  const rows: Row[] = CONNECTORS.map((c) => {
    const st = connectorStatus();
    return {
      _id: c.id,
      name: c.name,
      vendor: c.vendor,
      category: CATEGORY_LABEL[c.category],
      domain: c.domain === "both" ? "NOC + SOC" : c.domain.toUpperCase(),
      status: st.label,
      streams: c.streams,
      actions: c.actions.length,
      _details: {
        Connector: `${c.name} (${c.id})`,
        Vendor: c.vendor,
        Category: CATEGORY_LABEL[c.category],
        Status: `${st.label}. ${st.detail}`,
        "Data streams (pull)": c.streams.join(", ") || "Configurable mapping",
        "Push / webhook": c.push ?? "No",
        "Response actions": c.actions.length ? c.actions.map((a) => `${a.key} (${a.tier})`).join(", ") : "None",
        Certification: "Not yet built. Starts as sandbox (fixtures), then contract-tested, then live-verified with credentials you provide.",
        Credentials: "Write-only. Stored encrypted; never shown again after saving.",
      },
    };
  });

  return (
    <>
      <PageHeader
        title="Connectors"
        description="Integration catalog and connector instances for this tenant. Select a connector for its capabilities."
      />
      <div role="note" className="border-border bg-surface mb-6 rounded-md border px-3 py-2 text-sm">
        <p>
          <strong>No connectors are configured.</strong> Connector instances, health and credentials arrive with the connector SDK in phase P2,
          sandbox mode first. This page shows real status from the platform: it does not simulate connections.
        </p>
      </div>
      <Grid cols={4}>
        <Card>
          <p className="text-muted text-xs">Connectors in catalog</p>
          <p className="mt-1 text-2xl font-semibold">{CONNECTORS.length}</p>
        </Card>
        <Card>
          <p className="text-muted text-xs">Configured instances</p>
          <p className="mt-1 text-2xl font-semibold">0</p>
        </Card>
        <Card>
          <p className="text-muted text-xs">Live-verified</p>
          <p className="mt-1 text-2xl font-semibold">0</p>
          <p className="text-muted text-xs">Requires your credentials (phase P8)</p>
        </Card>
        <Card>
          <p className="text-muted text-xs">Execution mode</p>
          <p className="mt-1 text-2xl font-semibold">Simulate</p>
          <p className="text-muted text-xs">Live actions are disabled</p>
        </Card>
      </Grid>
      <section className="mt-6">
        <DataTable
          caption="Connector catalog"
          rows={rows}
          columns={[
            { key: "name", header: "Connector" },
            { key: "vendor", header: "Vendor", hideOnMobile: true },
            { key: "category", header: "Category", filter: true },
            { key: "domain", header: "Used by", filter: true },
            { key: "status", header: "Status", filter: true },
            { key: "streams", header: "Data streams", type: "tags", hideOnMobile: true },
            { key: "actions", header: "Actions", type: "number", align: "right" },
          ]}
          pageSize={25}
        />
        {canManage && (
          <p className="text-muted mt-3 text-xs">
            You can manage connectors. The “Add connector” flow becomes available when the connector API ships (P2).
          </p>
        )}
      </section>
    </>
  );
}
