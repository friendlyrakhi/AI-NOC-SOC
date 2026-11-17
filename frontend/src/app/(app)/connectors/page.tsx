import { ActionForm } from "@/components/action-form";
import { DataTable, type Row } from "@/components/data-table";
import { KpiTile, SandboxBadge, SandboxNotice, SectionTitle } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Card, Field, PageHeader } from "@/components/ui";
import { createInstance, createLiveInstance, replayScenario } from "@/app/actions/connectors";
import { CATEGORY_LABEL, type ConnectorCategory } from "@/lib/connectors";
import { instanceColumns, instanceRow } from "@/lib/pipeline-rows";
import { getMe } from "@/lib/server/api";
import { getConnectorState } from "@/lib/server/pipeline";

/**
 * Integrations: catalog, this tenant's connector instances and sandbox scenarios.
 * Status shown here is what the connector runner reported after real runs. A new instance
 * shows "Awaiting first run" until then; nothing on this page claims health it has not earned.
 */
export default async function ConnectorsPage() {
  const me = await getMe();
  const denied = gate(me, "connector:read", "Connectors");
  if (denied) return denied;
  const canManage = me.permissions.includes("connector:manage");
  const state = await getConnectorState();

  if (!state) {
    return (
      <>
        <PageHeader title="Connectors" description="Integration catalog and connector instances for this tenant." />
        <div role="note" className="border-border bg-surface rounded-md border px-3 py-2 text-sm">
          Integrations are managed per customer. Select a single customer (not the &ldquo;All customers&rdquo; view) to see and
          manage its connectors.
        </div>
      </>
    );
  }
  const { definitions, instances, scenarios } = state;
  const count = (s: string) => instances.filter((i) => i.status === s).length;

  const catalog: Row[] = definitions.map((d) => ({
    _id: d.id,
    name: d.name,
    vendor: d.vendor,
    category: CATEGORY_LABEL[d.category as ConnectorCategory] ?? d.category,
    certification: d.certification,
    instances: instances.filter((i) => i.definition_id === d.id).length,
    streams: d.streams.map((s) => s.name),
    _details: {
      Connector: `${d.name} (${d.id})`,
      Vendor: d.vendor,
      Certification: `${d.certification}: runs against a vendor simulator. Live use needs credentials you provide and a later, approved phase.`,
      "Data streams (pull)": d.streams.map((s) => `${s.name} → ${s.output} every ${s.default_interval_seconds}s`).join(", ") || "None (push only)",
      "Push / webhook": d.webhook ? "Yes: HMAC-signed webhook ingress" : "No",
      "Response actions": d.actions.length ? d.actions.map((a) => `${a.key} (${a.tier}, simulated)`).join(", ") : "None",
      Scenarios: d.scenarios.join(", ") || null,
      Reference: d.docs_reference || null,
    },
  }));

  return (
    <>
      <PageHeader
        title="Connectors"
        description="Integration catalog, this tenant's connector instances and sandbox scenarios."
        actions={<SandboxBadge />}
      />
      <SandboxNotice>
        Connectors run in <strong>sandbox mode</strong> against a vendor simulator unless an operator has enabled{" "}
        <strong>live reads</strong> (P8, hardened profile). Live instances only read; response actions are always simulated.
      </SandboxNotice>
      <Grid cols={4}>
        <KpiTile label="Configured instances" value={instances.length} hint={`${definitions.length} connectors in catalog`} />
        <KpiTile label="Healthy" value={count("healthy")} hint={`${count("pending")} awaiting first run`} />
        <KpiTile label="Degraded or failing" value={count("degraded") + count("failing")} hint={`${count("disabled")} disabled`} />
        <KpiTile label="Execution mode" value="Simulate" hint="Live actions are disabled in this build" />
      </Grid>

      <section className="mt-6">
        <SectionTitle>Instances</SectionTitle>
        <DataTable
          caption="Connector instances"
          rows={instances.map((i) => instanceRow(i, definitions))}
          columns={instanceColumns}
          emptyText="No integrations yet. Add one below (sandbox mode)."
          pageSize={25}
        />
      </section>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        {canManage && (
          <Card title="Add integration">
            <ActionForm action={createInstance} submitLabel="Add in sandbox mode" resetOnSuccess>
              <Field label="Connector">
                <select name="definition_id" required className="input mt-1 w-full">
                  {definitions.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.name}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Name" hint="Unique within this tenant, e.g. “Prod Datadog”.">
                <input name="name" required maxLength={100} className="input mt-1 w-full" />
              </Field>
            </ActionForm>
          </Card>
        )}

        {canManage && definitions.some((d) => d.live_read) && (
          <Card title="Add live integration (read-only)">
            <p className="text-muted mb-3 text-xs">
              Reads the vendor&apos;s real API; it never writes, and response actions stay simulated. Needs the hardened profile with
              operator-held unseal shares and the live-read switch (docs/operations/p8-vendor-onboarding.md). Add credentials on the
              integration&apos;s page afterwards.
            </p>
            <ActionForm action={createLiveInstance} submitLabel="Add live (read-only)" stepUp resetOnSuccess>
              <Field label="Connector">
                <select name="definition_id" required className="input mt-1 w-full">
                  {definitions
                    .filter((d) => d.live_read)
                    .map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name} ({d.certification})
                      </option>
                    ))}
                </select>
              </Field>
              <Field label="Name">
                <input name="name" required maxLength={100} className="input mt-1 w-full" />
              </Field>
              <Field label="Configuration (JSON)" hint="Vendor URLs and options from the connector's configuration schema.">
                <textarea
                  name="config"
                  rows={3}
                  className="input mt-1 w-full font-mono text-xs"
                  placeholder={'{"alertmanager_url": "https://alertmanager.example.com", "prometheus_url": "https://prometheus.example.com"}'}
                />
              </Field>
            </ActionForm>
          </Card>
        )}

        <Card title="Sandbox scenarios">
          <p className="text-muted mb-3 text-xs">
            Replays a scripted situation through the real pipeline using this tenant&apos;s sandbox instances. Replaying a scenario several
            times exercises de-duplication: repeats raise occurrence counts instead of new alerts.
          </p>
          <ul className="space-y-4">
            {scenarios.map((s) => (
              <li key={s.key} className="border-border border-t pt-3 first:border-t-0 first:pt-0">
                <p className="text-sm font-medium">{s.title}</p>
                <p className="text-muted text-xs">{s.description}</p>
                <p className="text-muted mt-1 text-xs">
                  Uses: {s.connectors.join(", ")}
                  {s.missing.length > 0 && <span className="text-warning"> · missing: {s.missing.join(", ")}</span>}
                </p>
                {canManage && s.configured.length > 0 && (
                  <ActionForm action={replayScenario} submitLabel="Replay" className="mt-2 flex flex-wrap items-end gap-3">
                    <input type="hidden" name="scenario" value={s.key} />
                    <label className="text-muted text-xs">
                      Times
                      <select name="times" defaultValue="1" className="input ml-2 w-20" aria-label={`Replay count for ${s.title}`}>
                        {[1, 2, 5, 10].map((n) => (
                          <option key={n} value={n}>
                            {n}×
                          </option>
                        ))}
                      </select>
                    </label>
                  </ActionForm>
                )}
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <section className="mt-6">
        <SectionTitle>Catalog</SectionTitle>
        <DataTable
          caption="Connector catalog"
          rows={catalog}
          columns={[
            { key: "name", header: "Connector" },
            { key: "vendor", header: "Vendor", hideOnMobile: true },
            { key: "category", header: "Category", filter: true },
            { key: "certification", header: "Certification", filter: true },
            { key: "instances", header: "Instances", type: "number", align: "right" },
            { key: "streams", header: "Data streams", type: "tags", hideOnMobile: true },
          ]}
          pageSize={25}
        />
      </section>
    </>
  );
}
