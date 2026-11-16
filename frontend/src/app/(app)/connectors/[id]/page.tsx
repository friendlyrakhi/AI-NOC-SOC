import Link from "next/link";
import { notFound } from "next/navigation";

import { ActionForm } from "@/components/action-form";
import { DataTable } from "@/components/data-table";
import { HealthBadge, KpiTile, SandboxBadge, SectionTitle } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Card, Field, PageHeader } from "@/components/ui";
import {
  deleteInstance,
  requestSync,
  rotateWebhookSecret,
  setCredentials,
  setEnabled,
  setFaults,
  testInstance,
} from "@/app/actions/connectors";
import { formatTime } from "@/lib/format";
import { INSTANCE_STATUS } from "@/lib/pipeline-rows";
import { getMe } from "@/lib/server/api";
import { getInstanceDetail } from "@/lib/server/pipeline";

type Faults = { auth_failure?: boolean; error_rate?: number; rate_limit_rate?: number; schema_drift_rate?: number; latency_ms?: number };

export default async function ConnectorInstancePage({ params }: { params: Promise<{ id: string }> }) {
  const me = await getMe();
  const denied = gate(me, "connector:read", "Connector");
  if (denied) return denied;
  const { id } = await params;
  const detail = await getInstanceDetail(id);
  if (!detail) notFound();
  const { instance: i, definition: d, runs, deadLetters } = detail;
  const canManage = me.permissions.includes("connector:manage");
  const canSecret = me.permissions.includes("connector:secret:write");
  const st = INSTANCE_STATUS[i.status];
  const faults = ((i.config as Record<string, unknown>).sandbox_faults ?? {}) as Faults;
  const secretFields = Object.keys((d?.secrets_schema as { properties?: Record<string, unknown> })?.properties ?? {});
  const hidden = (
    <>
      <input type="hidden" name="instance_id" value={i.id} />
      <input type="hidden" name="version" value={i.version} />
    </>
  );

  return (
    <>
      <p className="mb-2 text-xs">
        <Link href="/connectors" className="text-primary hover:underline">
          ← Connectors
        </Link>
      </p>
      <PageHeader title={i.name} description={`${d?.name ?? i.definition_id} · ${d?.vendor ?? ""}`} actions={<SandboxBadge />} />
      <Grid cols={4}>
        <KpiTile label="Status" value={st.label} hint={i.status === "pending" ? "No run reported yet" : undefined}>
          <HealthBadge status={st.health} />
        </KpiTile>
        <KpiTile label="Last successful run" value={i.last_success_at ? formatTime(i.last_success_at) : "Never"} />
        <KpiTile label="Last error" value={i.last_error_at ? formatTime(i.last_error_at) : "None"} />
        <KpiTile label="Credentials" value={i.has_credentials ? "Set" : "Not set"} hint="Write-only; never displayed" />
      </Grid>
      {i.status_detail && (
        <p role="note" className="border-border bg-surface mt-4 rounded-md border px-3 py-2 text-sm">
          <strong>Runner detail:</strong> {i.status_detail}
        </p>
      )}

      {canManage && (
        <div className="mt-6 flex flex-wrap gap-3">
          <ActionForm action={requestSync} submitLabel="Sync now" className="flex items-center gap-3">
            {hidden}
          </ActionForm>
          <ActionForm action={testInstance} submitLabel="Test connection" className="flex items-center gap-3">
            {hidden}
          </ActionForm>
          <ActionForm action={setEnabled} submitLabel={i.enabled ? "Disable" : "Enable"} className="flex items-center gap-3">
            {hidden}
            <input type="hidden" name="enabled" value={String(!i.enabled)} />
          </ActionForm>
        </div>
      )}

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        {canManage && (
          <Card title="Sandbox fault injection">
            <p className="text-muted mb-3 text-xs">
              Makes the vendor simulator misbehave so you can watch the runner&apos;s health handling: authentication failure fails
              immediately; errors degrade, then fail after three consecutive runs; rate limiting and schema drift degrade.
            </p>
            <ActionForm action={setFaults} submitLabel="Apply">
              {hidden}
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" name="auth_failure" defaultChecked={!!faults.auth_failure} /> Reject credentials
              </label>
              <div className="grid grid-cols-2 gap-3">
                {(
                  [
                    ["error_rate", "HTTP 503 rate (%)", faults.error_rate],
                    ["rate_limit_rate", "HTTP 429 rate (%)", faults.rate_limit_rate],
                    ["schema_drift_rate", "Schema drift rate (%)", faults.schema_drift_rate],
                  ] as const
                ).map(([name, label, v]) => (
                  <Field key={name} label={label}>
                    <input name={name} type="number" min={0} max={100} defaultValue={Math.round((v ?? 0) * 100)} className="input mt-1 w-24" />
                  </Field>
                ))}
                <Field label="Added latency (ms)">
                  <input name="latency_ms" type="number" min={0} max={10000} defaultValue={faults.latency_ms ?? 0} className="input mt-1 w-24" />
                </Field>
              </div>
            </ActionForm>
          </Card>
        )}

        {canSecret && (
          <Card title="Credentials">
            <p className="text-muted mb-3 text-xs">
              Stored envelope-encrypted and bound to this instance. They are never returned by the API or shown here again. In sandbox
              mode they are not sent anywhere.
            </p>
            {secretFields.length ? (
              <ActionForm action={setCredentials} submitLabel="Save credentials" stepUp resetOnSuccess>
                {hidden}
                {secretFields.map((f) => (
                  <Field key={f} label={f}>
                    <input name={`secret:${f}`} type="password" autoComplete="off" className="input mt-1 w-full" />
                  </Field>
                ))}
              </ActionForm>
            ) : (
              <p className="text-sm">This connector takes no credentials.</p>
            )}
            {d?.webhook && (
              <div className="border-border mt-4 border-t pt-4">
                <p className="text-sm font-medium">Webhook</p>
                <p className="text-muted mb-2 text-xs">
                  POST /api/v1/ingest/webhooks/{i.id} with an HMAC-SHA256 signature (X-NocSoc-Timestamp, X-NocSoc-Nonce,
                  X-NocSoc-Signature). Rotating issues a new secret and invalidates the old one.
                </p>
                <ActionForm action={rotateWebhookSecret} submitLabel={i.webhook_enabled ? "Rotate secret" : "Issue secret"} stepUp>
                  {hidden}
                </ActionForm>
              </div>
            )}
          </Card>
        )}
      </div>

      <section className="mt-6">
        <SectionTitle>Recent runs</SectionTitle>
        <DataTable
          caption="Recent runs"
          rows={runs.map((r) => ({
            _id: String(r.id),
            stream: r.stream,
            trigger: r.trigger,
            status: r.status,
            records: r.records_out,
            error: r.error_class ? `${r.error_class}: ${r.error_detail ?? ""}` : null,
            finished: r.finished_at,
          }))}
          columns={[
            { key: "stream", header: "Stream", filter: true },
            { key: "trigger", header: "Trigger", filter: true, hideOnMobile: true },
            { key: "status", header: "Result", type: "state", filter: true },
            { key: "records", header: "Records", type: "number", align: "right" },
            { key: "error", header: "Error", hideOnMobile: true },
            { key: "finished", header: "Finished", type: "relative" },
          ]}
          emptyText="No runs yet. The runner polls every few seconds when the stream profile is running."
          pageSize={10}
        />
      </section>

      <section className="mt-6">
        <SectionTitle>Dead letters</SectionTitle>
        <DataTable
          caption="Dead letters"
          rows={deadLetters.map((x) => ({ _id: String(x.id), reason: x.reason, detail: x.detail, at: x.at }))}
          columns={[
            { key: "reason", header: "Reason", filter: true },
            { key: "detail", header: "Detail" },
            { key: "at", header: "When", type: "relative" },
          ]}
          emptyText="No rejected records."
          pageSize={10}
        />
      </section>

      {canManage && (
        <Card title="Delete integration" className="mt-6">
          <p className="text-muted mb-3 text-xs">Removes the instance, its checkpoints and its stored secrets. Ingested alerts remain.</p>
          <ActionForm action={deleteInstance} submitLabel="Delete" danger stepUp>
            {hidden}
          </ActionForm>
        </Card>
      )}
    </>
  );
}
