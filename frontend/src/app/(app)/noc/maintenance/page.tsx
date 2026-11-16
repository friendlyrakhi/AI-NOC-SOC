import { ActionForm } from "@/components/action-form";
import { DataTable, type ColumnSpec } from "@/components/data-table";
import { SectionTitle } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { Card, Field, NotAvailable, PageHeader } from "@/components/ui";
import {
  cancelMaintenance,
  createMaintenance,
  createSuppression,
  disableSuppression,
  setCorrelationRule,
} from "@/app/actions/incidents";
import { formatTime } from "@/lib/format";
import { getMe } from "@/lib/server/api";
import { getOperationsControls, getServices } from "@/lib/server/pipeline";

const windowColumns: ColumnSpec[] = [
  { key: "title", header: "Window" },
  { key: "state", header: "State", type: "state", filter: true },
  { key: "services", header: "Services" },
  { key: "starts", header: "Starts", type: "time" },
  { key: "ends", header: "Ends", type: "time" },
];

const ruleColumns: ColumnSpec[] = [
  { key: "name", header: "Rule" },
  { key: "match", header: "Matches", type: "mono" },
  { key: "hits", header: "Suppressed", type: "number", align: "right" },
  { key: "expires", header: "Expires", type: "time" },
];

export default async function MaintenancePage() {
  const me = await getMe();
  const denied = gate(me, "maintenance:read", "Maintenance & noise control");
  if (denied) return denied;
  if (me.mode === "aggregate") return <NotAvailable what="Maintenance (select a single customer)" />;
  const [{ windows, rules, correlation }, services] = await Promise.all([getOperationsControls(), getServices()]);
  const names = new Map((services ?? []).map((s) => [s.id, s.name]));
  const can = (p: string) => me.permissions.includes(p);
  const active = (windows ?? []).filter((w) => w.state === "active" || w.state === "scheduled");

  return (
    <>
      <PageHeader
        title="Maintenance & noise control"
        description="Maintenance windows and suppression rules stop expected alerts from opening incidents. Suppressed alerts are kept and labelled, never deleted."
      />

      <SectionTitle>Maintenance windows</SectionTitle>
      <DataTable
        caption="Maintenance windows"
        rows={(windows ?? []).map((w) => ({
          _id: w.id,
          title: w.title,
          state: w.state,
          services: w.service_ids.map((s) => names.get(s) ?? s).join(", ") || `${w.asset_ids.length} asset(s)`,
          starts: w.starts_at,
          ends: w.ends_at,
          _details: { Window: w.title, Reason: w.reason || null, Starts: formatTime(w.starts_at), Ends: formatTime(w.ends_at) },
        }))}
        columns={windowColumns}
        emptyText="No maintenance windows."
      />
      {can("maintenance:manage") && (
        <div className="mt-4 grid gap-6 lg:grid-cols-2">
          <Card title="Schedule a window">
            <ActionForm action={createMaintenance} submitLabel="Save window" resetOnSuccess>
              <Field label="Title">
                <input name="title" required maxLength={200} className="input mt-1 w-full" />
              </Field>
              <fieldset>
                <legend className="text-muted text-xs">Services</legend>
                <div className="mt-1 grid grid-cols-2 gap-1">
                  {(services ?? []).map((s) => (
                    <label key={s.id} className="flex items-center gap-2 text-sm">
                      <input type="checkbox" name="service_ids" value={s.id} /> {s.name}
                    </label>
                  ))}
                </div>
              </fieldset>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Starts in (minutes)">
                  <input name="starts_in_minutes" type="number" min={0} max={10080} defaultValue={0} className="input mt-1 w-28" />
                </Field>
                <Field label="Duration (hours)">
                  <input name="hours" type="number" min={1} max={168} defaultValue={2} className="input mt-1 w-28" />
                </Field>
              </div>
              <Field label="Reason">
                <input name="reason" maxLength={1000} className="input mt-1 w-full" />
              </Field>
            </ActionForm>
          </Card>
          {active.length > 0 && (
            <Card title="Cancel a window">
              <ul className="space-y-2">
                {active.map((w) => (
                  <li key={w.id} className="flex items-center justify-between gap-3 text-sm">
                    <span>{w.title}</span>
                    <ActionForm action={cancelMaintenance} submitLabel="Cancel" danger className="flex items-center gap-2">
                      <input type="hidden" name="window_id" value={w.id} />
                    </ActionForm>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      )}

      <div className="mt-8">
        <SectionTitle>Suppression rules</SectionTitle>
      </div>
      {rules ? (
        <DataTable
          caption="Suppression rules"
          rows={rules.map((r) => ({
            _id: r.id,
            name: r.name,
            match: Object.entries(r.match)
              .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : String(v)}`)
              .join(" "),
            hits: r.hits,
            expires: r.expires_at,
            _details: { Rule: r.name, Reason: r.reason, Matches: JSON.stringify(r.match), Suppressed: r.hits },
          }))}
          columns={ruleColumns}
          emptyText="No active suppression rules."
        />
      ) : (
        <NotAvailable what="Suppression rules" />
      )}
      {can("alert:suppress") && (
        <div className="mt-4 grid gap-6 lg:grid-cols-2">
          <Card title="Add a suppression rule">
            <p className="text-muted mb-2 text-xs">All given conditions must match. Rules always expire; fix persistent noise at the source.</p>
            <ActionForm action={createSuppression} submitLabel="Add rule" resetOnSuccess>
              <Field label="Name">
                <input name="name" required maxLength={200} className="input mt-1 w-full" />
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Connector id (optional)">
                  <input name="connector" maxLength={64} placeholder="datadog" className="input mt-1 w-full" />
                </Field>
                <Field label="Title contains (optional)">
                  <input name="title_contains" maxLength={200} className="input mt-1 w-full" />
                </Field>
                <Field label="Severity (optional)">
                  <select name="severity" className="input mt-1 w-full" defaultValue="">
                    <option value="">Any</option>
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                  </select>
                </Field>
                <Field label="Expires after (hours)">
                  <input name="hours" type="number" min={1} max={720} defaultValue={24} className="input mt-1 w-28" />
                </Field>
              </div>
              <Field label="Reason">
                <input name="reason" required maxLength={1000} className="input mt-1 w-full" />
              </Field>
            </ActionForm>
          </Card>
          {rules && rules.length > 0 && (
            <Card title="Disable a rule">
              <ul className="space-y-2">
                {rules.map((r) => (
                  <li key={r.id} className="flex items-center justify-between gap-3 text-sm">
                    <span>{r.name}</span>
                    <ActionForm action={disableSuppression} submitLabel="Disable" danger className="flex items-center gap-2">
                      <input type="hidden" name="rule_id" value={r.id} />
                    </ActionForm>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      )}

      {correlation && (
        <div className="mt-8">
          <SectionTitle>Correlation rules</SectionTitle>
          <div className="grid gap-4 lg:grid-cols-3">
            {correlation.map((r) => (
              <Card key={r.key} title={r.title}>
                <p className="text-muted mb-3 text-xs">{r.description}</p>
                <p className="mb-3 text-sm">
                  {r.enabled ? "Enabled" : "Disabled"} · window {r.window_minutes} min
                  {r.window_minutes !== r.default_window_minutes && ` (default ${r.default_window_minutes})`}
                </p>
                {can("correlation:manage") && (
                  <ActionForm action={setCorrelationRule} submitLabel="Save" stepUp>
                    <input type="hidden" name="key" value={r.key} />
                    <label className="flex items-center gap-2 text-sm">
                      <input type="checkbox" name="enabled" defaultChecked={r.enabled} /> Enabled
                    </label>
                    <Field label="Window (minutes)">
                      <input name="window_minutes" type="number" min={1} max={1440} defaultValue={r.window_minutes} className="input mt-1 w-28" />
                    </Field>
                  </ActionForm>
                )}
              </Card>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
