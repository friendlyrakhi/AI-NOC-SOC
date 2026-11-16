import { ActionForm } from "@/components/action-form";
import { AdminGuard } from "@/components/admin-guard";
import { KpiTile } from "@/components/indicators";
import { Grid } from "@/components/page-states";
import { Card, Field, NotAvailable, PageHeader } from "@/components/ui";
import { saveAiSettings } from "@/app/actions/ai";
import { getMe } from "@/lib/server/api";
import { getAiAdmin } from "@/lib/server/pipeline";

const PROVIDERS = {
  mock: "Mock (deterministic, offline; default)",
  ollama: "Local model (Ollama)",
  anthropic: "Anthropic Claude (cloud)",
} as const;

export default async function AiAdminPage() {
  const me = await getMe();
  return (
    <>
      <PageHeader
        title="AI settings"
        description="Which model answers for this tenant, whether evidence may leave the platform, redaction and the daily token budget."
      />
      <AdminGuard me={me} permission="ai:admin">
        <AiAdmin />
      </AdminGuard>
    </>
  );
}

async function AiAdmin() {
  const data = await getAiAdmin();
  if (!data) return <NotAvailable what="AI settings" />;
  const { settings: s, usage: u } = data;
  const share = s.daily_token_budget ? Math.round((u.tokens_today / s.daily_token_budget) * 100) : 0;
  return (
    <div className="space-y-6">
      <Grid cols={4}>
        <KpiTile label="Provider" value={s.provider} hint={s.gateway_reachable ? "Gateway reachable" : "Gateway not reachable"} />
        <KpiTile label="Tokens today" value={u.tokens_today.toLocaleString()} hint={`${share}% of ${s.daily_token_budget.toLocaleString()}`} />
        <KpiTile label="AI runs (30 d)" value={u.runs_30d} hint={`${u.by_status.grounded ?? 0} grounded`} />
        <KpiTile label="Feedback" value={`${u.feedback_up} / ${u.feedback_down}`} hint="helpful / not helpful" />
      </Grid>
      <Card title="Provider and data handling">
        <p className="text-muted mb-3 text-xs">
          Cloud providers receive redacted evidence only, and only when the gateway administrator has enabled egress and this tenant opts
          in. Changes need your authenticator code.
        </p>
        <ActionForm action={saveAiSettings} submitLabel="Save settings" stepUp>
          <Field label="Provider">
            <select name="provider" defaultValue={s.provider} className="input mt-1 w-full max-w-md">
              {(Object.keys(PROVIDERS) as (keyof typeof PROVIDERS)[]).map((p) => (
                <option key={p} value={p}>
                  {PROVIDERS[p]}
                  {s.providers_available[p] ? "" : " (not available on this gateway)"}
                </option>
              ))}
            </select>
          </Field>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" name="allow_cloud" defaultChecked={s.allow_cloud} /> Allow sending redacted evidence to a cloud provider
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" name="redact_pii" defaultChecked={s.redact_pii} /> Redact personal data (emails, IPs, phone numbers) for
            any model
          </label>
          <Field label="Daily token budget">
            <input name="daily_token_budget" type="number" min={0} max={100000000} defaultValue={s.daily_token_budget} className="input mt-1 w-40" />
          </Field>
        </ActionForm>
      </Card>
      <Card title="Runs by task (30 days)">
        <ul className="text-sm">
          {Object.entries(u.by_task).map(([task, n]) => (
            <li key={task}>
              {task.replace(/_/g, " ")}: {n}
            </li>
          ))}
          {Object.keys(u.by_task).length === 0 && <li className="text-muted">No AI runs yet.</li>}
        </ul>
      </Card>
    </div>
  );
}
