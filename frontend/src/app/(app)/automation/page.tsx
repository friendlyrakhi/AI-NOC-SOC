import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { RequestsTable, TierBadge } from "@/components/automation";
import { DataTable } from "@/components/data-table";
import { KpiTile, SandboxNotice, StateBadge } from "@/components/indicators";
import { gate, Grid } from "@/components/page-states";
import { Tabs } from "@/components/tabs";
import { Card, Field, PageHeader } from "@/components/ui";
import { setActionPolicy, setKillSwitch } from "@/app/actions/automation";
import { formatTime } from "@/lib/format";
import { getMe, type Me } from "@/lib/server/api";
import {
  getCatalog,
  getInbox,
  getKillSwitch,
  getPlaybooks,
  getRequests,
  getRuns,
  stepsOf,
  TIER_HELP,
  type CatalogEntry,
  type KillSwitch,
} from "@/lib/server/automation";

import { DemoAutomation } from "./_demo";

function KillSwitchCard({ ks, me }: { ks: KillSwitch; me: Me }) {
  const can = me.permissions.includes("automation:killswitch");
  return (
    <Card title="Kill switch">
      <p className={`text-sm font-medium ${ks.engaged ? "text-danger" : "text-success"}`} role="status">
        {ks.engaged ? "Engaged: automation is halted" : "Released: automation may run"}
      </p>
      <p className="text-muted mt-1 text-xs">
        {ks.global_engaged ? "Engaged platform-wide by a platform administrator. " : ""}
        {ks.tenant_engaged ? `Engaged for this tenant${ks.changed_at ? ` since ${formatTime(ks.changed_at)}` : ""}: ${ks.reason}` : ""}
        {!ks.engaged && "When engaged, running playbooks stop at their next step and no approved action executes."}
      </p>
      {can && !ks.global_engaged && (
        <div className="mt-3">
          <ActionForm action={setKillSwitch} submitLabel={ks.tenant_engaged ? "Release kill switch" : "Engage kill switch"} stepUp danger={!ks.tenant_engaged}>
            <input type="hidden" name="engaged" value={ks.tenant_engaged ? "false" : "true"} />
            <Field label="Reason (audited)">
              <input name="reason" required maxLength={500} className="input w-full" />
            </Field>
          </ActionForm>
        </div>
      )}
    </Card>
  );
}

function PolicyForm({ c }: { c: CatalogEntry }) {
  return (
    <details className="text-xs">
      <summary className="text-primary cursor-pointer">Policy</summary>
      <ActionForm action={setActionPolicy} submitLabel="Save policy" stepUp className="mt-2 space-y-2">
        <input type="hidden" name="action_key" value={c.key} />
        <label className="flex items-center gap-2">
          <input type="checkbox" name="allowed" defaultChecked={c.allowed} /> Allowed for this tenant
        </label>
        <label className="flex items-center gap-2">
          <input type="checkbox" name="require_justification" defaultChecked={c.require_justification} /> Require a justification
        </label>
        <Field label="Raise tier (never below the catalog tier)">
          <select name="tier_override" defaultValue={c.effective_tier !== c.tier ? c.effective_tier : ""} className="input">
            <option value="">Catalog tier ({c.tier})</option>
            {["T1", "T2", "T3"]
              .filter((t) => t > c.tier)
              .map((t) => (
                <option key={t} value={t}>
                  {t}: {TIER_HELP[t]}
                </option>
              ))}
          </select>
        </Field>
      </ActionForm>
    </details>
  );
}

export default async function AutomationPage() {
  const me = await getMe();
  const denied = gate(me, "playbook:read", "Automation center");
  if (denied) return denied;
  if (me.mode === "aggregate") {
    return <DemoAutomation reason="Automation acts on one customer at a time: pick a customer in the switcher to see its real playbooks and approvals." />;
  }
  const can = (p: string) => me.permissions.includes(p);
  const [playbooks, runs, catalog, requests, inbox, ks] = await Promise.all([
    getPlaybooks(),
    getRuns(),
    can("action:read") ? getCatalog() : Promise.resolve(null),
    can("action:read") ? getRequests({ limit: 100 }) : Promise.resolve(null),
    can("action:approve") ? getInbox() : Promise.resolve(null),
    can("action:read") ? getKillSwitch() : Promise.resolve(null),
  ]);
  if (!playbooks) return <DemoAutomation reason="Automation data is not available right now." />;

  const published = playbooks.filter((p) => p.published_version != null);
  const running = (runs ?? []).filter((r) => r.status === "running");

  return (
    <>
      <PageHeader
        title="Automation center"
        description="Versioned playbooks, the action catalog and policy, approvals and the kill switch."
        actions={
          inbox && inbox.length > 0 ? (
            <Link href="/automation/approvals" className="btn btn-primary">
              Approvals inbox ({inbox.length})
            </Link>
          ) : undefined
        }
      />
      <SandboxNotice>
        Actions run through sandbox connectors in <strong>simulate</strong> or <strong>dry-run</strong> mode only. Live execution is disabled in
        this build: the API, the database and the workflow worker all refuse it.
      </SandboxNotice>
      <Grid cols={4}>
        <KpiTile label="Published playbooks" value={published.length} hint={`${playbooks.length} in total`} />
        <KpiTile label="Running now" value={running.length} hint={`${runs?.length ?? 0} recent runs`} />
        <KpiTile label="Waiting for you" value={inbox ? inbox.length : "—"} hint={inbox ? "Approval requests" : "You are not an approver"} />
        <KpiTile label="Kill switch" value={ks ? (ks.engaged ? "Engaged" : "Released") : "—"} />
      </Grid>

      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <Tabs
            tabs={[
              {
                label: "Playbooks",
                count: playbooks.length,
                content: (
                  <div className="grid gap-4 lg:grid-cols-2">
                    {playbooks.length === 0 && <p className="text-muted text-sm">No playbooks yet.</p>}
                    {playbooks.map((p) => {
                      const v = (p.versions ?? []).find((x) => x.version === p.published_version) ?? p.versions?.[0];
                      return (
                        <Card key={p.id}>
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <h2 className="text-sm font-semibold">
                                <Link href={`/automation/playbooks/${p.id}`} className="hover:underline">
                                  {p.name}
                                </Link>
                              </h2>
                              <p className="text-muted text-xs">
                                {p.domain.toUpperCase()} · {p.published_version ? `v${p.published_version} published` : "not published"} · {(p.versions ?? []).length} version(s)
                              </p>
                            </div>
                            {p.max_tier && <TierBadge tier={p.max_tier} />}
                          </div>
                          <p className="text-muted mt-2 text-xs">{p.description}</p>
                          <ol className="mt-3 space-y-1">
                            {stepsOf(v?.definition).map((s, i) => (
                              <li key={s.id} className="flex items-center gap-2 text-sm">
                                <span className="text-muted w-4 text-right text-xs">{i + 1}.</span>
                                <code className="flex-1 font-mono text-xs">{s.action}</code>
                                <span className="text-muted text-xs">{s.target === "incident" ? "incident" : "primary asset"}</span>
                              </li>
                            ))}
                          </ol>
                        </Card>
                      );
                    })}
                  </div>
                ),
              },
              {
                label: "Runs",
                count: runs?.length ?? 0,
                content: (
                  <DataTable
                    caption="Playbook runs"
                    rows={(runs ?? []).map((r) => ({
                      _id: r.id,
                      _href: `/automation/runs/${r.id}`,
                      playbook: r.playbook_name,
                      version: `v${r.version}`,
                      mode: r.mode === "dry_run" ? "Dry run" : "Simulate",
                      status: r.status,
                      steps: Object.keys(r.steps).length,
                      started: r.started_at,
                    }))}
                    columns={[
                      { key: "playbook", header: "Playbook", type: "link", filter: true },
                      { key: "version", header: "Version" },
                      { key: "mode", header: "Mode", filter: true },
                      { key: "status", header: "Status", type: "state", filter: true },
                      { key: "steps", header: "Steps done", type: "number", align: "right", hideOnMobile: true },
                      { key: "started", header: "Started", type: "relative" },
                    ]}
                    emptyText="No runs yet. Start a playbook from an incident or from the playbook page."
                  />
                ),
              },
              ...(requests
                ? [{ label: "Action requests", count: requests.length, content: <RequestsTable requests={requests} caption="Action requests" /> }]
                : []),
              ...(catalog
                ? [
                    {
                      label: "Action catalog",
                      count: catalog.length,
                      content: (
                        <ul className="divide-border divide-y">
                          {catalog.map((c) => (
                            <li key={c.key} className="flex flex-wrap items-start gap-3 py-2">
                              <TierBadge tier={c.effective_tier} />
                              <div className="min-w-60 flex-1">
                                <p className="font-mono text-sm">{c.key}</p>
                                <p className="text-muted text-xs">
                                  {c.description} · {c.target_kind} · {c.reversible ? "reversible" : "not reversible"}
                                  {c.effective_tier !== c.tier && ` · raised from ${c.tier}`}
                                </p>
                              </div>
                              <StateBadge value={c.allowed ? "allowed" : "denied"} />
                              {can("action:policy") && <PolicyForm c={c} />}
                            </li>
                          ))}
                        </ul>
                      ),
                    },
                  ]
                : []),
            ]}
          />
        </div>
        <div className="space-y-6">
          {ks && <KillSwitchCard ks={ks} me={me} />}
          <Card title="Approval rules">
            <ul className="text-muted space-y-1 text-xs">
              {Object.entries(TIER_HELP).map(([t, text]) => (
                <li key={t}>
                  <TierBadge tier={t} /> {text}
                </li>
              ))}
              <li>Requests suggested by the AI always need a human approver.</li>
              <li>The requester can never approve their own request.</li>
              <li>Approvals need a fresh authenticator code and expire if nobody decides in time.</li>
            </ul>
          </Card>
        </div>
      </div>
    </>
  );
}
