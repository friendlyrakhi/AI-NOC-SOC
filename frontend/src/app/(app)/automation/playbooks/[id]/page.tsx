import Link from "next/link";
import { notFound } from "next/navigation";

import { ActionForm } from "@/components/action-form";
import { TierBadge } from "@/components/automation";
import { SandboxNotice, StateBadge } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { Card, Field, PageHeader } from "@/components/ui";
import { newVersion, publishVersion, runPlaybook } from "@/app/actions/automation";
import { formatTime } from "@/lib/format";
import { getMe } from "@/lib/server/api";
import { getCatalog, getPlaybook, stepsOf } from "@/lib/server/automation";
import { getIncidents, isUuid } from "@/lib/server/pipeline";

export default async function PlaybookPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const me = await getMe();
  const denied = gate(me, "playbook:read", "Playbook");
  if (denied) return denied;
  const p = isUuid(id) ? await getPlaybook(id) : null;
  if (!p) notFound();
  const can = (perm: string) => me.permissions.includes(perm);
  const [catalog, incidents] = await Promise.all([
    can("action:read") ? getCatalog() : Promise.resolve(null),
    can("playbook:run") && p.published_version ? getIncidents() : Promise.resolve(null),
  ]);
  const open = (incidents?.items ?? []).filter((i) => i.status !== "closed" && i.status !== "resolved");
  const tiers = new Map((catalog ?? []).map((c) => [c.key, c.effective_tier]));
  const versions = [...(p.versions ?? [])].sort((a, b) => b.version - a.version);
  const latest = versions[0];
  const published = versions.find((v) => v.status === "published");

  return (
    <>
      <p className="mb-2 text-xs">
        <Link href="/automation" className="text-primary hover:underline">
          ← Automation center
        </Link>
      </p>
      <PageHeader
        title={p.name}
        description={`${p.domain.toUpperCase()} playbook · ${p.description}`}
        actions={p.max_tier ? <TierBadge tier={p.max_tier} /> : undefined}
      />
      <SandboxNotice>Runs execute in simulate or dry-run mode through sandbox connectors. Live execution is disabled in this build.</SandboxNotice>

      <div className="grid gap-6 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          {versions.map((v) => (
            <Card key={v.id}>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <h2 className="text-sm font-semibold">
                  Version {v.version} <StateBadge value={v.status} />
                </h2>
                <p className="text-muted text-xs">
                  Created {formatTime(v.created_at)}
                  {v.published_at && ` · published ${formatTime(v.published_at)}`}
                </p>
              </div>
              <ol className="mt-3 space-y-1.5">
                {stepsOf(v.definition).map((s, i) => (
                  <li key={s.id} className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="text-muted w-4 text-right text-xs">{i + 1}.</span>
                    <code className="font-mono text-xs">{s.action}</code>
                    {tiers.get(s.action) && <TierBadge tier={tiers.get(s.action)!} />}
                    <span className="text-muted text-xs">
                      on {s.target === "incident" ? "the incident" : "its primary asset"}
                      {s.requires?.length ? ` · after ${s.requires.join(", ")}` : ""}
                      {s.on_failure === "continue" ? " · continues on failure" : ""}
                    </span>
                  </li>
                ))}
              </ol>
              {v.status === "draft" && can("playbook:publish") && (
                <div className="mt-4">
                  <ActionForm action={publishVersion} submitLabel={`Publish version ${v.version}`} stepUp>
                    <input type="hidden" name="playbook_id" value={p.id} />
                    <input type="hidden" name="version" value={v.version} />
                    <p className="text-muted text-xs">Publishing freezes this version and retires the current one. Runs already started keep their version.</p>
                  </ActionForm>
                </div>
              )}
            </Card>
          ))}
        </div>

        <div className="space-y-6">
          {can("playbook:run") && published && (
            <Card title={`Run version ${published.version}`}>
              {open.length > 0 ? (
                <ActionForm action={runPlaybook} submitLabel="Start run">
                  <input type="hidden" name="playbook_id" value={p.id} />
                  <Field label="Incident">
                    <select name="incident_id" required className="input w-full">
                      {open.map((i) => (
                        <option key={i.id} value={i.id}>
                          {i.number} · {i.title}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Mode">
                    <select name="mode" defaultValue="dry_run" className="input w-full">
                      <option value="dry_run">Dry run: preview every step</option>
                      <option value="simulate">Simulate: sandbox connectors</option>
                    </select>
                  </Field>
                </ActionForm>
              ) : (
                <p className="text-muted text-sm">No open incident to run it against.</p>
              )}
            </Card>
          )}
          {can("playbook:edit") && latest && (
            <Card title="New draft version">
              <ActionForm action={newVersion} submitLabel="Save draft">
                <input type="hidden" name="playbook_id" value={p.id} />
                <Field label="Definition (JSON)" hint="Validated by the API: known actions, valid targets and parameters, no cycles, at most 20 steps.">
                  <textarea name="definition" rows={14} defaultValue={JSON.stringify(latest.definition, null, 2)} className="input w-full font-mono text-xs" />
                </Field>
              </ActionForm>
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
