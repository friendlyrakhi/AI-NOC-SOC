import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { DataTable } from "@/components/data-table";
import { EventResults, QueryFields, type EventItem } from "@/components/events";
import { SandboxNotice, StateBadge } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { PollRefresh } from "@/components/poll-refresh";
import { Card, Field, PageHeader } from "@/components/ui";
import { attachHunt, deleteHunt, runHunt, saveHunt } from "@/app/actions/insights";
import { formatTime } from "@/lib/format";
import { getMe } from "@/lib/server/api";
import { getHuntResults, getHuntRuns, getHunts, type HuntRun } from "@/lib/server/insights";
import { getIncidents, isUuid } from "@/lib/server/pipeline";

import { DemoHunting } from "./_demo";

function describe(query: Record<string, unknown>): string {
  const parts = Object.entries(query)
    .filter(([k, v]) => !["since", "until"].includes(k) && v !== "" && !(Array.isArray(v) && v.length === 0))
    .map(([k, v]) => `${k.replace("_", " ")}: ${Array.isArray(v) ? v.join(", ") : String(v)}`);
  return parts.length ? parts.join(" · ") : "all events";
}

export default async function HuntingPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const me = await getMe();
  const denied = gate(me, "hunt:run", "Threat hunting");
  if (denied) return denied;
  const [hunts, runs] = me.mode === "tenant" ? await Promise.all([getHunts(), getHuntRuns()]) : [null, null];
  if (!hunts || !runs) return <DemoHunting />;
  const selected = String((await searchParams).run ?? "");
  const [results, incidents] = await Promise.all([
    isUuid(selected) ? getHuntResults(selected) : Promise.resolve(null),
    isUuid(selected) && me.permissions.includes("incident:comment") ? getIncidents("soc", 50) : Promise.resolve(null),
  ]);
  const running = (r: HuntRun) => r.status === "queued" || r.status === "running";

  return (
    <>
      <PageHeader
        title="Threat hunting"
        description="Saved hunts and hunt runs over this tenant's events (last 30 days). Runs execute in the background; results are kept with the run and can be attached to an incident."
      />
      <SandboxNotice>Events come from sandbox connectors processed by the real platform.</SandboxNotice>

      {results && (
        <section className="mb-8" aria-labelledby="run-title">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <h2 id="run-title" className="text-sm font-semibold">
              {results.hunt_name ?? "Ad-hoc hunt"} · {formatTime(results.created_at)} <StateBadge value={results.status} />
            </h2>
            {running(results) && <PollRefresh seconds={2} />}
          </div>
          <p className="text-muted mb-3 text-xs">Query: {describe(results.query)}</p>
          {results.status === "failed" && <p className="text-danger text-sm">{results.error}</p>}
          {results.status === "succeeded" && (
            <>
              <EventResults
                items={results.results as unknown as EventItem[]}
                total={results.hit_count}
                facets={results.facets as Record<string, { value: string; count: number }[]>}
                caption="Hunt results"
              />
              {incidents && incidents.items.length > 0 && (
                <Card title="Attach results to an incident" className="mt-4">
                  <ActionForm action={attachHunt} submitLabel="Attach summary" className="flex flex-wrap items-end gap-3">
                    <input type="hidden" name="hunt_run_id" value={results.id} />
                    <Field label="Incident">
                      <select name="incident_id" className="input">
                        {incidents.items.map((i) => (
                          <option key={i.id} value={i.id}>
                            {i.number} · {i.title}
                          </option>
                        ))}
                      </select>
                    </Field>
                    <Field label="Note (optional)">
                      <input name="note" maxLength={1000} className="input w-64" />
                    </Field>
                  </ActionForm>
                </Card>
              )}
            </>
          )}
        </section>
      )}

      <div className="grid gap-6 xl:grid-cols-3">
        <div className="space-y-6 xl:col-span-2">
          <section aria-labelledby="saved-hunts">
            <h2 id="saved-hunts" className="mb-3 text-sm font-semibold">
              Saved hunts
            </h2>
            {hunts.length === 0 ? (
              <Card>
                <p className="text-muted text-sm">No saved hunts yet. Define one on the right.</p>
              </Card>
            ) : (
              <ul className="grid gap-3 lg:grid-cols-2" aria-label="Saved hunts">
                {hunts.map((h) => (
                  <li key={h.id}>
                    <Card>
                      <h3 className="text-sm font-semibold">{h.name}</h3>
                      {h.description && <p className="text-muted mt-1 text-xs">{h.description}</p>}
                      <p className="mt-2 font-mono text-xs break-words">{describe(h.query)}</p>
                      <p className="text-muted mt-2 text-xs">
                        {h.last_run_at ? `Last run ${formatTime(h.last_run_at)} · ${h.last_hit_count ?? 0} matches` : "Not run yet"} · window: last 24 hours
                      </p>
                      <div className="mt-3 flex flex-wrap gap-2">
                        <ActionForm action={runHunt} submitLabel="Run hunt" className="flex items-center gap-2">
                          <input type="hidden" name="hunt_id" value={h.id} />
                        </ActionForm>
                        <ActionForm action={deleteHunt} submitLabel="Delete" danger className="flex items-center gap-2">
                          <input type="hidden" name="hunt_id" value={h.id} />
                        </ActionForm>
                      </div>
                    </Card>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section>
            <h2 className="mb-3 text-sm font-semibold">Recent runs</h2>
            <DataTable
              caption="Hunt runs"
              rows={runs.map((r) => ({
                _id: r.id,
                _href: `/soc/hunting?run=${r.id}`,
                name: r.hunt_name ?? "Ad-hoc hunt",
                query: describe(r.query),
                status: r.status,
                hits: r.hit_count,
                created: r.created_at,
              }))}
              columns={[
                { key: "name", header: "Hunt", type: "link" },
                { key: "query", header: "Query", hideOnMobile: true },
                { key: "status", header: "Status", type: "state", filter: true },
                { key: "hits", header: "Matches", type: "number", align: "right" },
                { key: "created", header: "Started", type: "relative" },
              ]}
              emptyText="No hunts run yet."
            />
          </section>
        </div>
        <div className="space-y-6">
          <Card title="Run a hunt now">
            <ActionForm action={runHunt} submitLabel="Run hunt">
              <QueryFields />
            </ActionForm>
          </Card>
          <Card title="Save a hunt">
            <ActionForm action={saveHunt} submitLabel="Save hunt" resetOnSuccess>
              <Field label="Name">
                <input name="name" required maxLength={200} className="input w-full" />
              </Field>
              <Field label="Hypothesis or description">
                <input name="description" maxLength={2000} className="input w-full" />
              </Field>
              <QueryFields hours={false} />
            </ActionForm>
            <p className="text-muted mt-2 text-xs">
              Per tenant at most two hunts run at once.{" "}
              <Link href="/soc/investigations" className="text-primary underline">
                Explore events interactively →
              </Link>
            </p>
          </Card>
        </div>
      </div>
    </>
  );
}
