import Link from "next/link";

import { DataTable } from "@/components/data-table";
import { Field } from "@/components/ui";

/** Event search fields (the constrained query the API accepts) and results with facet pivots. */

export const CLASSES = ["alert", "detection", "authentication", "process", "network", "api_activity", "ticket"] as const;
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export interface QueryValues {
  text?: string;
  domain?: string;
  severity?: string[];
  classes?: string[];
  asset?: string;
  actor_user?: string;
  ip?: string;
  connector?: string;
  mitre?: string;
  hours?: string;
}

export function QueryFields({ values = {}, hours = true }: { values?: QueryValues; hours?: boolean }) {
  return (
    <div className="space-y-3">
      <Field label="Search text" hint='Words, "exact phrases", -exclude, prefix*. Searches titles, assets, users and attributes.'>
        <input name="text" defaultValue={values.text} maxLength={300} className="input w-full" />
      </Field>
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label="Domain">
          <select name="domain" defaultValue={values.domain ?? ""} className="input w-full">
            <option value="">Any</option>
            <option value="noc">NOC</option>
            <option value="soc">SOC</option>
          </select>
        </Field>
        <Field label="Asset (exact)">
          <input name="asset" defaultValue={values.asset} maxLength={200} className="input w-full" />
        </Field>
        <Field label="User (exact)">
          <input name="actor_user" defaultValue={values.actor_user} maxLength={200} className="input w-full" />
        </Field>
        <Field label="IP address">
          <input name="ip" defaultValue={values.ip} maxLength={45} className="input w-full font-mono" />
        </Field>
        <Field label="ATT&CK techniques" hint="e.g. T1003, T1059.001">
          <input name="mitre" defaultValue={values.mitre} maxLength={120} className="input w-full font-mono" />
        </Field>
        {hours && (
          <Field label="Time window">
            <select name="hours" defaultValue={values.hours ?? "24"} className="input w-full">
              <option value="1">Last hour</option>
              <option value="24">Last 24 hours</option>
              <option value="168">Last 7 days</option>
              <option value="720">Last 30 days</option>
            </select>
          </Field>
        )}
      </div>
      <fieldset>
        <legend className="text-muted text-xs">Severity</legend>
        <div className="mt-1 flex flex-wrap gap-3 text-sm">
          {SEVERITIES.map((s) => (
            <label key={s} className="flex items-center gap-1 capitalize">
              <input type="checkbox" name="severity" value={s} defaultChecked={values.severity?.includes(s)} /> {s}
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset>
        <legend className="text-muted text-xs">Event class</legend>
        <div className="mt-1 flex flex-wrap gap-3 text-sm">
          {CLASSES.map((c) => (
            <label key={c} className="flex items-center gap-1">
              <input type="checkbox" name="classes" value={c} defaultChecked={values.classes?.includes(c)} /> {c.replace("_", " ")}
            </label>
          ))}
        </div>
      </fieldset>
    </div>
  );
}

export interface EventItem {
  event_id: string;
  class: string;
  domain: string;
  severity: string;
  observed_at: string;
  connector: string;
  title: string;
  asset?: string | null;
  actor_user?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  mitre?: string[];
}

const FACET_LABEL: Record<string, string> = { severity: "Severity", asset: "Assets", actor_user: "Users", connector: "Sources" };

/** Results table plus facets; a facet value links to Investigate filtered on it (pivot). */
export function EventResults({
  items,
  total,
  facets,
  caption,
}: {
  items: EventItem[];
  total: number;
  facets: Record<string, { value: string; count: number }[]>;
  caption: string;
}) {
  const pivot = (field: string, value: string) => `/soc/investigations?${new URLSearchParams({ [field]: value }).toString()}`;
  return (
    <div className="grid gap-6 xl:grid-cols-4">
      <aside className="space-y-4" aria-label="Facets">
        {Object.entries(facets).map(([field, buckets]) =>
          buckets.length ? (
            <div key={field}>
              <h3 className="text-muted mb-1 text-xs font-semibold">{FACET_LABEL[field] ?? field}</h3>
              <ul className="space-y-0.5 text-sm">
                {buckets.map((b) => (
                  <li key={b.value} className="flex justify-between gap-2">
                    <Link href={pivot(field, b.value)} className="text-primary truncate hover:underline" title={`Investigate ${b.value}`}>
                      {b.value}
                    </Link>
                    <span className="text-muted tabular-nums">{b.count}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null,
        )}
      </aside>
      <div className="xl:col-span-3">
        <p className="text-muted mb-2 text-xs">
          {total} matching event{total === 1 ? "" : "s"}
          {total > items.length ? `, showing the newest ${items.length}` : ""}.
        </p>
        <DataTable
          caption={caption}
          rows={items.map((e) => ({
            _id: e.event_id,
            at: e.observed_at,
            severity: e.severity,
            title: e.title,
            eventClass: e.class.replace("_", " "),
            asset: e.asset ?? null,
            user: e.actor_user ?? null,
            ip: [e.src_ip, e.dst_ip].filter(Boolean).join(" → ") || null,
            source: e.connector,
            mitre: (e.mitre ?? []).join(", ") || null,
            _details: {
              Title: e.title,
              Time: e.observed_at,
              Severity: e.severity,
              Class: e.class,
              Domain: e.domain.toUpperCase(),
              Asset: e.asset ?? null,
              User: e.actor_user ?? null,
              "Source IP": e.src_ip ?? null,
              "Destination IP": e.dst_ip ?? null,
              Source: `${e.connector} (sandbox connector)`,
              "ATT&CK": (e.mitre ?? []).join(", ") || null,
            },
          }))}
          columns={[
            { key: "at", header: "Time", type: "time" },
            { key: "severity", header: "Severity", type: "severity", filter: true },
            { key: "title", header: "Event" },
            { key: "eventClass", header: "Class", filter: true, hideOnMobile: true },
            { key: "asset", header: "Asset", type: "mono" },
            { key: "user", header: "User", hideOnMobile: true },
            { key: "ip", header: "IP", type: "mono", hideOnMobile: true },
            { key: "source", header: "Source", filter: true, hideOnMobile: true },
          ]}
          emptyText="No events match."
          exportName="events"
          dataSource="sandbox"
        />
      </div>
    </div>
  );
}
