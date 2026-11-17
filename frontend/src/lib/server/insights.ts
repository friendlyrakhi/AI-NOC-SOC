import "server-only";

import { apiFetch, apiGetOptional, type Schemas } from "@/lib/server/api";

/**
 * P6 data: KPIs from the analytics facts, search, hunts, reports and the AI briefing. Each loader
 * returns null when it is not available to this caller (permission, the read-only "All customers"
 * view, or the stream/search profile not running), so pages can say so instead of inventing data.
 */
export type Kpi = Schemas["Kpi"];
export type KpiSet = Schemas["KpiSet"];
export type Drill = Schemas["Drill"];
export type SeriesPoint = Schemas["SeriesPoint"];
export type Overview = Schemas["Overview"];
export type CustomerKpis = Schemas["CustomerKpis"];
export type Report = Schemas["ReportOut"];
export type Hunt = Schemas["HuntOut"];
export type HuntRun = Schemas["HuntRunOut"];
export type HuntResults = Schemas["HuntResultsOut"];
export type EventSearch = Schemas["EventSearchOut"];
export type AiRun = Schemas["AiRunOut"];

export const PERIODS = ["24h", "7d", "30d", "90d"] as const;
export type Period = (typeof PERIODS)[number];
export const DOMAINS = ["all", "noc", "soc"] as const;
export type Domain = (typeof DOMAINS)[number];

export function period(value: string | string[] | undefined, fallback: Period = "7d"): Period {
  return (PERIODS as readonly string[]).includes(String(value)) ? (value as Period) : fallback;
}

export function domain(value: string | string[] | undefined): Domain {
  return (DOMAINS as readonly string[]).includes(String(value)) ? (value as Domain) : "all";
}

async function optional<T>(path: string, init?: { method?: string; body?: unknown }): Promise<T | null> {
  const r = await apiFetch<T>(path, init);
  if (r.ok) return r.data;
  if (r.status === 401) return apiGetOptional<T>(path); // reuses the sign-in redirect
  return null;
}

export const getOverview = (p: Period) => optional<Overview>(`/command-center/overview?period=${p}`);
export const getKpis = (d: Domain, p: Period) => optional<KpiSet>(`/analytics/kpis?domain=${d}&period=${p}`);
export const getDrill = (key: string, d: Domain, p: Period) =>
  optional<Drill>(`/analytics/kpis/${encodeURIComponent(key)}/records?domain=${d}&period=${p}&limit=1000`);
export const getCustomerKpis = (p: Period) => optional<CustomerKpis[]>(`/command-center/customers?period=${p}`);
export const getReports = () => optional<Report[]>("/reports");
export const getHunts = () => optional<Hunt[]>("/hunts");
export const getHuntRuns = () => optional<HuntRun[]>("/hunt/queries?limit=25");
export const getHuntResults = (id: string) => optional<HuntResults>(`/hunt/queries/${encodeURIComponent(id)}/results`);
export const getLatestBriefing = () => optional<AiRun | null>("/ai/briefing/latest");

export function getSeries(
  metric: "alerts" | "incidents",
  p: Period,
  groupBy: "none" | "severity" | "domain",
  d: Domain = "all",
): Promise<SeriesPoint[] | null> {
  const interval = p === "24h" ? "hour" : "day";
  return optional<SeriesPoint[]>(
    `/analytics/timeseries?metric=${metric}&interval=${interval}&period=${p}&domain=${d}&group_by=${groupBy}`,
  );
}

// ---------------------------------------------------------------- formatting (shared by pages)
export function kpiValue(k: Kpi): { value: string; unit?: string } {
  if (k.value === null || k.value === undefined) return { value: "—" };
  if (k.unit === "ratio") return { value: (k.value * 100).toFixed(1), unit: "%" };
  if (k.unit === "seconds") {
    const minutes = k.value / 60;
    return minutes < 120 ? { value: minutes.toFixed(0), unit: "min" } : { value: (minutes / 60).toFixed(1), unit: "h" };
  }
  return { value: k.value.toFixed(0) };
}

export function kpiBasis(k: Kpi): string {
  const noun = k.records === "incident" ? "incident" : "alert";
  const n = (count: number) => `${count} ${noun}${count === 1 ? "" : "s"}`;
  if (k.numerator !== null && k.numerator !== undefined) return `${k.numerator} of ${n(k.basis)}`;
  if (k.unit === "seconds") return `over ${n(k.basis)}`;
  return n(k.basis);
}

/** Buckets -> chart series with one point per bucket for every group (missing buckets are 0). */
export function toSeries(points: SeriesPoint[], p: Period): { name: string; points: { date: string; value: number }[] }[] {
  const hourly = p === "24h";
  const now = Date.now();
  const span = { "24h": 24, "7d": 7, "30d": 30, "90d": 90 }[p];
  const step = hourly ? 3_600_000 : 86_400_000;
  const start = Math.floor((now - (span - 1) * step) / step) * step;
  const buckets = Array.from({ length: span }, (_, i) => new Date(start + i * step).toISOString());
  const key = (iso: string) => Math.floor(Date.parse(iso) / step) * step;
  const groups = [...new Set(points.map((x) => x.group || "all"))].sort();
  return groups.map((g) => {
    const counts = new Map<number, number>();
    for (const x of points) if ((x.group || "all") === g) counts.set(key(x.start), (counts.get(key(x.start)) ?? 0) + x.count);
    return { name: g, points: buckets.map((b) => ({ date: b, value: counts.get(key(b)) ?? 0 })) };
  });
}
