import type { Health, Severity } from "@/lib/demo/types";
import { SEVERITIES } from "@/lib/demo/types";

/** Status colors (fixed palette); always rendered with a label or icon. */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--status-critical)",
  high: "var(--status-serious)",
  medium: "var(--status-warning)",
  low: "var(--muted)",
  info: "var(--axis)",
};

export const HEALTH_COLOR: Record<Health, string> = {
  healthy: "var(--status-good)",
  degraded: "var(--status-warning)",
  down: "var(--status-critical)",
  maintenance: "var(--muted)",
};

const cap = (s: string) => s[0].toUpperCase() + s.slice(1);

export function severityParts(items: { severity: Severity }[], include: Severity[] = SEVERITIES) {
  return include.map((s) => ({ label: cap(s), value: items.filter((i) => i.severity === s).length, color: SEVERITY_COLOR[s] }));
}

export function healthParts(items: { status: Health }[]) {
  return (["healthy", "degraded", "down", "maintenance"] as Health[]).map((h) => ({
    label: cap(h),
    value: items.filter((i) => i.status === h).length,
    color: HEALTH_COLOR[h],
  }));
}

export function countBy<T>(items: T[], key: (item: T) => string | null | undefined, top = 8) {
  const counts = new Map<string, number>();
  for (const item of items) {
    const k = key(item);
    if (k) counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, top)
    .map(([label, value]) => ({ label, value }));
}

export const OPEN_ALERT = new Set(["new", "acknowledged", "in_progress"]);
export const OPEN_INCIDENT = new Set(["open", "investigating", "contained", "mitigated"]);

export function avgLast(points: { value: number }[], days = 7): number {
  const tail = points.slice(-days);
  return tail.length ? tail.reduce((s, p) => s + p.value, 0) / tail.length : 0;
}
