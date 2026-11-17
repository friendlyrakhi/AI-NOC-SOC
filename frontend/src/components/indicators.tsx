import Link from "next/link";
import type { ReactNode } from "react";

import type { Health, Severity } from "@/lib/demo/types";

/**
 * Status indicators. Meaning is never carried by color alone: each state has a distinct
 * shape plus a text label (dataviz status rule; WCAG 1.4.1).
 */
const SEVERITY: Record<Severity, { label: string; color: string; shape: ReactNode }> = {
  critical: {
    label: "Critical",
    color: "var(--status-critical)",
    shape: <polygon points="5,1 11,1 15,5 15,11 11,15 5,15 1,11 1,5" />,
  },
  high: { label: "High", color: "var(--status-serious)", shape: <polygon points="8,1 15,15 1,15" /> },
  medium: { label: "Medium", color: "var(--status-warning)", shape: <polygon points="8,1 15,8 8,15 1,8" /> },
  low: { label: "Low", color: "var(--muted)", shape: <circle cx="8" cy="8" r="6" fill="none" strokeWidth="2.5" stroke="currentColor" /> },
  info: { label: "Info", color: "var(--muted)", shape: <circle cx="8" cy="8" r="3.5" /> },
};

function Glyph({ color, children }: { color: string; children: ReactNode }) {
  return (
    <svg aria-hidden="true" viewBox="0 0 16 16" width="12" height="12" style={{ color, fill: color }} className="shrink-0">
      {children}
    </svg>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEVERITY[severity];
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap">
      <Glyph color={s.color}>{s.shape}</Glyph>
      {s.label}
    </span>
  );
}

const HEALTH: Record<Health, { label: string; color: string; shape: ReactNode }> = {
  healthy: { label: "Healthy", color: "var(--status-good)", shape: <path d="M3 8.5l3 3 7-7" fill="none" strokeWidth="2.5" stroke="currentColor" /> },
  degraded: { label: "Degraded", color: "var(--status-warning)", shape: <polygon points="8,1 15,8 8,15 1,8" /> },
  down: { label: "Down", color: "var(--status-critical)", shape: <polygon points="5,1 11,1 15,5 15,11 11,15 5,15 1,11 1,5" /> },
  maintenance: { label: "Maintenance", color: "var(--muted)", shape: <rect x="2" y="7" width="12" height="2.5" /> },
};

export function HealthBadge({ status }: { status: Health }) {
  const h = HEALTH[status];
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap">
      <Glyph color={h.color}>{h.shape}</Glyph>
      {h.label}
    </span>
  );
}

/** Marks anything built from generated demo data. */
export function DemoBadge() {
  return (
    <span
      title="Generated demo data. Not from a live system."
      className="border-caution/70 text-warning rounded border px-1.5 py-px text-[10px] font-bold tracking-wider"
    >
      DEMO
    </span>
  );
}

export function DemoNotice({ children }: { children?: ReactNode }) {
  return (
    <div role="note" className="border-caution/40 bg-caution/5 mb-6 flex items-start gap-3 rounded-md border px-3 py-2 text-xs">
      <DemoBadge />
      <p className="text-muted">
        {children ?? "Generated demonstration data for this tenant. No live systems are connected; actions are simulated."}
      </p>
    </div>
  );
}

/**
 * Marks data that came through the real ingestion pipeline from a *sandbox* connector:
 * real platform processing of simulated vendor data. Distinct from DEMO (generated in the UI).
 */
export function SandboxBadge() {
  return (
    <span
      title="Ingested through the platform pipeline from a sandbox connector (simulated vendor data). Not a live system."
      className="border-primary/60 text-primary rounded border px-1.5 py-px text-[10px] font-bold tracking-wider"
    >
      SANDBOX
    </span>
  );
}

export function SandboxNotice({ children }: { children?: ReactNode }) {
  return (
    <div role="note" className="border-primary/40 bg-primary/5 mb-4 flex items-start gap-3 rounded-md border px-3 py-2 text-xs">
      <SandboxBadge />
      <p className="text-muted">
        {children ??
          "Ingested by the platform from sandbox connectors: real normalization, de-duplication and storage of simulated vendor data. No live systems are connected."}
      </p>
    </div>
  );
}

export function KpiTile({
  label,
  value,
  unit,
  delta,
  goodWhen = "down",
  hint,
  href,
  children,
}: {
  label: string;
  value: string | number;
  unit?: string;
  delta?: number;
  goodWhen?: "up" | "down";
  hint?: string;
  href?: string;
  children?: ReactNode;
}) {
  const good = delta === undefined || delta === 0 ? null : (delta > 0) === (goodWhen === "up");
  const body = (
    <>
      <p className="text-muted text-xs">{label}</p>
      <p className="mt-1 text-2xl font-semibold tracking-tight">
        {value}
        {unit && <span className="text-muted ml-1 text-sm font-normal">{unit}</span>}
      </p>
      {delta !== undefined && (
        <p className="mt-0.5 text-xs">
          <span className={good === null ? "text-muted" : good ? "text-success" : "text-danger"}>
            {delta > 0 ? "▲" : delta < 0 ? "▼" : "■"} {Math.abs(delta).toFixed(Math.abs(delta) < 10 ? 1 : 0)}%
          </span>{" "}
          <span className="text-muted">vs previous 7 days</span>
        </p>
      )}
      {hint && <p className="text-muted mt-0.5 text-xs">{hint}</p>}
      {children && <div className="mt-2">{children}</div>}
    </>
  );
  const cls = "bg-surface border-border block rounded-lg border p-4";
  return href ? (
    <Link href={href} className={`${cls} hover:border-primary/60 focus-visible:ring-primary/50 outline-none focus-visible:ring-2`}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  );
}

export function SectionTitle({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-3 flex items-center justify-between gap-3">
      <h2 className="text-sm font-semibold">{children}</h2>
      {action}
    </div>
  );
}

/** Tone for categorical workflow states (not severity). */
export function StateBadge({ value }: { value: string }) {
  const label = value.replace(/_/g, " ");
  const tone =
    /^(open|new|failed|retest_failed|denied|down|awaiting_approval|pending|pending_approval|halted)$/.test(value)
      ? "border-danger/40 text-danger"
      : /^(investigating|in_progress|acknowledged|running|executing|scheduled|planned|retest|contained|draft)$/.test(value)
        ? "border-caution/60 text-warning"
        : /^(resolved|closed|mitigated|fixed|remediated|retest_passed|succeeded|approved|completed|published|reported|done)$/.test(value)
          ? "border-success/40 text-success"
          : "border-border text-muted";
  return <span className={`inline-block rounded border px-1.5 py-px text-[11px] font-medium whitespace-nowrap capitalize ${tone}`}>{label}</span>;
}
