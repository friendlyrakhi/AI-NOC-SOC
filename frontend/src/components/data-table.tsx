"use client";

import Link from "next/link";
import { useId, useMemo, useRef, useState } from "react";

import { HealthBadge, SeverityBadge, StateBadge } from "@/components/indicators";
import type { Health, Severity } from "@/lib/demo/types";
import { formatTime, relativeTime } from "@/lib/format";

/**
 * Generic, accessible data table. Column specs are plain data so server components can
 * pass them: cells render by `type`. Supports search, per-column filters, sortable
 * headers (aria-sort), pagination, CSV export and drill-down (link or details dialog).
 */
export type CellType =
  | "text" | "mono" | "severity" | "health" | "state" | "time" | "relative"
  | "number" | "percent" | "score" | "tags" | "bool" | "link";

export interface ColumnSpec {
  key: string;
  header: string;
  type?: CellType;
  /** Show a filter select built from this column's distinct values. */
  filter?: boolean;
  sortable?: boolean;
  /** For "link": row field holding the href. */
  hrefKey?: string;
  /** Hide on narrow screens. */
  hideOnMobile?: boolean;
  align?: "right";
}

export type Row = Record<string, unknown> & {
  _id: string;
  /** Whole-row drill-down target. */
  _href?: string;
  /** Shown in the details dialog when there is no `_href`. */
  _details?: Record<string, string | number | boolean | null>;
};

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const HEALTH_ORDER: Record<string, number> = { down: 0, degraded: 1, maintenance: 2, healthy: 3 };

function sortValue(type: CellType | undefined, v: unknown): string | number {
  if (v === null || v === undefined) return "";
  if (type === "severity") return SEV_ORDER[String(v)] ?? 9;
  if (type === "health") return HEALTH_ORDER[String(v)] ?? 9;
  if (typeof v === "number") return v;
  if (typeof v === "boolean") return v ? 1 : 0;
  if (Array.isArray(v)) return v.join(",");
  return String(v).toLowerCase();
}

function Cell({ col, row }: { col: ColumnSpec; row: Row }) {
  const v = row[col.key];
  if (v === null || v === undefined || v === "") return <span className="text-muted">—</span>;
  switch (col.type) {
    case "severity":
      return <SeverityBadge severity={v as Severity} />;
    case "health":
      return <HealthBadge status={v as Health} />;
    case "state":
      return <StateBadge value={String(v)} />;
    case "mono":
      return <span className="font-mono text-xs break-all">{String(v)}</span>;
    case "time":
      return <span className="text-muted text-xs whitespace-nowrap tabular-nums">{formatTime(String(v))}</span>;
    case "relative":
      return (
        <time dateTime={String(v)} title={formatTime(String(v))} className="text-muted text-xs whitespace-nowrap" suppressHydrationWarning>
          {relativeTime(String(v))}
        </time>
      );
    case "number":
      return <span className="tabular-nums">{Number(v).toLocaleString("en-GB")}</span>;
    case "percent":
      return <span className="tabular-nums">{Number(v).toFixed(Number(v) >= 99 ? 2 : 1)}%</span>;
    case "score": {
      const n = Number(v);
      return (
        <span className="inline-flex items-center gap-2">
          <span className="tabular-nums w-7 text-right">{n}</span>
          <span aria-hidden="true" className="bg-border/60 h-1.5 w-16 overflow-hidden rounded">
            <span className="block h-full rounded" style={{ width: `${Math.min(100, n)}%`, background: "var(--series-1)" }} />
          </span>
        </span>
      );
    }
    case "tags":
      return (
        <span className="flex flex-wrap gap-1">
          {(v as string[]).map((t) => (
            <span key={t} className="bg-border/50 rounded px-1.5 py-px text-[11px]">
              {t}
            </span>
          ))}
        </span>
      );
    case "bool":
      return <span>{v ? "Yes" : "No"}</span>;
    case "link": {
      const href = col.hrefKey ? (row[col.hrefKey] as string | undefined) : row._href;
      return href ? (
        <Link href={href} className="text-primary hover:underline" onClick={(e) => e.stopPropagation()}>
          {String(v)}
        </Link>
      ) : (
        <span>{String(v)}</span>
      );
    }
    default:
      return <span>{String(v)}</span>;
  }
}

export function toCsv(columns: ColumnSpec[], rows: Row[]): string {
  const esc = (v: unknown) => {
    let s = Array.isArray(v) ? v.join("; ") : v === null || v === undefined ? "" : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; // spreadsheet formula injection guard (threat model T16, OWASP CSV injection)
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [columns.map((c) => esc(c.header)).join(","), ...rows.map((r) => columns.map((c) => esc(r[c.key])).join(","))].join("\n");
}

export interface DataTableProps {
  rows: Row[];
  columns: ColumnSpec[];
  /** Accessible table name. */
  caption: string;
  searchPlaceholder?: string;
  pageSize?: number;
  initialSort?: { key: string; dir: "asc" | "desc" };
  exportName?: string;
  /** Labels the CSV file: generated DEMO data, or real platform data from sandbox connectors. */
  dataSource?: "demo" | "sandbox";
  emptyText?: string;
}

export function DataTable({
  rows,
  columns,
  caption,
  searchPlaceholder = "Search…",
  pageSize: initialPageSize = 25,
  initialSort,
  exportName,
  dataSource = "demo",
  emptyText = "No matching records.",
}: DataTableProps) {
  const id = useId();
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [sort, setSort] = useState(initialSort ?? null);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(initialPageSize);
  const [selected, setSelected] = useState<Row | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);

  const filterCols = columns.filter((c) => c.filter);
  const options = useMemo(
    () =>
      Object.fromEntries(
        filterCols.map((c) => [
          c.key,
          [...new Set(rows.flatMap((r) => (Array.isArray(r[c.key]) ? (r[c.key] as string[]) : [String(r[c.key] ?? "")])))]
            .filter(Boolean)
            .sort((a, b) => (c.type === "severity" ? (SEV_ORDER[a] ?? 9) - (SEV_ORDER[b] ?? 9) : a.localeCompare(b))),
        ]),
      ),
    [rows, filterCols],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    let out = rows.filter((r) => {
      for (const [key, value] of Object.entries(filters)) {
        if (!value) continue;
        const cell = r[key];
        if (Array.isArray(cell) ? !cell.includes(value) : String(cell ?? "") !== value) return false;
      }
      if (!q) return true;
      return columns.some((c) => {
        const cell = r[c.key];
        return (Array.isArray(cell) ? cell.join(" ") : String(cell ?? "")).toLowerCase().includes(q);
      });
    });
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      out = [...out].sort((a, b) => {
        const av = sortValue(col?.type, a[sort.key]);
        const bv = sortValue(col?.type, b[sort.key]);
        const cmp = av < bv ? -1 : av > bv ? 1 : 0;
        return sort.dir === "asc" ? cmp : -cmp;
      });
    }
    return out;
  }, [rows, columns, query, filters, sort]);

  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const current = Math.min(page, pages - 1);
  const visible = filtered.slice(current * pageSize, current * pageSize + pageSize);

  function toggleSort(key: string) {
    setPage(0);
    setSort((s) => (s?.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }));
  }

  function openRow(row: Row) {
    if (row._details) {
      setSelected(row);
      dialog.current?.showModal();
    }
  }

  function download() {
    const blob = new Blob([toCsv(columns, filtered)], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${exportName ?? "export"}-${dataSource === "sandbox" ? "SANDBOX" : "DEMO"}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-2">
        <label className="min-w-48 flex-1">
          <span className="sr-only">Search {caption}</span>
          <input
            type="search"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setPage(0);
            }}
            placeholder={searchPlaceholder}
            className="input w-full"
          />
        </label>
        {filterCols.map((c) => (
          <label key={c.key} className="text-xs">
            <span className="text-muted mb-0.5 block">{c.header}</span>
            <select
              value={filters[c.key] ?? ""}
              onChange={(e) => {
                setFilters((f) => ({ ...f, [c.key]: e.target.value }));
                setPage(0);
              }}
              className="input py-1 capitalize"
            >
              <option value="">All</option>
              {options[c.key]?.map((o) => (
                <option key={o} value={o}>
                  {o.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </label>
        ))}
        {exportName && (
          <button type="button" onClick={download} className="btn btn-ghost border-border border">
            Export CSV
          </button>
        )}
      </div>

      <p id={`${id}-count`} role="status" className="text-muted text-xs">
        {filtered.length.toLocaleString("en-GB")} of {rows.length.toLocaleString("en-GB")} records
      </p>

      <div className="border-border overflow-x-auto rounded-lg border">
        <table className="w-full text-left text-sm" aria-describedby={`${id}-count`}>
          <caption className="sr-only">{caption}</caption>
          <thead className="bg-surface text-muted text-xs">
            <tr>
              {columns.map((c) => {
                const active = sort?.key === c.key;
                const sortable = c.sortable !== false;
                return (
                  <th
                    key={c.key}
                    scope="col"
                    aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : undefined}
                    className={`px-3 py-2 font-medium whitespace-nowrap ${c.hideOnMobile ? "hidden md:table-cell" : ""} ${c.align === "right" ? "text-right" : ""}`}
                  >
                    {sortable ? (
                      <button type="button" onClick={() => toggleSort(c.key)} className="hover:text-foreground inline-flex items-center gap-1">
                        {c.header}
                        <span aria-hidden="true" className={active ? "text-foreground" : "opacity-30"}>
                          {active && sort.dir === "desc" ? "▼" : "▲"}
                        </span>
                      </button>
                    ) : (
                      c.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody className="divide-border divide-y">
            {visible.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="text-muted px-3 py-8 text-center">
                  {emptyText}
                </td>
              </tr>
            ) : (
              visible.map((row) => (
                <tr
                  key={row._id}
                  onClick={row._details ? () => openRow(row) : undefined}
                  className={row._details || row._href ? "hover:bg-border/25 cursor-pointer" : undefined}
                >
                  {columns.map((c, i) => (
                    <td
                      key={c.key}
                      className={`px-3 py-2 align-top ${c.hideOnMobile ? "hidden md:table-cell" : ""} ${c.align === "right" ? "text-right" : ""}`}
                    >
                      {i === 0 && row._href && c.type !== "link" ? (
                        <Link href={row._href} className="text-primary hover:underline">
                          <Cell col={c} row={row} />
                        </Link>
                      ) : i === 0 && row._details ? (
                        <button type="button" className="text-primary text-left hover:underline" onClick={(e) => (e.stopPropagation(), openRow(row))}>
                          <Cell col={c} row={row} />
                        </button>
                      ) : (
                        <Cell col={c} row={row} />
                      )}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <nav aria-label={`${caption} pages`} className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <label className="text-muted flex items-center gap-2">
          Rows per page
          <select
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setPage(0);
            }}
            className="input py-0.5"
          >
            {[10, 25, 50, 100].map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
        <div className="flex items-center gap-2">
          <button type="button" className="btn btn-ghost" onClick={() => setPage(current - 1)} disabled={current === 0}>
            ← Previous
          </button>
          <span className="text-muted tabular-nums">
            Page {current + 1} of {pages}
          </span>
          <button type="button" className="btn btn-ghost" onClick={() => setPage(current + 1)} disabled={current >= pages - 1}>
            Next →
          </button>
        </div>
      </nav>

      <dialog
        ref={dialog}
        aria-labelledby={`${id}-dialog-title`}
        onClose={() => setSelected(null)}
        className="bg-surface text-foreground border-border m-auto w-[min(40rem,92vw)] rounded-lg border p-0"
      >
        {selected && (
          <div className="p-5">
            <div className="mb-4 flex items-start justify-between gap-4">
              <h2 id={`${id}-dialog-title`} className="text-base font-semibold">
                {String(selected[columns[0].key] ?? "Details")}
              </h2>
              <button type="button" onClick={() => dialog.current?.close()} className="btn btn-ghost" aria-label="Close details">
                ✕
              </button>
            </div>
            <dl className="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-2 text-sm">
              {Object.entries(selected._details ?? {}).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-muted">{k}</dt>
                  <dd className="break-words whitespace-pre-wrap">{v === null ? "—" : String(v)}</dd>
                </div>
              ))}
            </dl>
          </div>
        )}
      </dialog>
    </div>
  );
}
