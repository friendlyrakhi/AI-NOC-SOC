"use client";

import Link from "next/link";
import { useEffect, useId, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";

import { formatDay, formatHour } from "@/lib/format";

/**
 * Charts follow the dataviz method: validated categorical slots in fixed order, 2px lines,
 * hairline grid, one y-axis, legend for >= 2 series plus end labels (<= 4), crosshair
 * tooltip (pointer and keyboard), and a table view for every chart.
 */
export type Slot = 1 | 2 | 3 | 4 | 5 | 6;
const color = (slot: Slot) => `var(--series-${slot})`;

export type ValueFormat = "int" | "decimal" | "percent" | "minutes";

export function fmt(value: number, format: ValueFormat = "int"): string {
  switch (format) {
    case "percent":
      return `${value.toFixed(1)}%`;
    case "minutes":
      return value >= 60 ? `${(value / 60).toFixed(1)} h` : `${Math.round(value)} min`;
    case "decimal":
      return value.toFixed(1);
    default:
      return Math.round(value).toLocaleString("en-GB");
  }
}

function niceTicks(min: number, max: number, count = 4): number[] {
  const span = max - min || 1;
  const raw = span / count;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => span / s <= count) ?? raw;
  const start = Math.floor(min / step) * step;
  const ticks: number[] = [];
  for (let v = start; v <= max + step * 0.001; v += step) ticks.push(Number(v.toFixed(6)));
  return ticks;
}

function useWidth<T extends HTMLElement>(fallback = 640) {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(fallback);
  useEffect(() => {
    if (!ref.current || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(([entry]) => setWidth(Math.max(240, Math.floor(entry.contentRect.width))));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, width] as const;
}

export interface Series {
  name: string;
  slot: Slot;
  points: { date: string; value: number }[];
}

export function Legend({ items }: { items: { name: string; slot: Slot }[] }) {
  return (
    <ul className="text-muted flex flex-wrap gap-x-4 gap-y-1 text-xs" aria-label="Legend">
      {items.map((s) => (
        <li key={s.name} className="flex items-center gap-1.5">
          <span aria-hidden="true" className="inline-block h-0.5 w-3 rounded" style={{ background: color(s.slot), height: 3 }} />
          <span className="text-foreground">{s.name}</span>
        </li>
      ))}
    </ul>
  );
}

function toCsv(series: Series[]): string {
  const head = ["date", ...series.map((s) => s.name)].join(",");
  const rows = series[0]?.points.map((p, i) => [p.date, ...series.map((s) => s.points[i]?.value ?? "")].join(",")) ?? [];
  return [head, ...rows].join("\n");
}

function DataTableView({ series, format, xLabel }: { series: Series[]; format: ValueFormat; xLabel: (d: string) => string }) {
  return (
    <details className="mt-2 text-xs">
      <summary className="text-muted hover:text-foreground cursor-pointer">View data as table</summary>
      <div className="mt-2 max-h-64 overflow-auto">
        <table className="w-full text-left">
          <thead className="text-muted">
            <tr>
              <th scope="col" className="py-1 pr-3 font-medium">
                Time
              </th>
              {series.map((s) => (
                <th key={s.name} scope="col" className="py-1 pr-3 text-right font-medium">
                  {s.name}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="tabular-nums">
            {series[0]?.points.map((p, i) => (
              <tr key={p.date} className="border-border border-t">
                <td className="py-1 pr-3">{xLabel(p.date)}</td>
                {series.map((s) => (
                  <td key={s.name} className="py-1 pr-3 text-right">
                    {fmt(s.points[i]?.value ?? 0, format)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

export function TimeSeriesChart({
  title,
  series,
  format = "int",
  height = 200,
  yMin,
  yMax,
  granularity = "day",
  exportName,
}: {
  title: string;
  series: Series[];
  format?: ValueFormat;
  height?: number;
  yMin?: number;
  yMax?: number;
  granularity?: "day" | "hour";
  /** Shows a CSV download (file name gets a DEMO suffix). */
  exportName?: string;
}) {
  const xLabel = granularity === "hour" ? formatHour : formatDay;
  const [wrap, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const titleId = useId();
  const n = series[0]?.points.length ?? 0;
  const labelled = series.length >= 2 && series.length <= 4;
  const pad = { l: 44, r: labelled ? 92 : 14, t: 10, b: 24 };
  const w = width;
  const h = height;
  const values = series.flatMap((s) => s.points.map((p) => p.value));
  const lo = yMin ?? Math.min(0, ...values);
  const hiRaw = yMax ?? Math.max(...values, 1);
  const ticks = niceTicks(lo, hiRaw);
  const hi = Math.max(hiRaw, ticks[ticks.length - 1]);
  const x = (i: number) => pad.l + (n <= 1 ? 0 : (i / (n - 1)) * (w - pad.l - pad.r));
  const y = (v: number) => pad.t + (1 - (v - lo) / (hi - lo || 1)) * (h - pad.t - pad.b);

  if (n === 0) return <p className="text-muted text-sm">No data in this scope.</p>;

  const xTicks = [0, Math.floor((n - 1) / 3), Math.floor((2 * (n - 1)) / 3), n - 1];

  // End labels, nudged apart so they never collide.
  const ends = series
    .map((s) => ({ s, y: y(s.points[n - 1].value) }))
    .sort((a, b) => a.y - b.y);
  for (let i = 1; i < ends.length; i++) if (ends[i].y - ends[i - 1].y < 13) ends[i].y = ends[i - 1].y + 13;

  function onMove(e: PointerEvent<SVGSVGElement>) {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * w;
    const i = Math.round(((px - pad.l) / (w - pad.l - pad.r)) * (n - 1));
    setHover(Math.max(0, Math.min(n - 1, i)));
  }

  function onKey(e: KeyboardEvent<SVGSVGElement>) {
    if (e.key === "ArrowRight") setHover((v) => Math.min(n - 1, (v ?? -1) + 1));
    else if (e.key === "ArrowLeft") setHover((v) => Math.max(0, (v ?? n) - 1));
    else if (e.key === "Escape") setHover(null);
    else return;
    e.preventDefault();
  }

  const tipLeft = hover !== null ? Math.min(x(hover) + 12, w - 170) : 0;

  return (
    <figure className="m-0">
      <figcaption id={titleId} className="sr-only">
        {title}
      </figcaption>
      {series.length >= 2 && (
        <div className="mb-2">
          <Legend items={series} />
        </div>
      )}
      <div ref={wrap} className="relative w-full">
        <svg
          role="img"
          aria-labelledby={titleId}
          aria-describedby={`${titleId}-hint`}
          tabIndex={0}
          width={w}
          height={h}
          viewBox={`0 0 ${w} ${h}`}
          onPointerMove={onMove}
          onPointerLeave={() => setHover(null)}
          onKeyDown={onKey}
          onBlur={() => setHover(null)}
          className="focus-visible:ring-primary/50 block rounded outline-none focus-visible:ring-2"
        >
          {ticks.map((t) => (
            <g key={t}>
              <line x1={pad.l} x2={w - pad.r} y1={y(t)} y2={y(t)} stroke="var(--grid)" strokeWidth={1} />
              <text x={pad.l - 6} y={y(t)} textAnchor="end" dominantBaseline="middle" fontSize={10} fill="var(--muted)" className="tabular-nums">
                {fmt(t, format)}
              </text>
            </g>
          ))}
          <line x1={pad.l} x2={w - pad.r} y1={y(lo)} y2={y(lo)} stroke="var(--axis)" strokeWidth={1} />
          {xTicks.map((i, k) => (
            <text
              key={i}
              x={x(i)}
              y={h - 6}
              // Edge labels anchor inward so they are never clipped.
              textAnchor={k === 0 ? "start" : k === xTicks.length - 1 ? "end" : "middle"}
              fontSize={10}
              fill="var(--muted)"
            >
              {xLabel(series[0].points[i].date)}
            </text>
          ))}
          {series.map((s) => (
            <path
              key={s.name}
              d={s.points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join("")}
              fill="none"
              stroke={color(s.slot)}
              strokeWidth={2}
              strokeLinejoin="round"
              strokeLinecap="round"
            />
          ))}
          {labelled &&
            ends.map(({ s, y: ly }) => (
              <text key={s.name} x={w - pad.r + 8} y={ly} dominantBaseline="middle" fontSize={11} fill="var(--foreground)">
                {s.name}
              </text>
            ))}
          {hover !== null && (
            <g>
              <line x1={x(hover)} x2={x(hover)} y1={pad.t} y2={h - pad.b} stroke="var(--muted)" strokeWidth={1} />
              {series.map((s) => (
                <circle
                  key={s.name}
                  cx={x(hover)}
                  cy={y(s.points[hover].value)}
                  r={4}
                  fill={color(s.slot)}
                  stroke="var(--surface)"
                  strokeWidth={2}
                />
              ))}
            </g>
          )}
        </svg>
        {hover !== null && (
          <div
            role="status"
            className="bg-background border-border pointer-events-none absolute top-1 rounded-md border px-2.5 py-1.5 text-xs shadow-lg"
            style={{ left: tipLeft }}
          >
            <p className="text-muted mb-0.5">{xLabel(series[0].points[hover].date)}</p>
            {series.map((s) => (
              <p key={s.name} className="flex items-center gap-1.5">
                <span aria-hidden="true" className="inline-block h-2 w-2 rounded-full" style={{ background: color(s.slot) }} />
                <span className="text-muted">{s.name}</span>
                <span className="ml-auto pl-3 font-medium tabular-nums">{fmt(s.points[hover].value, format)}</span>
              </p>
            ))}
          </div>
        )}
      </div>
      <p id={`${titleId}-hint`} className="sr-only">
        Use the left and right arrow keys to read values.
      </p>
      <div className="flex items-start justify-between gap-3">
        <DataTableView series={series} format={format} xLabel={xLabel} />
        {exportName && (
          <button
            type="button"
            className="text-muted hover:text-foreground mt-2 text-xs underline"
            onClick={() => {
              const a = document.createElement("a");
              a.href = URL.createObjectURL(new Blob([toCsv(series)], { type: "text/csv" }));
              a.download = `${exportName}-DEMO.csv`;
              a.click();
              URL.revokeObjectURL(a.href);
            }}
          >
            Download CSV
          </button>
        )}
      </div>
    </figure>
  );
}

/** Ranked values: a list with thin bars (a table that also shows magnitude). */
export function BarList({
  items,
  format = "int",
  label,
}: {
  items: { label: string; value: number; href?: string; note?: string }[];
  format?: ValueFormat;
  label: string;
}) {
  const max = Math.max(...items.map((i) => i.value), 1);
  if (items.length === 0) return <p className="text-muted text-sm">No data in this scope.</p>;
  return (
    <ol aria-label={label} className="space-y-2">
      {items.map((item) => {
        const name = item.href ? (
          <Link href={item.href} className="hover:underline">
            {item.label}
          </Link>
        ) : (
          item.label
        );
        return (
          <li key={item.label} className="group" title={`${item.label}: ${fmt(item.value, format)}`}>
            <div className="flex items-baseline justify-between gap-3 text-xs">
              <span className="truncate">
                {name}
                {item.note && <span className="text-muted ml-1">{item.note}</span>}
              </span>
              <span className="tabular-nums">{fmt(item.value, format)}</span>
            </div>
            <div aria-hidden="true" className="bg-border/40 mt-1 h-1.5 overflow-hidden rounded">
              <div
                className="h-full rounded transition-opacity group-hover:opacity-80"
                style={{ width: `${(item.value / max) * 100}%`, background: "var(--series-1)" }}
              />
            </div>
          </li>
        );
      })}
    </ol>
  );
}

/** Part-to-whole (<= 6 parts): a segmented bar with 2px gaps and a counted legend. */
export function SegmentBar({
  parts,
  label,
}: {
  parts: { label: string; value: number; color: string }[];
  label: string;
}) {
  const total = parts.reduce((s, p) => s + p.value, 0);
  return (
    <div>
      <div role="img" aria-label={`${label}: ${parts.map((p) => `${p.label} ${p.value}`).join(", ")}`} className="flex h-3 gap-0.5">
        {total === 0 ? (
          <div className="bg-border/40 h-full w-full rounded" />
        ) : (
          parts
            .filter((p) => p.value > 0)
            .map((p) => (
              <div
                key={p.label}
                title={`${p.label}: ${p.value}`}
                className="h-full first:rounded-l last:rounded-r"
                style={{ width: `${(p.value / total) * 100}%`, background: p.color }}
              />
            ))
        )}
      </div>
      <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {parts.map((p) => (
          <li key={p.label} className="flex items-center gap-1.5">
            <span aria-hidden="true" className="inline-block h-2 w-2 rounded-sm" style={{ background: p.color }} />
            <span className="text-muted">{p.label}</span>
            <span className="font-medium tabular-nums">{p.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Decorative trend line for stat tiles (the tile states the value). */
export function Sparkline({ points, slot = 1 }: { points: { value: number }[]; slot?: Slot }) {
  if (points.length < 2) return null;
  const vals = points.map((p) => p.value);
  const lo = Math.min(...vals);
  const hi = Math.max(...vals);
  const d = vals
    .map((v, i) => `${i ? "L" : "M"}${((i / (vals.length - 1)) * 100).toFixed(1)},${(22 - ((v - lo) / (hi - lo || 1)) * 20).toFixed(1)}`)
    .join("");
  return (
    <svg aria-hidden="true" viewBox="0 0 100 24" preserveAspectRatio="none" className="h-6 w-full">
      <path d={d} fill="none" stroke={color(slot)} strokeWidth={2} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
