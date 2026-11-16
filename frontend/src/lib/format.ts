/** Deterministic formatting (identical on server and client; UTC). */

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function formatTime(value: string): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${hh}:${mm} UTC`;
}

export function formatDay(value: string): string {
  const d = new Date(value);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`;
}

export function formatHour(value: string): string {
  const d = new Date(value);
  return `${String(d.getUTCHours()).padStart(2, "0")}:00`;
}

export function relativeTime(value: string, now: number = Date.now()): string {
  const diff = now - Date.parse(value);
  const future = diff < 0;
  const s = Math.abs(diff) / 1000;
  const unit =
    s < 60 ? "just now"
    : s < 3600 ? `${Math.floor(s / 60)} min`
    : s < 86400 ? `${Math.floor(s / 3600)} h`
    : `${Math.floor(s / 86400)} d`;
  if (unit === "just now") return unit;
  return future ? `in ${unit}` : `${unit} ago`;
}

export function minutes(value: number): string {
  if (value < 60) return `${Math.round(value)} min`;
  const h = Math.floor(value / 60);
  const m = Math.round(value % 60);
  return m ? `${h} h ${m} min` : `${h} h`;
}

/** Percent change of the last 7 points vs the 7 before. */
export function weekDelta(points: { value: number }[]): number {
  if (points.length < 14) return 0;
  const sum = (a: { value: number }[]) => a.reduce((s, p) => s + p.value, 0);
  const last = sum(points.slice(-7));
  const prev = sum(points.slice(-14, -7));
  return prev === 0 ? 0 : ((last - prev) / prev) * 100;
}
