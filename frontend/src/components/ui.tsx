import type { ReactNode } from "react";

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="text-muted mt-1 max-w-3xl text-sm">{description}</p>}
      </div>
      {actions}
    </div>
  );
}

export function Card({ title, children, className }: { title?: string; children: ReactNode; className?: string }) {
  return (
    <section className={`bg-surface border-border rounded-lg border p-5 ${className ?? ""}`}>
      {title && <h2 className="mb-3 text-sm font-semibold">{title}</h2>}
      {children}
    </section>
  );
}

const TONES = {
  neutral: "bg-border/60 text-foreground",
  success: "bg-success/15 text-success",
  warning: "bg-warning/15 text-warning",
  danger: "bg-danger/15 text-danger",
  info: "bg-accent-soc/15 text-accent-soc",
} as const;

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: keyof typeof TONES }) {
  return <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${TONES[tone]}`}>{children}</span>;
}

export function Table({ head, children, empty }: { head: string[]; children: ReactNode; empty?: boolean }) {
  return (
    <div className="border-border overflow-x-auto rounded-lg border">
      <table className="w-full text-left text-sm">
        <thead className="bg-surface text-muted text-xs uppercase">
          <tr>
            {head.map((h) => (
              <th key={h} scope="col" className="px-3 py-2 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-border divide-y">
          {empty ? (
            <tr>
              <td colSpan={head.length} className="text-muted px-3 py-6 text-center">
                Nothing here yet.
              </td>
            </tr>
          ) : (
            children
          )}
        </tbody>
      </table>
    </div>
  );
}

export function Td({ children, className }: { children: ReactNode; className?: string }) {
  return <td className={`px-3 py-2 align-top ${className ?? ""}`}>{children}</td>;
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className="text-muted text-xs">{label}</span>
      <div className="mt-1">{children}</div>
      {hint && <span className="text-muted mt-1 block text-xs">{hint}</span>}
    </label>
  );
}

export function NotAvailable({ what }: { what: string }) {
  return (
    <Card>
      <p className="text-muted text-sm">{what} is not available with your current role or tenant.</p>
    </Card>
  );
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }) + " UTC";
}
