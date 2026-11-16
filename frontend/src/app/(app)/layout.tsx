import Link from "next/link";
import type { ReactNode } from "react";

import { logout } from "@/app/actions/auth";
import { SandboxBanner } from "@/components/sandbox-banner";
import { PortalFrame } from "@/components/shell/portal-frame";
import { TenantSwitcher, type TenantOption } from "@/components/shell/tenant-switcher";
import { visibleAdminNav } from "@/lib/nav";
import { PORTALS } from "@/lib/portals";
import { getMe } from "@/lib/server/api";

export default async function AppLayout({ children }: { children: ReactNode }) {
  const me = await getMe();
  const allowed = new Set(me.portals);
  if (me.is_platform_admin) allowed.add("admin");
  const portals = PORTALS.filter((p) => allowed.has(p.id));

  const options: TenantOption[] = [];
  for (const t of me.tenants) {
    options.push({
      value: `${t.id}:tenant`,
      label: t.access === "delegated" ? `${t.name} (via MSP)` : t.name,
    });
    // MSP members may open the read-only "All customers" view (ADR-0016).
    if (t.kind === "msp" && t.access === "member") {
      options.push({ value: `${t.id}:aggregate`, label: `${t.name}: All customers (read-only)` });
    }
  }
  const current = me.active_tenant_id ? `${me.active_tenant_id}:${me.mode === "aggregate" ? "aggregate" : "tenant"}` : "";
  const adminNav = visibleAdminNav(me.permissions, me.active_tenant_kind ?? null, me.is_platform_admin);

  return (
    <>
      <SandboxBanner />
      <header className="border-border bg-surface flex flex-wrap items-center gap-x-6 gap-y-2 border-b px-4 py-2">
        <Link href="/" className="text-sm font-semibold tracking-tight">
          NOC &amp; SOC Platform
        </Link>
        <nav aria-label="Portals" className="flex gap-1">
          {portals.map((p) => (
            <Link key={p.id} href={p.href} className="btn btn-ghost px-2.5 py-1">
              {p.name}
            </Link>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-3">
          {me.mode === "aggregate" && (
            <span className="bg-accent-command/15 text-accent-command rounded px-2 py-0.5 text-xs font-medium">
              All customers · read-only
            </span>
          )}
          {me.via_msp_tenant_id && (
            <span className="bg-accent-soc/15 text-accent-soc rounded px-2 py-0.5 text-xs font-medium">
              Delegated access
            </span>
          )}
          <TenantSwitcher options={options} current={current} />
          <span className="text-muted hidden text-xs sm:inline">{me.email}</span>
          <form action={logout}>
            <button type="submit" className="btn btn-ghost px-2 py-1 text-xs">
              Sign out
            </button>
          </form>
        </div>
      </header>
      <PortalFrame adminNav={adminNav}>{children}</PortalFrame>
    </>
  );
}
