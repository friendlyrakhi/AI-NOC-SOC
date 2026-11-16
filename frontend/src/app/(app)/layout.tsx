import Link from "next/link";
import type { ReactNode } from "react";

import { logout } from "@/app/actions/auth";
import { SandboxBanner } from "@/components/sandbox-banner";
import { PortalFrame } from "@/components/shell/portal-frame";
import { TenantSwitcher, type TenantOption } from "@/components/shell/tenant-switcher";
import { buildNav } from "@/lib/nav";
import { getMe } from "@/lib/server/api";

const HEADER_LINKS = [
  { label: "Command Center", href: "/command", portal: "command" },
  { label: "AI NOC", href: "/noc", portal: "noc" },
  { label: "AI SOC", href: "/soc", portal: "soc" },
] as const;

export default async function AppLayout({ children }: { children: ReactNode }) {
  const me = await getMe();
  const nav = buildNav(me.permissions, me.active_tenant_kind ?? null, me.is_platform_admin);

  const options: TenantOption[] = [];
  for (const t of me.tenants) {
    options.push({ value: `${t.id}:tenant`, label: t.access === "delegated" ? `${t.name} (via MSP)` : t.name });
    if (t.kind === "msp" && t.access === "member") {
      options.push({ value: `${t.id}:aggregate`, label: `${t.name}: All customers (read-only)` });
    }
  }
  const current = me.active_tenant_id ? `${me.active_tenant_id}:${me.mode === "aggregate" ? "aggregate" : "tenant"}` : "";
  const links = [
    ...HEADER_LINKS.filter((l) => me.portals.includes(l.portal)),
    ...(nav.ops.length ? [{ label: "Operations", href: nav.ops[0].items[0].href }] : []),
    ...(nav.admin.length ? [{ label: "Admin", href: nav.admin[0].items[0].href }] : []),
  ];

  return (
    <>
      <a
        href="#main"
        className="bg-primary sr-only z-50 rounded px-3 py-1 text-white focus:not-sr-only focus:absolute focus:top-2 focus:left-2"
      >
        Skip to content
      </a>
      <SandboxBanner />
      <header className="border-border bg-surface flex flex-wrap items-center gap-x-5 gap-y-2 border-b px-4 py-2">
        <Link href="/" className="text-sm font-semibold tracking-tight whitespace-nowrap">
          NOC &amp; SOC Platform
        </Link>
        <nav aria-label="Portals" className="flex flex-wrap gap-1">
          {links.map((p) => (
            <Link key={p.href} href={p.href} className="btn btn-ghost px-2.5 py-1">
              {p.label}
            </Link>
          ))}
        </nav>
        {me.permissions.includes("search:read") && me.mode !== "none" && (
          <form action="/search" role="search" className="min-w-40 flex-1 md:max-w-xs">
            <label htmlFor="global-search" className="sr-only">
              Search incidents, assets, alerts and indicators
            </label>
            <input id="global-search" name="q" type="search" placeholder="Search…" className="input w-full py-1" />
          </form>
        )}
        <div className="ml-auto flex flex-wrap items-center gap-3">
          {me.mode === "aggregate" && (
            <span className="bg-accent-command/15 text-accent-command rounded px-2 py-0.5 text-xs font-medium">
              All customers · read-only
            </span>
          )}
          {me.via_msp_tenant_id && (
            <span className="bg-accent-soc/15 text-accent-soc rounded px-2 py-0.5 text-xs font-medium">Delegated access</span>
          )}
          <TenantSwitcher options={options} current={current} />
          <span className="text-muted hidden text-xs xl:inline">{me.email}</span>
          <form action={logout}>
            <button type="submit" className="btn btn-ghost px-2 py-1 text-xs">
              Sign out
            </button>
          </form>
        </div>
      </header>
      <PortalFrame nav={nav}>{children}</PortalFrame>
    </>
  );
}
