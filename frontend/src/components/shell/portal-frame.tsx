"use client";

import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

import { SideNav } from "@/components/shell/side-nav";
import { PORTAL_NAV, type NavItem } from "@/lib/nav";

const ACCENT: Record<string, string> = {
  noc: "border-accent-noc",
  soc: "border-accent-soc",
  command: "border-accent-command",
  admin: "border-accent-admin",
};

const TITLE: Record<string, string> = { noc: "AI NOC", soc: "AI SOC", command: "Command Center", admin: "Administration" };

/** Picks the side navigation for the portal in the URL's first segment. */
export function PortalFrame({ adminNav, children }: { adminNav: NavItem[]; children: ReactNode }) {
  const portal = usePathname().split("/")[1] ?? "";
  const items = portal === "admin" ? adminNav : (PORTAL_NAV[portal as keyof typeof PORTAL_NAV] ?? null);
  return (
    <div className="flex flex-1">
      {items && (
        <aside className="border-border hidden w-56 shrink-0 border-r p-3 md:block">
          <p className={`mb-3 border-l-2 pl-3 text-xs font-semibold tracking-wider uppercase ${ACCENT[portal]}`}>
            {TITLE[portal]}
          </p>
          <SideNav items={items} accent={ACCENT[portal] ?? ""} />
        </aside>
      )}
      <main className="min-w-0 flex-1 px-4 py-6 md:px-8">{children}</main>
    </div>
  );
}
