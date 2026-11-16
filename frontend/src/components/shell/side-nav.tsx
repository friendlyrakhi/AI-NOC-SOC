"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import type { NavItem } from "@/lib/nav";

export function SideNav({ items, accent }: { items: NavItem[]; accent: string }) {
  const pathname = usePathname();
  return (
    <nav aria-label="Section" className="space-y-0.5">
      {items.map((item) => {
        if (!item.href) {
          return (
            <span
              key={item.label}
              aria-disabled="true"
              className="text-muted/70 flex items-center justify-between rounded-md px-3 py-1.5 text-sm"
            >
              {item.label}
              <span className="text-[10px] font-medium tracking-wide">{item.phase}</span>
            </span>
          );
        }
        const active = pathname === item.href;
        return (
          <Link
            key={item.href}
            href={item.href}
            aria-current={active ? "page" : undefined}
            className={`block rounded-md border-l-2 px-3 py-1.5 text-sm ${
              active ? `bg-border/40 text-foreground ${accent}` : "text-muted hover:text-foreground border-transparent"
            }`}
          >
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
