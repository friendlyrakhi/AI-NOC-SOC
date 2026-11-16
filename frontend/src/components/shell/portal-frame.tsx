"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState, type ReactNode } from "react";

import { portalOf, type NavSection, type PortalKey } from "@/lib/nav";

const ACCENT: Record<PortalKey, string> = {
  command: "border-accent-command",
  noc: "border-accent-noc",
  soc: "border-accent-soc",
  ops: "border-accent-admin",
  admin: "border-accent-admin",
};

function Sections({ sections, accent, onNavigate }: { sections: NavSection[]; accent: string; onNavigate?: () => void }) {
  const pathname = usePathname();
  // The most specific matching href is the current page.
  const all = sections.flatMap((s) => s.items.map((i) => i.href));
  const current = all
    .filter((h) => pathname === h || pathname.startsWith(`${h}/`))
    .sort((a, b) => b.length - a.length)[0];
  return (
    <div className="space-y-5">
      {sections.map((section) => (
        <div key={section.title}>
          <p className="text-muted mb-1.5 px-3 text-[11px] font-semibold tracking-wider uppercase">{section.title}</p>
          <ul className="space-y-0.5">
            {section.items.map((item) => {
              const active = item.href === current;
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={`block rounded-md border-l-2 px-3 py-1.5 text-sm ${
                      active ? `bg-border/40 text-foreground ${accent}` : "text-muted hover:text-foreground border-transparent"
                    }`}
                  >
                    {item.label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </div>
  );
}

/** Side navigation for the portal in the URL, plus a mobile drawer. */
export function PortalFrame({ nav, children }: { nav: Record<PortalKey, NavSection[]>; children: ReactNode }) {
  const pathname = usePathname();
  const portal = portalOf(pathname);
  const sections = portal ? nav[portal] : [];
  const accent = portal ? ACCENT[portal] : "";
  const [open, setOpen] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    if (open) dialog.current?.showModal();
    else dialog.current?.close();
  }, [open]);

  return (
    <div className="flex flex-1">
      {sections.length > 0 && (
        <aside aria-label="Section navigation" className="border-border hidden w-60 shrink-0 border-r p-3 lg:block">
          <nav aria-label="Section">
            <Sections sections={sections} accent={accent} />
          </nav>
        </aside>
      )}
      <div className="min-w-0 flex-1">
        {sections.length > 0 && (
          <div className="border-border border-b px-4 py-2 lg:hidden">
            <button type="button" className="btn btn-ghost border-border border" aria-haspopup="dialog" onClick={() => setOpen(true)}>
              ☰ Menu
            </button>
          </div>
        )}
        <main id="main" className="px-4 py-6 md:px-8">
          {children}
        </main>
      </div>
      <dialog
        ref={dialog}
        aria-label="Navigation"
        onClose={() => setOpen(false)}
        className="bg-surface text-foreground border-border m-0 h-full max-h-none w-72 max-w-[85vw] border-r p-3"
      >
        <div className="mb-3 flex justify-end">
          <button type="button" className="btn btn-ghost" onClick={() => setOpen(false)} aria-label="Close navigation">
            ✕
          </button>
        </div>
        <nav aria-label="Section (mobile)">
          <Sections sections={sections} accent={accent} onNavigate={() => setOpen(false)} />
        </nav>
      </dialog>
    </div>
  );
}
