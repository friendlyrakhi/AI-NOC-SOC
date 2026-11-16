"use client";

import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

/** WAI-ARIA tabs: arrow keys move between tabs, Home/End jump, panels are labelled. */
export function Tabs({ tabs, initial = 0 }: { tabs: { label: string; content: ReactNode; count?: number }[]; initial?: number }) {
  const [active, setActive] = useState(initial);
  const id = useId();
  const refs = useRef<(HTMLButtonElement | null)[]>([]);

  function onKey(e: KeyboardEvent<HTMLDivElement>) {
    const last = tabs.length - 1;
    const next =
      e.key === "ArrowRight" ? (active === last ? 0 : active + 1)
      : e.key === "ArrowLeft" ? (active === 0 ? last : active - 1)
      : e.key === "Home" ? 0
      : e.key === "End" ? last
      : null;
    if (next === null) return;
    e.preventDefault();
    setActive(next);
    refs.current[next]?.focus();
  }

  return (
    <div>
      <div role="tablist" aria-orientation="horizontal" onKeyDown={onKey} className="border-border mb-4 flex flex-wrap gap-1 border-b">
        {tabs.map((t, i) => (
          <button
            key={t.label}
            ref={(el) => {
              refs.current[i] = el;
            }}
            role="tab"
            type="button"
            id={`${id}-tab-${i}`}
            aria-selected={i === active}
            aria-controls={`${id}-panel-${i}`}
            tabIndex={i === active ? 0 : -1}
            onClick={() => setActive(i)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm ${
              i === active ? "border-primary text-foreground font-medium" : "text-muted hover:text-foreground border-transparent"
            }`}
          >
            {t.label}
            {t.count !== undefined && <span className="text-muted ml-1.5 text-xs tabular-nums">{t.count}</span>}
          </button>
        ))}
      </div>
      {tabs.map((t, i) => (
        <div
          key={t.label}
          role="tabpanel"
          id={`${id}-panel-${i}`}
          aria-labelledby={`${id}-tab-${i}`}
          hidden={i !== active}
          tabIndex={0}
          className="outline-none"
        >
          {t.content}
        </div>
      ))}
    </div>
  );
}
