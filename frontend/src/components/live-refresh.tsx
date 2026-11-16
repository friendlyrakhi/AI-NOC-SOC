"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

type Topic = "alert.upserted" | "incident.changed";

/**
 * Refreshes the current page (server components re-render with fresh API data) when the
 * tenant's live stream reports a change. Bursts are coalesced into one refresh per second.
 * Shows a small status so users know whether the view is live.
 */
export function LiveRefresh({ topics, incidentId }: { topics: Topic[]; incidentId?: string }) {
  const router = useRouter();
  const [state, setState] = useState<"connecting" | "live" | "offline">("connecting");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const key = topics.join(",");

  useEffect(() => {
    const wanted = new Set(key.split(","));
    const source = new EventSource("/api/live");
    const schedule = () => {
      if (timer.current) return;
      timer.current = setTimeout(() => {
        timer.current = null;
        router.refresh();
      }, 1000);
    };
    const handler = (event: MessageEvent<string>) => {
      if (!incidentId) return schedule();
      try {
        const data = JSON.parse(event.data) as { id?: string };
        if (event.type !== "incident.changed" || data.id === incidentId) schedule();
      } catch {
        /* ignore malformed events */
      }
    };
    for (const t of wanted) source.addEventListener(t, handler as EventListener);
    source.onopen = () => setState("live");
    source.onerror = () => setState(source.readyState === EventSource.CLOSED ? "offline" : "connecting");
    return () => {
      source.close();
      if (timer.current) clearTimeout(timer.current);
    };
  }, [key, incidentId, router]);

  const label = state === "live" ? "Live" : state === "connecting" ? "Connecting…" : "Offline (reload to retry)";
  return (
    <span role="status" aria-live="polite" className="text-muted inline-flex items-center gap-1.5 text-xs">
      <span aria-hidden className={`inline-block size-2 rounded-full ${state === "live" ? "bg-success" : "bg-border"}`} />
      {label}
    </span>
  );
}
