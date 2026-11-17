"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

/**
 * Re-renders the page every few seconds while something is still in progress (a workflow run
 * or an action request). Render it only for non-terminal states, so finished pages stay still.
 */
export function PollRefresh({ seconds = 3 }: { seconds?: number }) {
  const router = useRouter();
  useEffect(() => {
    const t = setInterval(() => router.refresh(), seconds * 1000);
    return () => clearInterval(t);
  }, [router, seconds]);
  return (
    <span className="text-muted inline-flex items-center gap-1.5 text-xs" role="status">
      <span aria-hidden="true" className="bg-warning h-2 w-2 animate-pulse rounded-full" />
      In progress: updating
    </span>
  );
}
