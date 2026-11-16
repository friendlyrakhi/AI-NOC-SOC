import type { ReactNode } from "react";

import { Card, PageHeader } from "@/components/ui";
import type { Me } from "@/lib/server/api";

/** Returns a page-level state to render instead of content, or null when the page may render. */
export function gate(me: Me, permission: string, title: string): ReactNode | null {
  if (!me.permissions.includes(permission)) {
    return (
      <>
        <PageHeader title={title} />
        <Card>
          <p className="text-muted text-sm">
            Your role does not include this area (<code className="font-mono">{permission}</code>). Ask a tenant administrator if you need
            access.
          </p>
        </Card>
      </>
    );
  }
  if (me.mode === "none") {
    return (
      <>
        <PageHeader title={title} />
        <Card>
          <p className="text-muted text-sm">Select a tenant in the switcher to see this page.</p>
        </Card>
      </>
    );
  }
  return null;
}

export function Grid({ children, cols = 4 }: { children: ReactNode; cols?: 2 | 3 | 4 | 5 | 6 }) {
  const map = { 2: "sm:grid-cols-2", 3: "sm:grid-cols-2 lg:grid-cols-3", 4: "sm:grid-cols-2 xl:grid-cols-4", 5: "sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5", 6: "sm:grid-cols-3 xl:grid-cols-6" };
  return <div className={`grid gap-4 ${map[cols]}`}>{children}</div>;
}
