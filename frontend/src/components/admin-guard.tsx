import type { ReactNode } from "react";

import { Card } from "@/components/ui";
import type { Me } from "@/lib/server/api";

/** Admin pages work on one tenant. In the read-only "All customers" view, ask for one. */
export function AdminGuard({ me, permission, children }: { me: Me; permission: string; children: ReactNode }) {
  if (me.mode === "aggregate") {
    return (
      <Card>
        <p className="text-sm">
          The <strong>All customers</strong> view is read-only. Choose a single tenant in the switcher to administer it.
        </p>
      </Card>
    );
  }
  if (me.mode === "none") {
    return (
      <Card>
        <p className="text-muted text-sm">Select a tenant first.</p>
      </Card>
    );
  }
  if (!me.permissions.includes(permission)) {
    return (
      <Card>
        <p className="text-muted text-sm">Your role does not include this area ({permission}).</p>
      </Card>
    );
  }
  return <>{children}</>;
}
