import { redirect } from "next/navigation";

import { Card, PageHeader } from "@/components/ui";
import { PORTALS } from "@/lib/portals";
import { getMe } from "@/lib/server/api";

export default async function Home() {
  const me = await getMe();
  const first = PORTALS.find((p) => me.portals.includes(p.id));
  if (first) redirect(first.href);
  if (me.is_platform_admin) redirect("/admin/platform");
  // Approvers may hold no portal at all: their work is the approvals inbox.
  if (me.permissions.includes("action:approve")) redirect("/automation/approvals");
  return (
    <>
      <PageHeader title="No portal available" />
      <Card>
        <p className="text-muted text-sm">
          {me.tenants.length === 0
            ? "You are not a member of any tenant yet. Ask an administrator to invite you."
            : "Your role in this tenant does not include any portal. Choose another tenant, or ask an administrator."}
        </p>
      </Card>
    </>
  );
}
