import Link from "next/link";

import { ApprovalList, DecisionControls, RequestSummary, TierBadge } from "@/components/automation";
import { SandboxNotice } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { Card, NotAvailable, PageHeader } from "@/components/ui";
import { getMe } from "@/lib/server/api";
import { getInbox } from "@/lib/server/automation";

/** Requests waiting for this approver: not their own, not yet decided by them, not expired. */
export default async function ApprovalsPage() {
  const me = await getMe();
  const denied = gate(me, "action:approve", "Approvals inbox");
  if (denied) return denied;
  const inbox = await getInbox();
  return (
    <>
      <p className="mb-2 text-xs">
        <Link href="/automation" className="text-primary hover:underline">
          ← Automation center
        </Link>
      </p>
      <PageHeader title="Approvals inbox" description="Action requests that need your decision. Highest risk first." />
      <SandboxNotice>Approved actions run in simulate or dry-run mode through sandbox connectors. No real system is changed.</SandboxNotice>
      {!inbox ? (
        <NotAvailable what="The approvals inbox" />
      ) : inbox.length === 0 ? (
        <Card>
          <p className="text-muted text-sm">Nothing is waiting for you.</p>
        </Card>
      ) : (
        <ul className="space-y-4" aria-label="Requests waiting for approval">
          {inbox.map((r) => (
            <li key={r.id}>
              <Card>
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <TierBadge tier={r.tier} />
                  <Link href={`/automation/requests/${r.id}`} className="font-mono text-sm font-semibold hover:underline">
                    {r.action_key}
                  </Link>
                  {r.requested_by_type === "ai" && (
                    <span className="border-primary/40 text-primary rounded border px-1.5 py-px text-[11px] font-medium">AI-suggested</span>
                  )}
                </div>
                <div className="grid gap-4 lg:grid-cols-2">
                  <RequestSummary r={r} />
                  <div className="space-y-4">
                    <ApprovalList r={r} />
                    <DecisionControls r={r} me={me} compact />
                  </div>
                </div>
              </Card>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
