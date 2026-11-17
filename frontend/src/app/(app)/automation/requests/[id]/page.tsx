import Link from "next/link";
import { notFound } from "next/navigation";

import { ApprovalList, DecisionControls, ModeBadge, RequestSummary, ResultBlock, TierBadge } from "@/components/automation";
import { SandboxNotice, StateBadge } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { PollRefresh } from "@/components/poll-refresh";
import { Card, PageHeader } from "@/components/ui";
import { getMe } from "@/lib/server/api";
import { getRequest } from "@/lib/server/automation";
import { isUuid } from "@/lib/server/pipeline";

const ACTIVE = new Set(["approved", "executing"]);

export default async function RequestPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const me = await getMe();
  const denied = gate(me, "action:read", "Action request");
  if (denied) return denied;
  const r = isUuid(id) ? await getRequest(id) : null;
  if (!r) notFound();
  return (
    <>
      <p className="mb-2 text-xs">
        <Link href={me.permissions.includes("action:approve") ? "/automation/approvals" : "/automation"} className="text-primary hover:underline">
          ← {me.permissions.includes("action:approve") ? "Approvals inbox" : "Automation center"}
        </Link>
      </p>
      <PageHeader
        title={r.action_key}
        description="Action request"
        actions={
          <span className="flex items-center gap-2">
            {ACTIVE.has(r.status) && <PollRefresh />}
            <TierBadge tier={r.tier} />
            <ModeBadge mode={r.execution_mode} />
            <StateBadge value={r.status} />
          </span>
        }
      />
      <SandboxNotice>Runs through a sandbox connector in {r.execution_mode === "dry_run" ? "dry-run" : "simulate"} mode. No real system is changed.</SandboxNotice>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Request">
          <RequestSummary r={r} />
          <ResultBlock r={r} />
        </Card>
        <Card title="Approvals">
          <div className="space-y-4">
            <ApprovalList r={r} />
            <DecisionControls r={r} me={me} />
          </div>
        </Card>
      </div>
    </>
  );
}
