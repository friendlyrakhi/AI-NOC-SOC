import Link from "next/link";
import { notFound } from "next/navigation";

import { gate } from "@/components/page-states";
import { PageHeader } from "@/components/ui";
import { formatTime } from "@/lib/format";
import { getMe } from "@/lib/server/api";
import { getKnowledgeDoc } from "@/lib/server/pipeline";

export default async function KnowledgeDocPage({ params }: { params: Promise<{ id: string }> }) {
  const me = await getMe();
  const denied = gate(me, "knowledge:read", "Knowledge document");
  if (denied) return denied;
  const { id } = await params;
  const doc = await getKnowledgeDoc(id);
  if (!doc) notFound();
  return (
    <>
      <p className="mb-2 text-xs">
        <Link href="/knowledge" className="text-primary hover:underline">
          ← Knowledge base
        </Link>
      </p>
      <PageHeader
        title={doc.title}
        description={`${doc.kind} · version ${doc.version} · ${doc.source} · updated ${formatTime(doc.updated_at)}`}
      />
      {/* Plain text: documents are shown without markdown or HTML interpretation. */}
      <pre className="border-border bg-surface rounded-md border p-4 text-sm whitespace-pre-wrap">{doc.body}</pre>
    </>
  );
}
