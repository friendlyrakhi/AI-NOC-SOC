import { ActionForm } from "@/components/action-form";
import { DataTable, type ColumnSpec } from "@/components/data-table";
import { gate } from "@/components/page-states";
import { Card, Field, NotAvailable, PageHeader } from "@/components/ui";
import { publishDoc } from "@/app/actions/ai";
import { getMe } from "@/lib/server/api";
import { getKnowledgeDocs } from "@/lib/server/pipeline";

const columns: ColumnSpec[] = [
  { key: "title", header: "Title", type: "link", hrefKey: "_href" },
  { key: "kind", header: "Kind", filter: true },
  { key: "source", header: "Source", filter: true, hideOnMobile: true },
  { key: "version", header: "Version", type: "number", align: "right", hideOnMobile: true },
  { key: "updated", header: "Updated", type: "relative" },
];

export default async function KnowledgePage() {
  const me = await getMe();
  const denied = gate(me, "knowledge:read", "Knowledge base");
  if (denied) return denied;
  const docs = me.mode === "aggregate" ? null : await getKnowledgeDocs();
  return (
    <>
      <PageHeader
        title="Knowledge base"
        description="Runbooks and articles the AI copilot cites as evidence. Only people with publish rights can add them, because they become model context."
      />
      {!docs ? (
        <NotAvailable what="Knowledge base (select a single customer)" />
      ) : (
        <DataTable
          caption="Knowledge documents"
          rows={docs.map((d) => ({
            _id: d.id,
            _href: `/knowledge/${d.id}`,
            title: d.title,
            kind: d.kind,
            source: d.source,
            version: d.version,
            updated: d.updated_at,
          }))}
          columns={columns}
          searchPlaceholder="Search runbooks…"
          emptyText="No documents yet."
        />
      )}
      {docs && me.permissions.includes("knowledge:publish") && (
        <Card title="Publish a document" className="mt-6">
          <p className="text-muted mb-2 text-xs">
            Text that looks like instructions to an AI model is refused. Publishing the same title again creates a new version.
          </p>
          <ActionForm action={publishDoc} submitLabel="Publish" stepUp resetOnSuccess>
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Title">
                <input name="title" required maxLength={200} className="input mt-1 w-full" />
              </Field>
              <Field label="Kind">
                <select name="kind" className="input mt-1 w-full" defaultValue="runbook">
                  <option value="runbook">Runbook</option>
                  <option value="kb">Knowledge article</option>
                  <option value="postmortem">Postmortem</option>
                </select>
              </Field>
            </div>
            <label className="block">
              <span className="text-muted text-xs">Content (plain text)</span>
              <textarea name="body" required maxLength={100000} rows={8} className="input mt-1 w-full" />
            </label>
          </ActionForm>
        </Card>
      )}
    </>
  );
}
