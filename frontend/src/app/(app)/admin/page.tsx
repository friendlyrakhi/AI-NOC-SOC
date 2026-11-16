import { renameTenant } from "@/app/actions/admin";
import { ActionForm } from "@/components/action-form";
import { AdminGuard } from "@/components/admin-guard";
import { Badge, Card, Field, PageHeader, formatDate } from "@/components/ui";
import { apiGet, getMe, has, type Schemas } from "@/lib/server/api";

export default async function TenantSettingsPage() {
  const me = await getMe();
  return (
    <>
      <PageHeader title="Tenant" description="Settings of the tenant you are working in." />
      <AdminGuard me={me} permission="tenant:read">
        <TenantSettings canEdit={has(me, "tenant:update")} />
      </AdminGuard>
    </>
  );
}

async function TenantSettings({ canEdit }: { canEdit: boolean }) {
  const t = await apiGet<Schemas["TenantOut"]>("/tenant");
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card title="Details">
        <dl className="grid grid-cols-[8rem_1fr] gap-y-2 text-sm">
          <dt className="text-muted">Name</dt>
          <dd>{t.name}</dd>
          <dt className="text-muted">Slug</dt>
          <dd className="font-mono">{t.slug}</dd>
          <dt className="text-muted">Type</dt>
          <dd>
            <Badge tone={t.kind === "msp" ? "info" : "neutral"}>{t.kind === "msp" ? "MSP" : "Customer"}</Badge>
          </dd>
          <dt className="text-muted">Status</dt>
          <dd>
            <Badge tone={t.status === "active" ? "success" : "warning"}>{t.status}</Badge>
          </dd>
          <dt className="text-muted">Created</dt>
          <dd>{formatDate(t.created_at)}</dd>
        </dl>
      </Card>
      {canEdit && (
        <Card title="Rename">
          <ActionForm action={renameTenant} submitLabel="Save" stepUp>
            <Field label="Display name">
              <input name="name" required maxLength={200} defaultValue={t.name} className="input w-full" />
            </Field>
          </ActionForm>
        </Card>
      )}
    </div>
  );
}
