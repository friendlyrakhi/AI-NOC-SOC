import { createMsp } from "@/app/actions/admin";
import { ActionForm } from "@/components/action-form";
import { Badge, Card, Field, PageHeader, Table, Td, formatDate } from "@/components/ui";
import { apiGet, getMe, type Schemas } from "@/lib/server/api";

export default async function PlatformPage() {
  const me = await getMe();
  if (!me.is_platform_admin) {
    return (
      <>
        <PageHeader title="Platform" />
        <Card>
          <p className="text-muted text-sm">Only platform administrators can see this page.</p>
        </Card>
      </>
    );
  }
  const tenants = await apiGet<Schemas["PlatformTenantOut"][]>("/platform/tenants");
  const names = new Map(tenants.map((t) => [t.id, t.name]));
  return (
    <>
      <PageHeader
        title="Platform"
        description="Tenants on this installation. Platform administrators manage tenants but cannot read tenant data."
      />
      <div className="space-y-6">
        <Table head={["Tenant", "Type", "Managed by", "Members", "Status", "Created"]}>
          {tenants.map((t) => (
            <tr key={t.id}>
              <Td>
                {t.name} <span className="text-muted font-mono text-xs">{t.slug}</span>
              </Td>
              <Td>
                <Badge tone={t.kind === "msp" ? "info" : "neutral"}>{t.kind}</Badge>
              </Td>
              <Td>{t.parent_tenant_id ? names.get(t.parent_tenant_id) : "—"}</Td>
              <Td>{t.members}</Td>
              <Td>
                <Badge tone={t.status === "active" ? "success" : "warning"}>{t.status}</Badge>
              </Td>
              <Td className="text-muted text-xs">{formatDate(t.created_at)}</Td>
            </tr>
          ))}
        </Table>
        <Card title="Create an MSP tenant">
          <ActionForm action={createMsp} submitLabel="Create MSP" resetOnSuccess>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Name">
                <input name="name" required maxLength={200} className="input w-full" />
              </Field>
              <Field label="Slug">
                <input name="slug" required pattern="[a-z0-9][a-z0-9-]{1,62}" className="input w-full font-mono" />
              </Field>
              <Field label="Administrator email">
                <input name="admin_email" type="email" required className="input w-full" />
              </Field>
              <Field label="Administrator name">
                <input name="admin_name" required maxLength={200} className="input w-full" />
              </Field>
            </div>
          </ActionForm>
        </Card>
      </div>
    </>
  );
}
