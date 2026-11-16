import { onboardCustomer } from "@/app/actions/admin";
import { ActionForm } from "@/components/action-form";
import { AdminGuard } from "@/components/admin-guard";
import { Badge, Card, Field, PageHeader, Table, Td, formatDate } from "@/components/ui";
import { apiGet, getMe, has, type Schemas } from "@/lib/server/api";

export default async function CustomersPage() {
  const me = await getMe();
  return (
    <>
      <PageHeader
        title="Customers"
        description="Customer tenants managed by this MSP. Each customer's data stays isolated; your staff reach it only through delegations."
      />
      {me.active_tenant_kind !== "msp" && me.mode !== "aggregate" ? (
        <Card>
          <p className="text-muted text-sm">Switch to your MSP tenant to manage customers.</p>
        </Card>
      ) : (
        <AdminGuard me={me} permission="msp:customers:read">
          <Customers canManage={has(me, "msp:customers:manage")} />
        </AdminGuard>
      )}
    </>
  );
}

async function Customers({ canManage }: { canManage: boolean }) {
  const customers = await apiGet<Schemas["CustomerOut"][]>("/customers");
  return (
    <div className="space-y-6">
      <Table head={["Customer", "Slug", "Status", "Active delegations", "Created"]} empty={customers.length === 0}>
        {customers.map((c) => (
          <tr key={c.id}>
            <Td>{c.name}</Td>
            <Td className="font-mono text-xs">{c.slug}</Td>
            <Td>
              <Badge tone={c.status === "active" ? "success" : "warning"}>{c.status}</Badge>
            </Td>
            <Td>{c.active_delegations}</Td>
            <Td className="text-muted text-xs">{formatDate(c.created_at)}</Td>
          </tr>
        ))}
      </Table>
      {canManage && (
        <Card title="Onboard a customer">
          <p className="text-muted mb-3 text-xs">
            Creates the tenant, gives your MSP administrators administrator access to it (the customer can revoke this),
            and invites the customer&apos;s first administrator by email.
          </p>
          <ActionForm action={onboardCustomer} submitLabel="Onboard customer" stepUp resetOnSuccess>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Customer name">
                <input name="name" required maxLength={200} className="input w-full" />
              </Field>
              <Field label="Slug" hint="lowercase letters, digits and dashes">
                <input name="slug" required pattern="[a-z0-9][a-z0-9-]{1,62}" className="input w-full font-mono" />
              </Field>
              <Field label="Customer administrator email">
                <input name="admin_email" type="email" required className="input w-full" />
              </Field>
              <Field label="Administrator name">
                <input name="admin_name" required maxLength={200} className="input w-full" />
              </Field>
            </div>
          </ActionForm>
        </Card>
      )}
    </div>
  );
}
