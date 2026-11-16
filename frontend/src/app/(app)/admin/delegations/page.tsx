import { createDelegation, revokeDelegation } from "@/app/actions/admin";
import { ActionForm } from "@/components/action-form";
import { AdminGuard } from "@/components/admin-guard";
import { Badge, Card, Field, PageHeader, Table, Td, formatDate } from "@/components/ui";
import { apiGet, apiGetOptional, getMe, has, type Me, type Schemas } from "@/lib/server/api";

export default async function DelegationsPage() {
  const me = await getMe();
  const isMsp = me.active_tenant_kind === "msp";
  return (
    <>
      <PageHeader
        title={isMsp ? "Delegations" : "MSP access"}
        description={
          isMsp
            ? "Which of your MSP roles may work inside each customer, and with which customer role. Customers can see and revoke these."
            : "Access your managed service provider has to this tenant. Revoking takes effect on the MSP's next request."
        }
      />
      <AdminGuard me={me} permission="delegation:read">
        <Delegations me={me} isMsp={isMsp} />
      </AdminGuard>
    </>
  );
}

async function Delegations({ me, isMsp }: { me: Me; isMsp: boolean }) {
  const delegations = await apiGet<Schemas["DelegationOut"][]>("/delegations");
  const canManage = has(me, "delegation:manage");
  const [customers, roles] =
    isMsp && canManage
      ? await Promise.all([
          apiGetOptional<Schemas["CustomerOut"][]>("/customers"),
          apiGetOptional<Schemas["RoleOut"][]>("/roles"),
        ])
      : [null, null];
  const systemRoles = (roles ?? []).filter((r) => r.is_system);
  return (
    <div className="space-y-6">
      <Table
        head={[isMsp ? "Customer" : "MSP", "MSP role", "Customer role", "All customers view", "Expires", "State", ""]}
        empty={delegations.length === 0}
      >
        {delegations.map((d) => (
          <tr key={d.id}>
            <Td>{isMsp ? d.customer_tenant.name : d.msp_tenant.name}</Td>
            <Td>{d.msp_role_name ?? <span className="text-muted">MSP custom role</span>}</Td>
            <Td>{d.customer_role_name}</Td>
            <Td>{d.aggregate_read ? "yes" : "no"}</Td>
            <Td className="text-muted text-xs">{d.expires_at ? formatDate(d.expires_at) : "never"}</Td>
            <Td>
              {d.active ? <Badge tone="success">active</Badge> : <Badge tone="danger">{d.revoked_at ? "revoked" : "expired"}</Badge>}
            </Td>
            <Td>
              {canManage && d.active && (
                <ActionForm action={revokeDelegation} submitLabel="Revoke" danger stepUp className="space-y-2">
                  <input type="hidden" name="delegation_id" value={d.id} />
                </ActionForm>
              )}
            </Td>
          </tr>
        ))}
      </Table>

      {isMsp && canManage && customers && (
        <Card title="Grant a delegation">
          <ActionForm action={createDelegation} submitLabel="Grant" stepUp>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Field label="Customer">
                <select name="customer_tenant_id" required className="input w-full">
                  {customers.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Your MSP role">
                <select name="msp_role_id" required className="input w-full">
                  {(roles ?? []).map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Gets customer role">
                <select name="customer_role_key" required className="input w-full">
                  {systemRoles.map((r) => (
                    <option key={r.key} value={r.key}>
                      {r.name}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Expires (optional)">
                <input name="expires_at" type="date" className="input w-full" />
              </Field>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" name="aggregate_read" defaultChecked /> Include in the read-only “All customers” view
            </label>
          </ActionForm>
        </Card>
      )}
    </div>
  );
}
