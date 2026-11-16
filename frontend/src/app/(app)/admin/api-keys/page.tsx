import { createApiKey, revokeApiKey } from "@/app/actions/admin";
import { ActionForm } from "@/components/action-form";
import { AdminGuard } from "@/components/admin-guard";
import { PermissionPicker } from "@/components/permission-picker";
import { Badge, Card, Field, PageHeader, Table, Td, formatDate } from "@/components/ui";
import { apiGet, apiGetOptional, getMe, has, type Me, type Schemas } from "@/lib/server/api";

export default async function ApiKeysPage() {
  const me = await getMe();
  return (
    <>
      <PageHeader
        title="API keys"
        description="For integrations and scripts. A key never exceeds what its creator can do, and stops working if the creator loses access."
      />
      <AdminGuard me={me} permission="apikey:read">
        <ApiKeys me={me} />
      </AdminGuard>
    </>
  );
}

async function ApiKeys({ me }: { me: Me }) {
  const keys = await apiGet<Schemas["ApiKeyOut"][]>("/api-keys");
  const canManage = has(me, "apikey:manage");
  const permissions = canManage
    ? ((await apiGetOptional<Schemas["PermissionOut"][]>("/permissions")) ?? []).filter((p) => !p.msp_only)
    : [];
  return (
    <div className="space-y-6">
      <Table head={["Name", "Prefix", "Permissions", "Expires", "Last used", "State", ""]} empty={keys.length === 0}>
        {keys.map((k) => (
          <tr key={k.id}>
            <Td>{k.name}</Td>
            <Td className="font-mono text-xs">{k.prefix}…</Td>
            <Td className="text-xs">{k.permissions.join(", ")}</Td>
            <Td className="text-muted text-xs">{formatDate(k.expires_at)}</Td>
            <Td className="text-muted text-xs">{formatDate(k.last_used_at)}</Td>
            <Td>{k.revoked_at ? <Badge tone="danger">revoked</Badge> : <Badge tone="success">active</Badge>}</Td>
            <Td>
              {canManage && !k.revoked_at && (
                <ActionForm action={revokeApiKey} submitLabel="Revoke" danger stepUp className="space-y-2">
                  <input type="hidden" name="key_id" value={k.id} />
                </ActionForm>
              )}
            </Td>
          </tr>
        ))}
      </Table>
      {canManage && (
        <Card title="Create a key">
          <ActionForm action={createApiKey} submitLabel="Create key" stepUp>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Name">
                <input name="name" required maxLength={100} className="input w-full" />
              </Field>
              <Field label="Expires in (days)">
                <input name="expires_in_days" type="number" min={1} max={365} defaultValue={90} className="input w-28" />
              </Field>
            </div>
            <PermissionPicker permissions={permissions} allowed={new Set(me.permissions)} />
          </ActionForm>
        </Card>
      )}
    </div>
  );
}
