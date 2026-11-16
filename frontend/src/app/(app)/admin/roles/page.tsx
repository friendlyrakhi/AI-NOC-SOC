import { createRole, deleteRole } from "@/app/actions/admin";
import { ActionForm } from "@/components/action-form";
import { AdminGuard } from "@/components/admin-guard";
import { PermissionPicker } from "@/components/permission-picker";
import { Badge, Card, Field, PageHeader } from "@/components/ui";
import { apiGet, getMe, has, type Me, type Schemas } from "@/lib/server/api";

export default async function RolesPage() {
  const me = await getMe();
  return (
    <>
      <PageHeader
        title="Roles"
        description="System roles are fixed. Custom roles combine permissions for this tenant only."
      />
      <AdminGuard me={me} permission="role:read">
        <Roles me={me} />
      </AdminGuard>
    </>
  );
}

async function Roles({ me }: { me: Me }) {
  const [roles, permissions] = await Promise.all([
    apiGet<Schemas["RoleOut"][]>("/roles"),
    apiGet<Schemas["PermissionOut"][]>("/permissions"),
  ]);
  const canManage = has(me, "role:manage");
  return (
    <div className="space-y-6">
      <div className="grid gap-4 lg:grid-cols-2">
        {roles.map((r) => (
          <Card key={r.id}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold">
                  {r.name} {r.is_system ? <Badge>system</Badge> : <Badge tone="info">custom</Badge>}
                </h2>
                <p className="text-muted font-mono text-xs">{r.key}</p>
                {r.description && <p className="text-muted mt-1 text-xs">{r.description}</p>}
              </div>
              <span className="text-muted text-xs whitespace-nowrap">{r.permissions.length} permissions</span>
            </div>
            <details className="mt-2">
              <summary className="text-muted cursor-pointer text-xs">Show permissions</summary>
              <div className="mt-2 flex flex-wrap gap-1">
                {r.permissions.map((p) => (
                  <Badge key={p}>{p}</Badge>
                ))}
              </div>
            </details>
            {canManage && !r.is_system && (
              <div className="border-border mt-3 border-t pt-3">
                <ActionForm action={deleteRole} submitLabel="Delete role" danger stepUp>
                  <input type="hidden" name="role_id" value={r.id} />
                </ActionForm>
              </div>
            )}
          </Card>
        ))}
      </div>

      {canManage && (
        <Card title="Create a custom role">
          <ActionForm action={createRole} submitLabel="Create role" stepUp resetOnSuccess>
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Key" hint="lowercase, e.g. shift_lead">
                <input name="key" required pattern="[a-z][a-z0-9_]{1,62}" className="input w-full font-mono" />
              </Field>
              <Field label="Name">
                <input name="name" required maxLength={100} className="input w-full" />
              </Field>
              <Field label="Description">
                <input name="description" maxLength={500} className="input w-full" />
              </Field>
            </div>
            <PermissionPicker permissions={permissions} allowed={new Set(me.permissions)} />
          </ActionForm>
        </Card>
      )}
    </div>
  );
}
