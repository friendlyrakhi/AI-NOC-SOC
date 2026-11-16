import Link from "next/link";

import { inviteMember } from "@/app/actions/admin";
import { ActionForm } from "@/components/action-form";
import { AdminGuard } from "@/components/admin-guard";
import { Badge, Card, Field, PageHeader, Table, Td, formatDate } from "@/components/ui";
import { apiGet, apiGetOptional, getMe, has, type Schemas } from "@/lib/server/api";

export default async function MembersPage() {
  const me = await getMe();
  return (
    <>
      <PageHeader title="Members" description="People with a membership in this tenant. MSP staff with delegated access are listed under Delegations." />
      <AdminGuard me={me} permission="user:read">
        <Members canInvite={has(me, "user:invite")} canAssign={has(me, "role:assign")} />
      </AdminGuard>
    </>
  );
}

async function Members({ canInvite, canAssign }: { canInvite: boolean; canAssign: boolean }) {
  const members = await apiGet<Schemas["MemberOut"][]>("/users");
  const roles = canAssign ? ((await apiGetOptional<Schemas["RoleOut"][]>("/roles")) ?? []) : [];
  return (
    <div className="space-y-6">
      <Table head={["Name", "Email", "Roles", "Status", "Last sign-in"]} empty={members.length === 0}>
        {members.map((m) => (
          <tr key={m.user_id}>
            <Td>
              <Link href={`/admin/users/${m.user_id}`} className="text-primary hover:underline">
                {m.display_name}
              </Link>
            </Td>
            <Td className="font-mono text-xs">{m.email}</Td>
            <Td>
              <div className="flex flex-wrap gap-1">
                {m.roles.map((r) => (
                  <Badge key={r.id}>{r.name}</Badge>
                ))}
              </div>
            </Td>
            <Td>
              {m.user_status === "invited" ? (
                <Badge tone="warning">invited</Badge>
              ) : (
                <Badge tone={m.membership_status === "active" ? "success" : "danger"}>{m.membership_status}</Badge>
              )}
            </Td>
            <Td className="text-muted text-xs">{formatDate(m.last_login_at)}</Td>
          </tr>
        ))}
      </Table>

      {canInvite && (
        <Card title="Invite a member">
          <ActionForm action={inviteMember} submitLabel="Send invitation" resetOnSuccess>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Email">
                <input name="email" type="email" required className="input w-full" />
              </Field>
              <Field label="Display name">
                <input name="display_name" required maxLength={200} className="input w-full" />
              </Field>
            </div>
            {canAssign && (
              <fieldset>
                <legend className="text-muted text-xs">Roles</legend>
                <div className="mt-1 grid gap-1 sm:grid-cols-2 lg:grid-cols-3">
                  {roles.map((r) => (
                    <label key={r.id} className="flex items-center gap-2 text-sm">
                      <input type="checkbox" name="role_ids" value={r.id} />
                      {r.name}
                      {!r.is_system && <Badge>custom</Badge>}
                    </label>
                  ))}
                </div>
              </fieldset>
            )}
          </ActionForm>
        </Card>
      )}
    </div>
  );
}
