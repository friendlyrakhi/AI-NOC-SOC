import Link from "next/link";

import { assignRoles, removeMember, setMemberStatus } from "@/app/actions/admin";
import { ActionForm } from "@/components/action-form";
import { AdminGuard } from "@/components/admin-guard";
import { Badge, Card, PageHeader, formatDate } from "@/components/ui";
import { apiGetOptional, getMe, has, type Me, type Schemas } from "@/lib/server/api";

export default async function MemberPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const me = await getMe();
  return (
    <>
      <p className="mb-2 text-sm">
        <Link href="/admin/users" className="text-muted hover:text-foreground">
          ← Members
        </Link>
      </p>
      <AdminGuard me={me} permission="user:read">
        <Member id={id} me={me} />
      </AdminGuard>
    </>
  );
}

async function Member({ id, me }: { id: string; me: Me }) {
  const member = await apiGetOptional<Schemas["MemberOut"]>(`/users/${encodeURIComponent(id)}`);
  if (!member) {
    return (
      <>
        <PageHeader title="Member not found" />
        <Card>
          <p className="text-muted text-sm">This person is not a member of the current tenant.</p>
        </Card>
      </>
    );
  }
  const self = member.user_id === me.user_id;
  const roles = has(me, "role:assign") ? ((await apiGetOptional<Schemas["RoleOut"][]>("/roles")) ?? []) : [];
  const held = new Set(member.roles.map((r) => r.id));
  return (
    <>
      <PageHeader title={member.display_name} description={member.email} />
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Membership">
          <dl className="grid grid-cols-[8rem_1fr] gap-y-2 text-sm">
            <dt className="text-muted">Account</dt>
            <dd>
              <Badge tone={member.user_status === "active" ? "success" : "warning"}>{member.user_status}</Badge>
            </dd>
            <dt className="text-muted">In this tenant</dt>
            <dd>
              <Badge tone={member.membership_status === "active" ? "success" : "danger"}>{member.membership_status}</Badge>
            </dd>
            <dt className="text-muted">Last sign-in</dt>
            <dd>{formatDate(member.last_login_at)}</dd>
          </dl>
          {self && <p className="text-muted mt-4 text-xs">You cannot change your own membership or roles.</p>}
          {!self && has(me, "user:update") && (
            <div className="mt-4">
              <ActionForm
                action={setMemberStatus}
                submitLabel={member.membership_status === "active" ? "Suspend" : "Reactivate"}
                danger={member.membership_status === "active"}
                stepUp
              >
                <input type="hidden" name="user_id" value={member.user_id} />
                <input type="hidden" name="status" value={member.membership_status === "active" ? "suspended" : "active"} />
              </ActionForm>
            </div>
          )}
          {!self && has(me, "user:remove") && (
            <div className="border-border mt-4 border-t pt-4">
              <ActionForm action={removeMember} submitLabel="Remove from tenant" danger stepUp>
                <input type="hidden" name="user_id" value={member.user_id} />
              </ActionForm>
            </div>
          )}
        </Card>

        {!self && has(me, "role:assign") && (
          <Card title="Roles">
            <ActionForm action={assignRoles} submitLabel="Save roles" stepUp>
              <input type="hidden" name="user_id" value={member.user_id} />
              <div className="grid gap-1 sm:grid-cols-2">
                {roles.map((r) => (
                  <label key={r.id} className="flex items-center gap-2 text-sm">
                    <input type="checkbox" name="role_ids" value={r.id} defaultChecked={held.has(r.id)} />
                    {r.name}
                  </label>
                ))}
              </div>
              <p className="text-muted text-xs">You can only grant permissions that you hold yourself.</p>
            </ActionForm>
          </Card>
        )}
      </div>
    </>
  );
}
