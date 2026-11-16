import { acceptInvitation } from "@/app/actions/auth";
import { ActionForm } from "@/components/action-form";
import { Field } from "@/components/ui";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function AcceptInvitationPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const token = typeof sp.token === "string" ? sp.token : "";
  return (
    <>
      <h1 className="mb-2 text-2xl font-semibold tracking-tight">Accept invitation</h1>
      <p className="text-muted mb-6 text-sm">Choose a password of at least 12 characters.</p>
      {token ? (
        <ActionForm action={acceptInvitation} submitLabel="Set password">
          <input type="hidden" name="token" value={token} />
          <Field label="New password">
            <input name="password" type="password" required minLength={12} autoComplete="new-password" className="input w-full" />
          </Field>
          <Field label="Confirm password">
            <input name="confirm" type="password" required minLength={12} autoComplete="new-password" className="input w-full" />
          </Field>
        </ActionForm>
      ) : (
        <p className="text-danger text-sm">This invitation link is incomplete.</p>
      )}
    </>
  );
}
