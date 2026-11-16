import { login } from "@/app/actions/auth";
import { ActionForm } from "@/components/action-form";
import { Field } from "@/components/ui";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function LoginPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const next = typeof sp.next === "string" ? sp.next : "/";
  const invited = typeof sp.invited === "string" ? sp.invited : null;
  return (
    <>
      <h1 className="mb-6 text-2xl font-semibold tracking-tight">Sign in</h1>
      {sp.expired && <p className="text-warning mb-4 text-sm">Your session ended. Please sign in again.</p>}
      {invited && <p className="text-success mb-4 text-sm">Password set for {invited}. You can sign in now.</p>}
      <ActionForm action={login} submitLabel="Sign in">
        <input type="hidden" name="next" value={next} />
        <Field label="Email">
          <input name="email" type="email" required autoComplete="username" defaultValue={invited ?? ""} className="input w-full" />
        </Field>
        <Field label="Password">
          <input name="password" type="password" required autoComplete="current-password" className="input w-full" />
        </Field>
      </ActionForm>
      <p className="text-muted mt-8 text-xs">
        Development accounts are created by <code className="font-mono">scripts\dev.ps1 seed</code> and listed in{" "}
        <code className="font-mono">infrastructure/secrets/dev-users.json</code>.
      </p>
    </>
  );
}
