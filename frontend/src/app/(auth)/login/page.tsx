import { login } from "@/app/actions/auth";
import { ActionForm } from "@/components/action-form";
import { Field } from "@/components/ui";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

const API = process.env.NOCSOC_API_INTERNAL_URL ?? "http://127.0.0.1:8100";

/** Optional single sign-on (P7): shown only when the API reports it configured. */
async function ssoConfig(): Promise<{ enabled: boolean; display_name: string } | null> {
  try {
    const r = await fetch(`${API}/api/v1/auth/oidc/config`, { cache: "no-store" });
    return r.ok ? ((await r.json()) as { enabled: boolean; display_name: string }) : null;
  } catch {
    return null;
  }
}

const SSO_ERRORS: Record<string, string> = {
  failed: "Single sign-on did not complete. Try again or use your password.",
  "no-account": "Your identity provider account has no access to this platform. Ask an administrator for an invitation.",
};

export default async function LoginPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const next = typeof sp.next === "string" ? sp.next : "/";
  const invited = typeof sp.invited === "string" ? sp.invited : null;
  const sso = await ssoConfig();
  const ssoError = typeof sp.sso === "string" ? SSO_ERRORS[sp.sso] : undefined;
  return (
    <>
      <h1 className="mb-6 text-2xl font-semibold tracking-tight">Sign in</h1>
      {sp.expired && <p className="text-warning mb-4 text-sm">Your session ended. Please sign in again.</p>}
      {invited && <p className="text-success mb-4 text-sm">Password set for {invited}. You can sign in now.</p>}
      {ssoError && (
        <p role="alert" className="text-danger mb-4 text-sm">
          {ssoError}
        </p>
      )}
      {sso?.enabled && (
        <div className="mb-6">
          <a href="/login/sso/start" className="btn btn-primary w-full justify-center">
            Sign in with {sso.display_name}
          </a>
          <p className="text-muted mt-3 text-center text-xs">or with your platform password</p>
        </div>
      )}
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
