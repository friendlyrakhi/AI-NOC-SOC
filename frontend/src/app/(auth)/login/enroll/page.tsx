import Link from "next/link";

import { confirmEnrollment } from "@/app/actions/auth";
import { ActionForm } from "@/components/action-form";
import { Field } from "@/components/ui";
import { apiFetch } from "@/lib/server/api";
import { getChallenge } from "@/lib/server/session";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function EnrollPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const challenge = await getChallenge();
  const start = challenge
    ? await apiFetch<{ secret: string; otpauth_uri: string }>("/auth/mfa/enroll", {
        method: "POST",
        auth: false,
        body: { challenge },
      })
    : null;

  if (!start?.ok) {
    return (
      <>
        <h1 className="mb-4 text-2xl font-semibold tracking-tight">Set up two-step verification</h1>
        <p className="text-muted text-sm">
          This sign-in has expired.{" "}
          <Link href="/login" className="underline">
            Sign in again
          </Link>
          .
        </p>
      </>
    );
  }
  const grouped = start.data.secret.match(/.{1,4}/g)?.join(" ") ?? start.data.secret;
  return (
    <>
      <h1 className="mb-2 text-2xl font-semibold tracking-tight">Set up two-step verification</h1>
      <p className="text-muted mb-4 text-sm">
        Your role can change settings or approve actions, so an authenticator app is required. Add this key to the app,
        then enter the code it shows.
      </p>
      <div className="bg-surface border-border mb-6 rounded-md border p-3">
        <p className="text-muted text-xs">Setup key</p>
        <code className="block font-mono text-sm tracking-wider select-all">{grouped}</code>
        <a href={start.data.otpauth_uri} className="text-primary mt-2 inline-block text-xs underline">
          Open in authenticator app
        </a>
      </div>
      <ActionForm action={confirmEnrollment} submitLabel="Confirm and sign in">
        <input type="hidden" name="next" value={typeof sp.next === "string" ? sp.next : "/"} />
        <Field label="Code from your app">
          <input
            name="code"
            required
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            className="input w-40 font-mono tracking-widest"
          />
        </Field>
      </ActionForm>
    </>
  );
}
