import Link from "next/link";

import { verifyMfa } from "@/app/actions/auth";
import { ActionForm } from "@/components/action-form";
import { Field } from "@/components/ui";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function MfaPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  return (
    <>
      <h1 className="mb-2 text-2xl font-semibold tracking-tight">Two-step verification</h1>
      <p className="text-muted mb-6 text-sm">Enter the 6-digit code from your authenticator app.</p>
      <ActionForm action={verifyMfa} submitLabel="Verify">
        <input type="hidden" name="next" value={typeof sp.next === "string" ? sp.next : "/"} />
        <Field label="Code">
          <input
            name="code"
            required
            autoFocus
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            className="input w-40 font-mono tracking-widest"
          />
        </Field>
      </ActionForm>
      <p className="text-muted mt-6 text-xs">
        Dev: <code className="font-mono">scripts\dev.ps1 totp &lt;email&gt;</code> prints the current code.{" "}
        <Link href="/login" className="underline">
          Start over
        </Link>
      </p>
    </>
  );
}
