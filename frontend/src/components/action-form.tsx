"use client";

import { startTransition, useActionState, useEffect, useRef, type FormEvent, type ReactNode } from "react";

import { initialFormState, type FormState } from "@/lib/forms";

interface Props {
  action: (state: FormState, form: FormData) => Promise<FormState>;
  submitLabel: string;
  children?: ReactNode;
  /** Adds an authenticator-code field (sensitive actions need a recent step-up). */
  stepUp?: boolean;
  danger?: boolean;
  className?: string;
  resetOnSuccess?: boolean;
}

export function ActionForm({ action, submitLabel, children, stepUp, danger, className, resetOnSuccess }: Props) {
  const [state, formAction, pending] = useActionState(action, initialFormState);
  const ref = useRef<HTMLFormElement>(null);

  useEffect(() => {
    if (state.ok && resetOnSuccess) ref.current?.reset();
  }, [state, resetOnSuccess]);

  // Submit manually: React 19 resets a form after its `action` runs, which would wipe the
  // user's input when a change fails (e.g. a mistyped authenticator code).
  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    startTransition(() => formAction(data));
  }

  return (
    <form ref={ref} onSubmit={onSubmit} className={className ?? "space-y-3"}>
      {children}
      {stepUp && (
        <label className="block">
          <span className="text-muted text-xs">Authenticator code (required for this change)</span>
          <input
            name="mfa_code"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            placeholder="123456"
            className="input mt-1 w-32 font-mono"
          />
        </label>
      )}
      <div className="flex items-center gap-3">
        <button type="submit" disabled={pending} className={danger ? "btn btn-danger" : "btn btn-primary"}>
          {pending ? "Working…" : submitLabel}
        </button>
        {state.error && (
          <p role="alert" className="text-danger text-sm">
            {state.error}
          </p>
        )}
        {state.ok && state.message && (
          <p role="status" className="text-success text-sm">
            {state.message}
          </p>
        )}
      </div>
      {state.secret && (
        <div className="border-warning/50 bg-warning/10 rounded-md border p-3">
          <p className="text-warning text-xs font-medium">Shown once. Store it securely.</p>
          <code className="mt-1 block font-mono text-sm break-all select-all">{state.secret}</code>
        </div>
      )}
    </form>
  );
}
