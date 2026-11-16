/** Shared shape for Server Action results rendered by <ActionForm>. */
export interface FormState {
  ok: boolean;
  message?: string;
  error?: string;
  /** One-time values shown to the user (e.g. a new API key). */
  secret?: string;
}

export const initialFormState: FormState = { ok: false };

export function str(form: FormData, key: string): string {
  const v = form.get(key);
  return typeof v === "string" ? v.trim() : "";
}

export function all(form: FormData, key: string): string[] {
  return form
    .getAll(key)
    .filter((v): v is string => typeof v === "string")
    .map((v) => v.trim())
    .filter(Boolean);
}
