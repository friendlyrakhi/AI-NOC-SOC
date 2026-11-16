import type { Schemas } from "@/lib/server/api";

/** Checkbox list of permissions grouped by resource. */
export function PermissionPicker({
  permissions,
  allowed,
}: {
  permissions: Schemas["PermissionOut"][];
  /** Only these can be selected (you cannot grant what you do not hold). */
  allowed: Set<string>;
}) {
  const groups = new Map<string, Schemas["PermissionOut"][]>();
  for (const p of permissions) {
    const group = p.key.split(":")[0];
    groups.set(group, [...(groups.get(group) ?? []), p]);
  }
  return (
    <fieldset className="max-h-80 overflow-y-auto pr-2">
      <legend className="text-muted text-xs">Permissions</legend>
      <div className="mt-2 grid gap-x-6 gap-y-3 sm:grid-cols-2">
        {[...groups.entries()].map(([group, perms]) => (
          <div key={group}>
            <p className="text-muted mb-1 text-xs font-medium tracking-wide uppercase">{group}</p>
            {perms.map((p) => (
              <label key={p.key} className={`flex items-start gap-2 text-sm ${allowed.has(p.key) ? "" : "opacity-40"}`}>
                <input type="checkbox" name="permissions" value={p.key} disabled={!allowed.has(p.key)} className="mt-1" />
                <span>
                  <span className="font-mono text-xs">{p.key}</span>
                  {p.privileged && <span className="text-warning ml-1 text-[10px]">MFA</span>}
                  <span className="text-muted block text-xs">{p.description}</span>
                </span>
              </label>
            ))}
          </div>
        ))}
      </div>
    </fieldset>
  );
}
