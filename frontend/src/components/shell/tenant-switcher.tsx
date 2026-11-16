"use client";

import { usePathname } from "next/navigation";
import { useRef } from "react";

import { switchTenant } from "@/app/actions/auth";

export interface TenantOption {
  value: string; // "<tenant_id>:tenant" | "<tenant_id>:aggregate"
  label: string;
}

export function TenantSwitcher({ options, current }: { options: TenantOption[]; current: string }) {
  const form = useRef<HTMLFormElement>(null);
  const pathname = usePathname();
  if (options.length === 0) return null;
  return (
    <form ref={form} action={switchTenant}>
      <input type="hidden" name="return_to" value={pathname.startsWith("/admin/users/") ? "/admin/users" : pathname} />
      <label className="sr-only" htmlFor="tenant-switcher">
        Tenant
      </label>
      <select
        id="tenant-switcher"
        name="tenant"
        defaultValue={current}
        onChange={() => form.current?.requestSubmit()}
        className="input max-w-64 py-1"
      >
        {current === "" && <option value="">Select a tenant…</option>}
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </form>
  );
}
