import type { ReactNode } from "react";

import { SandboxBanner } from "@/components/sandbox-banner";

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <>
      <SandboxBanner />
      <main className="flex flex-1 items-start justify-center px-4 py-16">
        <div className="w-full max-w-sm">
          <p className="text-muted mb-1 text-xs font-medium tracking-widest uppercase">NOC &amp; SOC Platform</p>
          {children}
        </div>
      </main>
    </>
  );
}
