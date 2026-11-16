import { PORTALS, type PortalId } from "@/lib/portals";

const accent: Record<PortalId, string> = {
  noc: "border-t-accent-noc",
  soc: "border-t-accent-soc",
  command: "border-t-accent-command",
  admin: "border-t-accent-admin",
};

export default function Home() {
  return (
    <>
      <div
        role="status"
        className="bg-warning/15 text-warning border-b border-warning/40 px-4 py-1.5 text-center text-sm font-medium"
      >
        SANDBOX — development build with mock data only. No live integrations. Remediation is simulated.
      </div>
      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-12">
        <h1 className="text-2xl font-semibold tracking-tight">AI NOC &amp; SOC Operations Platform</h1>
        <p className="text-muted mt-2">
          Phase 0 foundation. Portals become available as their phases ship.
        </p>
        <ul className="mt-8 grid gap-4 sm:grid-cols-2">
          {PORTALS.map((p) => (
            <li
              key={p.id}
              className={`bg-surface border-border rounded-lg border border-t-4 p-5 ${accent[p.id]}`}
            >
              <h2 className="font-semibold">{p.name}</h2>
              <p className="text-muted mt-1 text-sm">{p.description}</p>
              <p className="text-muted mt-3 font-mono text-xs">Planned: {p.phase}</p>
            </li>
          ))}
        </ul>
      </main>
    </>
  );
}
