export function SandboxBanner() {
  return (
    <div
      role="status"
      className="bg-warning/15 text-warning border-warning/40 border-b px-4 py-1.5 text-center text-xs font-medium"
    >
      SANDBOX: development build with mock data only. No live integrations. Remediation is simulated.
    </div>
  );
}
