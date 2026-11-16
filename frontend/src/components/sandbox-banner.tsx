export function SandboxBanner() {
  return (
    <div
      role="status"
      className="bg-caution/15 text-foreground border-caution/50 border-b px-4 py-1.5 text-center text-xs font-medium"
    >
      <span aria-hidden="true">⚠ </span>SANDBOX: development build with mock data only. No live integrations. Remediation is simulated.
    </div>
  );
}
