# Ransomware precursor on a server

Applies to encoded PowerShell from Office macros, shadow-copy deletion and mass file renames.

Signs: EDR detections for encoded PowerShell and vssadmin delete shadows, host-based alerts for many renamed files, and a performance alert on the affected file share. This is a joint NOC and SOC incident.

Steps:
1. Treat as active intrusion. Engage the SOC incident commander.
2. Host isolation is the primary containment; it is a high-impact action and needs two approvals.
3. Preserve evidence: memory capture before reboot if possible.
4. Check backups are intact and offline; do not restore before the root cause is found.
5. Inform the file-services owner about the expected impact.
