# ADR-0012: Tooling: uv, pnpm, Node 26, GitHub Actions

- Status: accepted
- Date: 2026-11-16
- Decision ID: D12 (docs/10-decisions-for-approval.md)

## Context
Fast, reproducible builds on Windows and Linux.

## Decision
uv 0.13 workspace (Python 3.12), pnpm 12 workspace, Node 26 (LTS) pinned in `.nvmrc`, GitHub Actions running `scripts/ci.sh`. `scripts/ci.ps1` runs the same gates locally. Images and tools are pinned by digest.

## Alternatives considered
Poetry/npm; Azure DevOps.

## Consequences
TLS-inspecting antivirus needs `system-certs = true` (uv) and the build CA bundle (infrastructure/certs/README.md).
