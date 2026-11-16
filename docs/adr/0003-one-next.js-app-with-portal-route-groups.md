# ADR-0003: One Next.js app with portal route groups

- Status: accepted
- Date: 2026-11-16
- Decision ID: D3 (docs/10-decisions-for-approval.md)

## Context
Two portals (NOC, SOC) plus Command Center and Admin share auth, design system and Copilot.

## Decision
A single Next.js app (16.x, App Router) with route groups `(noc)`, `(soc)`, `(command)`, `(admin)`, each with its own layout and entitlement.

## Alternatives considered
Separate Next.js apps per portal.

## Consequences
Less duplication. Can be split into multiple deployables (multi-zones) later.
