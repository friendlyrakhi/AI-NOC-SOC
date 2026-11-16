# ADR-0007: Built-in auth first, OIDC later

- Status: accepted
- Date: 2026-11-16
- Decision ID: D7 (docs/10-decisions-for-approval.md)

## Context
Keycloak costs about 1 GB RAM and setup time. Enterprise SSO is not needed for mock-data development.

## Decision
Local accounts (Argon2id), TOTP MFA and BFF sessions in P1. OIDC (Keycloak or Entra ID) in P7.

## Alternatives considered
Keycloak from P1.

## Consequences
Identity code must stay OIDC-ready (no assumptions that passwords exist).
