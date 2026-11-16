# ADR-0017: BFF with opaque server-side sessions and Server Actions

- Status: accepted
- Date: 2026-11-16
- Supersedes parts of: docs/02-architecture.md §6.2 (short-lived JWT between BFF and API; double-submit CSRF token)

## Context
The architecture planned a session cookie at the Next.js BFF, exchanged for a 5-minute JWT on each API call, plus a double-submit CSRF token. Building P1 surfaced simpler options with equal or better security:
- Revocation (logout, delegation revoke, membership removal) must take effect on the next request. JWTs make that hard without a denylist.
- Next.js 16 Server Actions accept POST only and compare `Origin` with `Host` before running.
- Every page in this product is authenticated and per-user, so Next.js Cache Components (prerendered static shells) add complexity and no benefit.

## Decision
1. **Opaque sessions owned by the API.** A login returns a 256-bit random token (`nss_…`). Only its SHA-256 is stored, in `sessions`, with absolute (12 h) and idle (60 min) expiry. The API validates it on every request, so revocation is immediate.
2. **The BFF keeps the token in an `HttpOnly`, `SameSite=Strict` cookie** and forwards it server-side as `Authorization: Bearer`. Browser JavaScript never sees it (an E2E test asserts this). `Secure` is on by default and turned off only for local http (`NOCSOC_COOKIE_SECURE=false` in the dev compose file) until TLS arrives in P7.
3. **All mutations are Server Actions.** CSRF protection = SameSite=Strict + the framework's Origin/Host check + POST-only. No double-submit token.
4. **Cache Components off.** Pages render dynamically.
5. **Step-up** is a session attribute (`step_up_at`, valid 5 minutes, cleared on tenant switch). Sensitive forms carry an authenticator-code field.
6. **API keys** (`nsk_…`) remain for machine access. They can never step up, so step-up-protected endpoints are closed to them.

## Consequences
- One database lookup per API request for session and permission evaluation. Fine at this scale; a short Valkey cache can be added later if needed, and then revocation latency must be revisited.
- JWT remains an option for future service-to-service calls (P2+), not for browser sessions.
- A user who gains a privileged role mid-session cannot step up until they enroll MFA at their next sign-in (login enforces enrollment). Accepted for now.
