# ADR-0019: Live-read connectors (P8)

Status: accepted (P8 approved 2026-11-17) · Supersedes: the "sandbox only" constraint of guardrail #1 **for reads only**

## Context

Through P7 every connector ran in `sandbox` mode against an in-process simulator. That was enforced at three layers:
- a database constraint (`connector_instances.mode = 'sandbox'`);
- the connector runner refusing other modes;
- the SDK refusing to build a connector without a runner-supplied transport.

P8 verifies connectors against real vendor systems. The vendors you chose are Prometheus/Alertmanager, ServiceNow, ManageEngine, SolarWinds, Autotask, Securonix, Qualys, Rapid7 and Tenable. Several of these normally run on premises (Prometheus, SolarWinds, ManageEngine), at private addresses.

**Live actions remain disabled.** Guardrail #2 is unchanged: execution modes stay `simulate` and `dry_run`.

## Decision

1. **A new instance mode, `live`, that only reads.** It adds no actions; `assert_execution_allowed` is unchanged. A live instance may be created only when **all** of these hold. Each check sits at a different layer, so no single mistake opens it:
   - **Platform switch.** `NOCSOC_LIVE_READ_ENABLED=true` is an environment setting that the API cannot change. It is accepted only together with `NOCSOC_SECRETS_PROVIDER=openbao` and `NOCSOC_OPENBAO_UNSEAL=shamir`: no live credential without the production-grade secrets provider (the P8 gate).
   - **Connector support.** The connector declares `live_read: true` in its manifest and implements `fetch_live` against the vendor's **real** API. The sandbox simulators use a uniform paging convention; real APIs do not.
   - **Database.** The constraint becomes `mode IN ('sandbox', 'live')`.
   - **Permission.** Creating or switching a live instance needs `connector:manage` plus step-up, and it is audited.
2. **Credentials** live only in OpenBao-wrapped envelopes (Transit), are write-only through the API, and are fetched by the runner over TLS.
3. **Egress.**
   - Public vendors: `https` only, every resolved address must be public, no redirects. DNS is re-checked on every request (T12, unchanged).
   - Private (on-premises) vendors: allowed only for hosts or CIDRs in the operator allow-list `NOCSOC_EGRESS_PRIVATE_ALLOWLIST`, an environment setting.
   - Never allowed, even when listed: loopback, link-local and metadata addresses, and the platform's own service names.
   - Plain `http` only with an explicit `allow_http: true` on an allow-listed private host, and never with credentials.
4. **Unseal: Shamir shares held by the operator.**
   - OpenBao is initialised once by `scripts/openbao.ps1 init`: 3 shares, threshold 2, printed once and never written to disk. The root token is used for the initial configuration and then revoked.
   - After every restart OpenBao stays sealed until the operator enters 2 shares with `scripts/openbao.ps1 unseal`.
   - The dev-grade auto-unseal remains the default for the non-live hardened profile.
5. **Certification.** A connector becomes `live-verified` only after a recorded run against a real endpoint (`connectors/catalog/verification/<id>.md`). The record holds:
   - the date and the vendor product and version;
   - the streams read, record counts, and normalisation results;
   - any differences found.

   No credentials, tenant data or vendor hostnames go in the record. Until then, a live-read-capable connector is `contract-tested`.

## Consequences

- Real telemetry can now enter the platform, through the same validation, normalisation, tenant ownership checks and dead-lettering as sandbox data.
- On-premises tools need a deliberate operator allow-list entry; the default stays public-https-only.
- Live **actions** still need their own design review and approval (guardrail #2).
