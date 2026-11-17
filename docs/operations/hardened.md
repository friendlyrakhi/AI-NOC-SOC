# Hardened profile: TLS between services, secure cookies, OpenBao

`scripts\dev.ps1 up -Hardened` (or `scripts/dev.sh up --hardened`) layers `infrastructure/compose/hardened.override.yml` on the normal stack. It addresses NFR-9 and the dev-phase residual risks in threat model §7.

## What changes

| Area | Default stack | Hardened |
|------|---------------|----------|
| Browser | http://127.0.0.1:3000, cookies not `Secure` | https://127.0.0.1:3443 through the Caddy edge, HSTS, `Secure` + `HttpOnly` + `SameSite=Strict` cookies. Port 3000 is closed. |
| Postgres | Plain connections | TLS 1.2+, `pg_hba` allows only `hostssl` from the network. Clients use `sslmode=verify-full` against the platform CA. |
| Valkey | Plain | TLS-only port, verified clients |
| ClickHouse | HTTP 8123 | HTTPS 8443, plain HTTP removed. The native port is used only inside the container. |
| OpenSearch | HTTP inside the `search` network | HTTPS (security plugin HTTP TLS), verified clients |
| API | HTTP | HTTPS (uvicorn TLS). The web BFF, connector runner and workflow worker verify it. Runner credential fetches now travel over TLS (P2 residual). |
| AI gateway | HTTP | HTTPS, verified by the API |
| Secrets at rest | Envelope encryption under a master key file | Envelope encryption with data keys from **OpenBao Transit**. The master key never leaves OpenBao; the API authenticates with AppRole. |

**Not yet TLS** (no credentials or secrets cross these links): Redpanda (raw telemetry, ownership checked on every message), the Temporal dev server (workflow ids and action parameters), the OpenSearch node transport (single node), and the edge-to-web hop inside the `frontend` network.

## Certificates

`scripts\certs.py` creates a dev CA and one RSA-2048 certificate per service in `infrastructure\secrets\tls\`. Leaf certificates last one year; the SAN is the compose service name, plus `localhost` and `127.0.0.1` for the edge. Bootstrap and `up -Hardened` run it automatically.

- **Trust the CA in your browser** to avoid warnings. On Windows:
  ```powershell
  Import-Certificate -FilePath infrastructure\secrets\tls\ca.crt -CertStoreLocation Cert:\CurrentUser\Root
  ```
  Remove it again when done.
- **Rotate the leaf certificates:**
  ```powershell
  python scripts\certs.py --rotate; scripts\dev.ps1 up -Hardened
  ```
- **Replace the CA:** `--new-ca` (clients need the new `ca.crt`).

**Antivirus that inspects TLS** (for example Norton Web/Mail Shield on the development PC) intercepts even `https://127.0.0.1` and re-signs the connection with its own root. If it does not trust the platform CA, it marks the site "untrusted". Either add `ca.crt` to the antivirus's trusted roots or exclude `127.0.0.1:3443`. Container-to-container TLS is not affected. `scripts/verify_hardened.py` runs its HTTPS checks inside the stack for this reason.

The CA key sits next to the certificates in the git-ignored, ACL-restricted secrets folder. This is a dev-grade PKI; production uses an organisational CA or ACME.

## OpenBao

- `openbao` runs OpenBao 2.7 with integrated (Raft) storage, single node, and TLS on the internal `secrets` network. Only the API, the migrate job and the setup job can reach it.
- `openbao-setup` runs on every start. It initialises OpenBao once, unseals it, ensures the Transit key `nocsoc-master` (AES-256-GCM, not exportable), and ensures an AppRole whose policy can only request and unwrap data keys with that key.
  - The AppRole's role id and secret id go to a volume mounted read-only by the API and the migrate job.
- After the stack is up, `dev.ps1 up -Hardened` runs `app.tools.rewrap_secrets`. It re-encrypts every existing local-key secret (connector credentials, webhook secrets, MFA secrets) under OpenBao. The command is idempotent and reports `remaining_v1: 0` when done.
- **Dev-grade unseal.** The unseal key and root token are stored in the `baoinit` volume, which only the setup job mounts, so the stack can unseal itself. Production replaces this with KMS auto-unseal or Shamir shares held by operators. This is a prerequisite of P8.
- **Key rotation:**
  ```bash
  bao write -f transit/keys/nocsoc-master/rotate
  ```
  Run it with the root token. Existing values stay readable, because Transit keeps old key versions for decryption.

## Checks

- `python scripts\check-compose.py` validates the default and the hardened configuration (CI gate `compose`):
  - OpenBao is on an internal network;
  - only the API and migrate job can mount the AppRole volume;
  - only the setup job can mount the init volume;
  - the web app publishes no port and its cookies are `Secure`.
- `python scriptserify_hardened.py` repeats the live verification in a throwaway project (your dev data is untouched) and writes `reports\hardened-verification.json`. The P7 exit review records its results: TLS handshakes, a rejected plain connection, sign-in through the edge, and OpenBao-encrypted secrets.
