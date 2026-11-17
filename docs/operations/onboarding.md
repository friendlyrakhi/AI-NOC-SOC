# Onboarding guide: MSPs, customers, users and integrations

How a new MSP, customer or team member gets onto the platform. Everything here works with sandbox connectors and DEMO data. Live vendor connections are not possible before P8.

## 1. Roles in the process

| Who | Signs in as | Can do |
|-----|-------------|--------|
| Platform administrator | `platform.admin@nocsoc.example` (dev) | Create MSP tenants (Admin → Platform). Has no access to tenant data unless invited. |
| MSP administrator | Tenant admin of the MSP tenant | Onboard customers, manage delegations, invite MSP staff |
| Customer administrator | Tenant admin of a customer tenant | Invite their own users, review or revoke the MSP's delegation, manage integrations |

Privileged actions need a session confirmed with the platform authenticator (MFA), and the most sensitive ones ask for a fresh code (step-up). A user who receives a privileged role while signed in must confirm a code or sign in again before using it.

## 2. A new MSP

1. The platform administrator opens **Admin → Platform → Create an MSP tenant** and enters the name, slug and the MSP administrator's e-mail.
2. The MSP administrator receives an invitation (Mailpit at http://127.0.0.1:8025 in dev). They set a password and **enrol an authenticator**, which is mandatory for administrators.
3. The MSP administrator invites staff under **Admin → Users → Invite a member** and assigns roles (NOC analyst, SOC analyst L1/L2, incident commander, approver, executive viewer, ...).

## 3. A new customer (MSP model, ADR-0016)

1. The MSP administrator opens **Admin → Customers → Onboard customer**, which needs a step-up code. In one action it:
   - creates the customer tenant;
   - creates the MSP's delegations (which MSP role acts as which customer role, and whether the customer appears in the read-only "All customers" view);
   - invites the customer's administrator.
2. The customer administrator accepts the invitation and enrols MFA. Under **Admin → Delegations** they can see exactly what the MSP may do, until when, and revoke it at any time. Delegated actions are mirrored into the customer's own audit log.
3. Each tenant's data is isolated by row-level security in Postgres, a row policy in ClickHouse, and per-tenant indices plus a tenant filter in OpenSearch. Nothing has to be configured for this.

## 4. Integrations (sandbox)

1. **Connectors → Add integration** (button **Add in sandbox mode**): pick a connector (16 in the catalog). Fill in its configuration. Credentials are write-only and stored encrypted (local key, or OpenBao in the hardened profile).
2. The connector runner starts pulling from the connector's **simulator**. Webhook-capable connectors show a webhook URL and a secret once. Calls must be HMAC-signed with a timestamp and a single-use nonce.
3. **Connectors → Replay** replays cross-tool stories (core switch failure, phishing and credential misuse, ransomware, ...). Use it to check that alerts, incidents, KPIs and search fill up for the new tenant.
4. Health per integration (last run, errors, dead letters) is on the integration's page. Records that fail validation are dead-lettered with a reason and can be replayed.

## 5. Optional single sign-on (`sso` profile)

`scripts\dev.ps1 up -Profiles core,stream,ai,workflow,search,sso` starts a DEMO Keycloak at http://127.0.0.1:8180. The login page then offers **Sign in with Keycloak (DEMO)**.
- The realm `nocsoc` has two users, `admin@globex.example` and `soc@initech.example`. Their Keycloak password is in `infrastructure/secrets/sso_demo_password`, and Keycloak asks them to set up an authenticator at the first sign-in.
- Signing in at the identity provider does **not** create platform users. The e-mail must belong to an existing, active, invited user, and access still comes from that user's roles.
- Because the realm forces OTP, `NOCSOC_OIDC_IDP_ENFORCES_MFA=true`, so SSO sessions count as MFA sessions. For another identity provider (for example Entra ID):
  - set `NOCSOC_OIDC_ISSUER`, `NOCSOC_OIDC_DISCOVERY_URL`, `NOCSOC_OIDC_CLIENT_ID` and the `oidc_client_secret` secret;
  - set `NOCSOC_OIDC_IDP_ENFORCES_MFA` to true only if the provider really enforces MFA for every sign-in. Otherwise the platform relies on the token's `amr` claim, and withholds privileged permissions without it.
- Step-up confirmations still use the platform authenticator.

## 6. Off-boarding

- **A user leaves.** Admin → Users → the member → **Remove from tenant**. Their sessions and API keys stop working at once.
- **A customer leaves the MSP.** The customer revokes the delegation, or the MSP removes the customer. Data stays in the customer tenant.
- **Deleting a tenant's data.** This is a platform operation (see the [runbook](runbook.md)). Back up first.
