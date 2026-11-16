"""P1 core: tenants (MSP hierarchy), identity, RBAC, delegations, API keys, audit chain.

Revision ID: 0001
Create Date: 2026-11-16

Security model (docs/03-data-model.md §2.11, ADR-0002, ADR-0016):
- Objects are owned by nocsoc_owner (NOLOGIN, BYPASSRLS; used by migrations and
  SECURITY DEFINER functions only).
- nocsoc_app (API, RLS enforced) gets the minimum grants listed at the bottom.
- nocsoc_aggregate (SELECT-only, entered by SET LOCAL ROLE) is used for the MSP
  "All customers" read-only view.
- nocsoc_auth (BYPASSRLS) is restricted to identity tables.
- Every tenant-owned table has ENABLE + FORCE ROW LEVEL SECURITY. Write policies are
  always restricted to app_tenant().
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

SCHEMA = r"""
-- ---------------------------------------------------------------- context helpers
CREATE FUNCTION app_tenant() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.tenant_id', true), '')::uuid $$;

CREATE FUNCTION app_user() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;

CREATE FUNCTION app_tenant_ids() RETURNS uuid[] LANGUAGE sql STABLE AS
$$ SELECT coalesce(string_to_array(nullif(current_setting('app.tenant_ids', true), ''), ',')::uuid[],
                   '{}'::uuid[]) $$;

-- ---------------------------------------------------------------- tenants
CREATE TABLE tenants (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind             text NOT NULL CHECK (kind IN ('msp', 'customer')),
  parent_tenant_id uuid REFERENCES tenants(id),
  slug             citext NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  settings         jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  version          integer NOT NULL DEFAULT 1,
  CONSTRAINT tenant_hierarchy CHECK (
    (kind = 'msp' AND parent_tenant_id IS NULL) OR
    (kind = 'customer' AND parent_tenant_id IS NOT NULL))
);
CREATE INDEX tenants_parent_idx ON tenants (parent_tenant_id);

CREATE FUNCTION tenants_parent_check() RETURNS trigger LANGUAGE plpgsql
SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.kind = 'customer' AND
     (SELECT kind FROM tenants WHERE id = NEW.parent_tenant_id) IS DISTINCT FROM 'msp' THEN
    RAISE EXCEPTION 'customer tenant parent must be an MSP tenant' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER tenants_parent_check BEFORE INSERT OR UPDATE OF kind, parent_tenant_id
  ON tenants FOR EACH ROW EXECUTE FUNCTION tenants_parent_check();

-- Parent (MSP) of the current tenant. SECURITY DEFINER avoids a recursive tenants policy.
CREATE FUNCTION app_parent_tenant() RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS
$$ SELECT parent_tenant_id FROM tenants WHERE id = app_tenant() $$;

-- ---------------------------------------------------------------- identity
CREATE TABLE users (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email             citext NOT NULL UNIQUE CHECK (length(email) <= 320),
  display_name      text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  status            text NOT NULL DEFAULT 'invited' CHECK (status IN ('invited', 'active', 'disabled')),
  is_platform_admin boolean NOT NULL DEFAULT false,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  last_login_at     timestamptz
);

CREATE TABLE user_credentials (
  user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind           text NOT NULL CHECK (kind IN ('password', 'totp')),
  secret         text NOT NULL,
  last_used_step bigint,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, kind)
);

CREATE TABLE sessions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash       bytea NOT NULL UNIQUE,
  user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  active_tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL,
  aggregate        boolean NOT NULL DEFAULT false,
  step_up_at       timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  last_seen_at     timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  revoked_at       timestamptz,
  ip               inet,
  user_agent       text
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE auth_challenges (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash     bytea NOT NULL UNIQUE,
  user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose        text NOT NULL CHECK (purpose IN ('mfa', 'mfa_enroll')),
  pending_secret text,
  attempts       integer NOT NULL DEFAULT 0,
  expires_at     timestamptz NOT NULL,
  used_at        timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, user_id)
);
CREATE INDEX memberships_user_idx ON memberships (user_id);

CREATE TABLE invitations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  bytea NOT NULL UNIQUE,
  expires_at  timestamptz NOT NULL,
  accepted_at timestamptz,
  created_by  uuid,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- RBAC
CREATE TABLE permissions (
  key         text PRIMARY KEY,
  description text NOT NULL,
  privileged  boolean NOT NULL DEFAULT false
);

CREATE TABLE roles (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid REFERENCES tenants(id) ON DELETE CASCADE,
  key         text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]{1,62}$'),
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  description text NOT NULL DEFAULT '',
  is_system   boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  version     integer NOT NULL DEFAULT 1,
  CONSTRAINT roles_system_global CHECK (is_system = (tenant_id IS NULL)),
  UNIQUE NULLS NOT DISTINCT (tenant_id, key)
);

CREATE TABLE role_permissions (
  role_id        uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_key text NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_key)
);

CREATE TABLE role_bindings (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  membership_id uuid NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,
  role_id       uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  created_by    uuid,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (membership_id, role_id)
);
CREATE INDEX role_bindings_tenant_idx ON role_bindings (tenant_id);

CREATE FUNCTION role_bindings_check() RETURNS trigger LANGUAGE plpgsql
SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF (SELECT tenant_id FROM memberships WHERE id = NEW.membership_id) IS DISTINCT FROM NEW.tenant_id THEN
    RAISE EXCEPTION 'role binding tenant does not match membership' USING ERRCODE = '23514';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM roles r WHERE r.id = NEW.role_id
                 AND (r.tenant_id IS NULL OR r.tenant_id = NEW.tenant_id)) THEN
    RAISE EXCEPTION 'role does not belong to tenant' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER role_bindings_check BEFORE INSERT OR UPDATE ON role_bindings
  FOR EACH ROW EXECUTE FUNCTION role_bindings_check();

-- ---------------------------------------------------------------- MSP delegations
CREATE TABLE delegations (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  msp_tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  customer_tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  msp_role_id        uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  customer_role_id   uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  aggregate_read     boolean NOT NULL DEFAULT false,
  expires_at         timestamptz,
  created_by         uuid,
  created_at         timestamptz NOT NULL DEFAULT now(),
  revoked_at         timestamptz,
  revoked_by         uuid,
  CHECK (msp_tenant_id <> customer_tenant_id)
);
CREATE INDEX delegations_msp_idx ON delegations (msp_tenant_id);
CREATE INDEX delegations_customer_idx ON delegations (customer_tenant_id);

CREATE FUNCTION delegations_check() RETURNS trigger LANGUAGE plpgsql
SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF (SELECT parent_tenant_id FROM tenants WHERE id = NEW.customer_tenant_id) IS DISTINCT FROM NEW.msp_tenant_id THEN
    RAISE EXCEPTION 'customer is not managed by this MSP' USING ERRCODE = '23514';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM roles WHERE id = NEW.customer_role_id AND is_system) THEN
    RAISE EXCEPTION 'customer role must be a system role' USING ERRCODE = '23514';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM roles WHERE id = NEW.msp_role_id
                 AND (tenant_id IS NULL OR tenant_id = NEW.msp_tenant_id)) THEN
    RAISE EXCEPTION 'MSP role does not belong to the MSP tenant' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delegations_check BEFORE INSERT ON delegations
  FOR EACH ROW EXECUTE FUNCTION delegations_check();

-- ---------------------------------------------------------------- API keys
CREATE TABLE api_keys (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  prefix       text NOT NULL,
  key_hash     bytea NOT NULL UNIQUE,
  permissions  text[] NOT NULL,
  expires_at   timestamptz NOT NULL,
  last_used_at timestamptz,
  revoked_at   timestamptz,
  created_by   uuid NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX api_keys_tenant_idx ON api_keys (tenant_id);

-- ---------------------------------------------------------------- audit (hash chain per tenant)
CREATE TABLE audit_log (
  id            bigserial PRIMARY KEY,
  tenant_id     uuid,
  seq           bigint NOT NULL,
  at            timestamptz NOT NULL,
  actor_type    text NOT NULL CHECK (actor_type IN ('user', 'api_key', 'system', 'anonymous')),
  actor_id      uuid,
  actor_ip      inet,
  via_tenant_id uuid,
  action        text NOT NULL,
  target_type   text,
  target_id     text,
  outcome       text NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
  details       jsonb NOT NULL DEFAULT '{}'::jsonb,
  trace_id      text,
  prev_hash     bytea,
  hash          bytea NOT NULL,
  UNIQUE NULLS NOT DISTINCT (tenant_id, seq)
);
CREATE INDEX audit_log_tenant_at_idx ON audit_log (tenant_id, at DESC);

CREATE FUNCTION audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only' USING ERRCODE = '42501';
END $$;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_immutable();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_immutable();

CREATE FUNCTION audit_hash(p_prev bytea, p_tenant uuid, p_seq bigint, p_at timestamptz,
  p_actor_type text, p_actor_id uuid, p_actor_ip inet, p_via uuid, p_action text,
  p_target_type text, p_target_id text, p_outcome text, p_details jsonb, p_trace text)
RETURNS bytea LANGUAGE sql STABLE SET TimeZone = 'UTC' AS $$
  SELECT sha256(coalesce(p_prev, '\x'::bytea) || convert_to(jsonb_build_object(
    'tenant_id', p_tenant, 'seq', p_seq, 'at', p_at, 'actor_type', p_actor_type,
    'actor_id', p_actor_id, 'actor_ip', host(p_actor_ip), 'via_tenant_id', p_via,
    'action', p_action, 'target_type', p_target_type, 'target_id', p_target_id,
    'outcome', p_outcome, 'details', p_details, 'trace_id', p_trace)::text, 'UTF8'))
$$;

-- Must never return NULL: every comparison is wrapped in coalesce(..., false), because
-- IF NOT NULL does not raise in PL/pgSQL (an unset setting would otherwise grant access).
CREATE FUNCTION audit_caller_may_access(p_tenant uuid, p_allow_mirror boolean) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT coalesce(session_user = 'nocsoc_auth', false)
      OR coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = session_user), false)
      OR coalesce(p_tenant = app_tenant(), false)
      OR coalesce(p_allow_mirror
                  AND p_tenant = nullif(current_setting('app.audit_mirror_tenant_id', true), '')::uuid, false)
$$;

CREATE FUNCTION audit_append(p_tenant uuid, p_actor_type text, p_actor_id uuid, p_actor_ip inet,
  p_via_tenant uuid, p_action text, p_target_type text, p_target_id text, p_outcome text,
  p_details jsonb, p_trace_id text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET TimeZone = 'UTC' AS $$
DECLARE
  v_prev bytea; v_seq bigint; v_id bigint;
  v_at timestamptz := date_trunc('milliseconds', clock_timestamp());
  v_details jsonb := coalesce(p_details, '{}'::jsonb);
BEGIN
  IF NOT coalesce(audit_caller_may_access(p_tenant, true), false) THEN
    RAISE EXCEPTION 'audit_append: tenant is not in the current context' USING ERRCODE = '42501';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('audit:' || coalesce(p_tenant::text, 'platform'), 0));
  SELECT a.seq, a.hash INTO v_seq, v_prev FROM audit_log a
   WHERE a.tenant_id IS NOT DISTINCT FROM p_tenant ORDER BY a.seq DESC LIMIT 1;
  v_seq := coalesce(v_seq, 0) + 1;
  INSERT INTO audit_log (tenant_id, seq, at, actor_type, actor_id, actor_ip, via_tenant_id, action,
                         target_type, target_id, outcome, details, trace_id, prev_hash, hash)
  VALUES (p_tenant, v_seq, v_at, p_actor_type, p_actor_id, p_actor_ip, p_via_tenant, p_action,
          p_target_type, p_target_id, p_outcome, v_details, p_trace_id, v_prev,
          audit_hash(v_prev, p_tenant, v_seq, v_at, p_actor_type, p_actor_id, p_actor_ip, p_via_tenant,
                     p_action, p_target_type, p_target_id, p_outcome, v_details, p_trace_id))
  RETURNING id INTO v_id;
  RETURN v_id;
END $$;

CREATE FUNCTION audit_verify(p_tenant uuid)
RETURNS TABLE (ok boolean, checked bigint, first_bad_seq bigint, reason text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public SET TimeZone = 'UTC' AS $$
DECLARE r audit_log%ROWTYPE; v_prev bytea; v_expected bigint := 1; v_count bigint := 0;
BEGIN
  IF NOT coalesce(audit_caller_may_access(p_tenant, false), false) THEN
    RAISE EXCEPTION 'audit_verify: tenant is not in the current context' USING ERRCODE = '42501';
  END IF;
  FOR r IN SELECT * FROM audit_log WHERE tenant_id IS NOT DISTINCT FROM p_tenant ORDER BY seq LOOP
    v_count := v_count + 1;
    IF r.seq <> v_expected THEN
      RETURN QUERY SELECT false, v_count, v_expected, 'missing entry (sequence gap)'; RETURN;
    END IF;
    IF r.prev_hash IS DISTINCT FROM v_prev THEN
      RETURN QUERY SELECT false, v_count, r.seq, 'previous-hash link broken'; RETURN;
    END IF;
    IF r.hash <> audit_hash(r.prev_hash, r.tenant_id, r.seq, r.at, r.actor_type, r.actor_id,
                            r.actor_ip, r.via_tenant_id, r.action, r.target_type, r.target_id,
                            r.outcome, r.details, r.trace_id) THEN
      RETURN QUERY SELECT false, v_count, r.seq, 'entry content modified'; RETURN;
    END IF;
    v_prev := r.hash; v_expected := v_expected + 1;
  END LOOP;
  RETURN QUERY SELECT true, v_count, NULL::bigint, NULL::text;
END $$;

-- ---------------------------------------------------------------- row level security
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;          ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;            ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE user_credentials ENABLE ROW LEVEL SECURITY; ALTER TABLE user_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;         ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_challenges ENABLE ROW LEVEL SECURITY;  ALTER TABLE auth_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;      ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;      ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;            ALTER TABLE roles FORCE ROW LEVEL SECURITY;
ALTER TABLE role_permissions ENABLE ROW LEVEL SECURITY; ALTER TABLE role_permissions FORCE ROW LEVEL SECURITY;
ALTER TABLE role_bindings ENABLE ROW LEVEL SECURITY;    ALTER TABLE role_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE delegations ENABLE ROW LEVEL SECURITY;      ALTER TABLE delegations FORCE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;         ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;        ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
-- user_credentials, sessions, auth_challenges, invitations: no policies, so only BYPASSRLS
-- roles (nocsoc_auth, owner) can touch them.

-- tenants: own tenant, plus an MSP's customers
-- own tenant, an MSP's customers, and a customer's MSP (name only matters; RLS is row-level)
CREATE POLICY tenants_select ON tenants FOR SELECT USING (
  id = app_tenant() OR parent_tenant_id = app_tenant() OR id = app_parent_tenant());
CREATE POLICY tenants_insert ON tenants FOR INSERT WITH CHECK (kind = 'customer' AND parent_tenant_id = app_tenant());
CREATE POLICY tenants_update ON tenants FOR UPDATE USING (id = app_tenant()) WITH CHECK (id = app_tenant());
CREATE POLICY tenants_aggregate ON tenants FOR SELECT TO nocsoc_aggregate USING (id = ANY (app_tenant_ids()));

-- users: members of the current tenant, and yourself
CREATE POLICY users_select ON users FOR SELECT USING (
  id = app_user() OR id IN (SELECT m.user_id FROM memberships m WHERE m.tenant_id = app_tenant()));

-- memberships: current tenant (read/write); your own memberships (read)
CREATE POLICY memberships_select ON memberships FOR SELECT USING (tenant_id = app_tenant() OR user_id = app_user());
CREATE POLICY memberships_update ON memberships FOR UPDATE USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY memberships_delete ON memberships FOR DELETE USING (tenant_id = app_tenant());

-- roles: system roles readable by all; custom roles only in their tenant
CREATE POLICY roles_select ON roles FOR SELECT USING (tenant_id IS NULL OR tenant_id = app_tenant());
CREATE POLICY roles_insert ON roles FOR INSERT WITH CHECK (tenant_id = app_tenant() AND NOT is_system);
CREATE POLICY roles_update ON roles FOR UPDATE USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant() AND NOT is_system);
CREATE POLICY roles_delete ON roles FOR DELETE USING (tenant_id = app_tenant());

CREATE POLICY role_permissions_select ON role_permissions FOR SELECT USING (
  EXISTS (SELECT 1 FROM roles r WHERE r.id = role_id));
CREATE POLICY role_permissions_insert ON role_permissions FOR INSERT WITH CHECK (
  EXISTS (SELECT 1 FROM roles r WHERE r.id = role_id AND r.tenant_id = app_tenant()));
CREATE POLICY role_permissions_delete ON role_permissions FOR DELETE USING (
  EXISTS (SELECT 1 FROM roles r WHERE r.id = role_id AND r.tenant_id = app_tenant()));

CREATE POLICY role_bindings_select ON role_bindings FOR SELECT USING (tenant_id = app_tenant());
CREATE POLICY role_bindings_insert ON role_bindings FOR INSERT WITH CHECK (tenant_id = app_tenant());
CREATE POLICY role_bindings_delete ON role_bindings FOR DELETE USING (tenant_id = app_tenant());

-- delegations: visible to both sides; created by the MSP; revocable by either side
CREATE POLICY delegations_select ON delegations FOR SELECT USING (
  msp_tenant_id = app_tenant() OR customer_tenant_id = app_tenant());
CREATE POLICY delegations_insert ON delegations FOR INSERT WITH CHECK (msp_tenant_id = app_tenant());
CREATE POLICY delegations_update ON delegations FOR UPDATE
  USING (msp_tenant_id = app_tenant() OR customer_tenant_id = app_tenant())
  WITH CHECK (msp_tenant_id = app_tenant() OR customer_tenant_id = app_tenant());

CREATE POLICY api_keys_select ON api_keys FOR SELECT USING (tenant_id = app_tenant());
CREATE POLICY api_keys_insert ON api_keys FOR INSERT WITH CHECK (tenant_id = app_tenant());
CREATE POLICY api_keys_update ON api_keys FOR UPDATE USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());

CREATE POLICY audit_select ON audit_log FOR SELECT USING (tenant_id = app_tenant());
CREATE POLICY audit_aggregate ON audit_log FOR SELECT TO nocsoc_aggregate USING (tenant_id = ANY (app_tenant_ids()));

-- ---------------------------------------------------------------- grants
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
-- Only our own functions (extension functions such as citext's must stay executable).
REVOKE ALL ON FUNCTION app_tenant(), app_user(), app_tenant_ids(), app_parent_tenant(), tenants_parent_check(),
  role_bindings_check(), delegations_check(), audit_immutable(),
  audit_hash(bytea, uuid, bigint, timestamptz, text, uuid, inet, uuid, text, text, text, text, jsonb, text),
  audit_caller_may_access(uuid, boolean),
  audit_append(uuid, text, uuid, inet, uuid, text, text, text, text, jsonb, text),
  audit_verify(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_tenant(), app_user(), app_tenant_ids(), app_parent_tenant(), audit_caller_may_access(uuid, boolean)
  TO nocsoc_app, nocsoc_auth, nocsoc_aggregate;
GRANT EXECUTE ON FUNCTION audit_append(uuid, text, uuid, inet, uuid, text, text, text, text, jsonb, text),
                          audit_verify(uuid) TO nocsoc_app, nocsoc_auth;

-- nocsoc_app (RLS enforced)
GRANT SELECT ON permissions TO nocsoc_app;
GRANT SELECT, INSERT ON tenants TO nocsoc_app;
GRANT UPDATE (name, settings, updated_at, version) ON tenants TO nocsoc_app;
GRANT SELECT ON users TO nocsoc_app;
GRANT SELECT, DELETE ON memberships TO nocsoc_app;
GRANT UPDATE (status) ON memberships TO nocsoc_app;
GRANT SELECT, INSERT, DELETE ON roles TO nocsoc_app;
GRANT UPDATE (name, description, updated_at, version) ON roles TO nocsoc_app;
GRANT SELECT, INSERT, DELETE ON role_permissions, role_bindings TO nocsoc_app;
GRANT SELECT, INSERT ON delegations TO nocsoc_app;
GRANT UPDATE (revoked_at, revoked_by) ON delegations TO nocsoc_app;
GRANT SELECT, INSERT ON api_keys TO nocsoc_app;
GRANT UPDATE (revoked_at) ON api_keys TO nocsoc_app;
GRANT SELECT ON audit_log TO nocsoc_app;

-- nocsoc_aggregate (read-only MSP view)
GRANT SELECT ON tenants, audit_log TO nocsoc_aggregate;

-- nocsoc_auth (identity; BYPASSRLS so keep grants narrow)
GRANT SELECT ON tenants, permissions, roles, role_permissions, delegations TO nocsoc_auth;
GRANT INSERT ON tenants TO nocsoc_auth;
GRANT SELECT, INSERT, UPDATE ON users, user_credentials, sessions, auth_challenges, invitations TO nocsoc_auth;
GRANT SELECT, INSERT ON memberships, role_bindings TO nocsoc_auth;
GRANT SELECT ON api_keys TO nocsoc_auth;
GRANT UPDATE (last_used_at) ON api_keys TO nocsoc_auth;
GRANT SELECT ON audit_log TO nocsoc_auth;
"""


def upgrade() -> None:
    # Raw driver execute without parameters: no placeholder parsing (the SQL contains %ROWTYPE).
    op.get_bind().connection.driver_connection.execute(SCHEMA)


def downgrade() -> None:
    raise NotImplementedError("P1 schema has no downgrade; use scripts/dev reset in development")
