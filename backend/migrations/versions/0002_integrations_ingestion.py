"""P2: connector instances, checkpoints, runs, secrets, alerts, assets, vulnerability findings.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-16

- connector_instances.mode is constrained to 'sandbox' in this build (guardrail #1). Live mode
  needs a later, separately approved migration (P8).
- Ingestion runs as nocsoc_worker (RLS enforced, tenant context per message). Ownership of a
  message is taken from the instance record, never from the message (threat model T10).
- Cross-tenant lookups that the runner, webhook ingress and worker need are narrow
  SECURITY DEFINER functions instead of broad grants.
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

SCHEMA = r"""
-- ---------------------------------------------------------------- secrets (envelope-encrypted)
CREATE TABLE secrets (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  kind       text NOT NULL CHECK (kind IN ('connector_credential', 'webhook_hmac')),
  ciphertext text NOT NULL,
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  rotated_at timestamptz
);
CREATE INDEX secrets_tenant_idx ON secrets (tenant_id);

-- ---------------------------------------------------------------- connectors
CREATE TABLE connector_instances (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  definition_id     text NOT NULL CHECK (definition_id ~ '^[a-z0-9_]+(\.[a-z0-9_]+)?$'),
  name              text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  -- Guardrail: sandbox only in this build (docs/README.md #1).
  mode              text NOT NULL DEFAULT 'sandbox' CHECK (mode = 'sandbox'),
  config            jsonb NOT NULL DEFAULT '{}'::jsonb,
  secret_id         uuid REFERENCES secrets(id) ON DELETE SET NULL,
  webhook_secret_id uuid REFERENCES secrets(id) ON DELETE SET NULL,
  enabled           boolean NOT NULL DEFAULT true,
  sync_requested_at timestamptz,
  status            text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'healthy', 'degraded', 'failing', 'disabled')),
  status_detail     text,
  last_run_at       timestamptz,
  last_success_at   timestamptz,
  last_error_at     timestamptz,
  created_by        uuid,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  version           integer NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, name)
);
CREATE INDEX connector_instances_tenant_idx ON connector_instances (tenant_id, definition_id);

CREATE TABLE connector_checkpoints (
  instance_id uuid NOT NULL REFERENCES connector_instances(id) ON DELETE CASCADE,
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  stream      text NOT NULL,
  cursor      jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (instance_id, stream)
);

CREATE TABLE connector_runs (
  id           bigserial PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  instance_id  uuid NOT NULL REFERENCES connector_instances(id) ON DELETE CASCADE,
  stream       text NOT NULL,
  trigger      text NOT NULL CHECK (trigger IN ('schedule', 'manual', 'scenario', 'webhook')),
  status       text NOT NULL CHECK (status IN ('succeeded', 'failed')),
  records_out  integer NOT NULL DEFAULT 0,
  error_class  text,
  error_detail text,
  started_at   timestamptz NOT NULL,
  finished_at  timestamptz NOT NULL
);
CREATE INDEX connector_runs_instance_idx ON connector_runs (instance_id, id DESC);

-- ---------------------------------------------------------------- assets
CREATE TABLE assets (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  type        text NOT NULL,
  name        text NOT NULL,
  environment text NOT NULL DEFAULT 'unknown',
  criticality integer NOT NULL DEFAULT 3 CHECK (criticality BETWEEN 1 AND 5),
  attributes  jsonb NOT NULL DEFAULT '{}'::jsonb,
  sources     text[] NOT NULL DEFAULT '{}',
  sandbox     boolean NOT NULL DEFAULT true,
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX assets_tenant_idx ON assets (tenant_id, type, name);

CREATE TABLE asset_identifiers (
  tenant_id          uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  asset_id           uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  kind               text NOT NULL,
  value              text NOT NULL,
  source_instance_id uuid,
  first_seen         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, kind, value)
);
CREATE INDEX asset_identifiers_asset_idx ON asset_identifiers (asset_id);

-- ---------------------------------------------------------------- alerts
CREATE FUNCTION severity_rank(s text) RETURNS integer LANGUAGE sql IMMUTABLE AS
$$ SELECT CASE s WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END $$;

CREATE TABLE alerts (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  domain             text NOT NULL CHECK (domain IN ('noc', 'soc')),
  source_instance_id uuid REFERENCES connector_instances(id) ON DELETE SET NULL,
  connector_id       text NOT NULL,
  source_alert_id    text NOT NULL,
  fingerprint        text NOT NULL,
  title              text NOT NULL,
  description        text NOT NULL DEFAULT '',
  severity           text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  status             text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'acknowledged', 'in_progress', 'resolved', 'closed', 'suppressed')),
  category           text NOT NULL DEFAULT '',
  asset_id           uuid REFERENCES assets(id) ON DELETE SET NULL,
  service_hint       text,
  first_seen         timestamptz NOT NULL,
  last_seen          timestamptz NOT NULL,
  occurrence_count   integer NOT NULL DEFAULT 1,
  mitre_techniques   text[] NOT NULL DEFAULT '{}',
  observables        jsonb NOT NULL DEFAULT '[]'::jsonb,
  labels             jsonb NOT NULL DEFAULT '{}'::jsonb,
  raw_ref            text,
  sandbox            boolean NOT NULL DEFAULT true,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  version            integer NOT NULL DEFAULT 1
);
-- One open alert per fingerprint: repeats increment occurrence_count (de-duplication).
CREATE UNIQUE INDEX alerts_open_fingerprint ON alerts (tenant_id, fingerprint) WHERE status NOT IN ('resolved', 'closed');
CREATE INDEX alerts_list_idx ON alerts (tenant_id, domain, last_seen DESC, id);
CREATE INDEX alerts_asset_idx ON alerts (asset_id);

-- ---------------------------------------------------------------- vulnerability findings
CREATE TABLE vuln_findings (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  external_id        text NOT NULL,
  connector_id       text NOT NULL,
  source_instance_id uuid REFERENCES connector_instances(id) ON DELETE SET NULL,
  vuln_id            text NOT NULL,
  title              text NOT NULL,
  severity           text NOT NULL,
  cvss               numeric(3, 1),
  epss               numeric(4, 3),
  kev                boolean NOT NULL DEFAULT false,
  status             text NOT NULL CHECK (status IN ('open', 'fixed', 'accepted')),
  asset_id           uuid REFERENCES assets(id) ON DELETE SET NULL,
  first_found        timestamptz NOT NULL,
  last_found         timestamptz NOT NULL,
  sandbox            boolean NOT NULL DEFAULT true,
  UNIQUE (tenant_id, external_id)
);

-- ---------------------------------------------------------------- ingestion bookkeeping
-- Idempotency ledger: a redelivered raw record is skipped (at-least-once delivery, exactly-once effect).
CREATE TABLE ingest_seen (
  tenant_id  uuid NOT NULL,
  record_key text NOT NULL,
  seen_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, record_key)
);

-- Dead letters may have no trustworthy tenant (e.g. ownership mismatch), so they are written
-- through a SECURITY DEFINER function and read per tenant.
CREATE TABLE ingest_dead_letters (
  id          bigserial PRIMARY KEY,
  tenant_id   uuid,
  instance_id uuid,
  reason      text NOT NULL,
  detail      text NOT NULL DEFAULT '',
  envelope    jsonb,
  at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX dead_letters_instance_idx ON ingest_dead_letters (instance_id, id DESC);

-- ---------------------------------------------------------------- narrow cross-tenant functions
-- Owner of an instance: the worker compares it with the tenant claimed by a message (T10).
CREATE FUNCTION connector_instance_owner(p_instance uuid)
RETURNS TABLE (tenant_id uuid, definition_id text, enabled boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT tenant_id, definition_id, enabled FROM connector_instances WHERE id = p_instance $$;

-- Webhook ingress: unauthenticated request -> instance owner and HMAC secret (encrypted).
CREATE FUNCTION webhook_lookup(p_instance uuid)
RETURNS TABLE (tenant_id uuid, definition_id text, enabled boolean, config jsonb, ciphertext text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT i.tenant_id, i.definition_id, i.enabled, i.config, s.ciphertext
     FROM connector_instances i LEFT JOIN secrets s ON s.id = i.webhook_secret_id
    WHERE i.id = p_instance $$;

-- Runner work list (all tenants). No secrets: credentials are fetched per instance.
CREATE FUNCTION runner_work()
RETURNS TABLE (instance_id uuid, tenant_id uuid, definition_id text, mode text, config jsonb,
               sync_requested_at timestamptz, checkpoints jsonb, last_runs jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT i.id, i.tenant_id, i.definition_id, i.mode, i.config, i.sync_requested_at,
          coalesce((SELECT jsonb_object_agg(c.stream, c.cursor) FROM connector_checkpoints c WHERE c.instance_id = i.id), '{}'::jsonb),
          coalesce((SELECT jsonb_object_agg(r.stream, r.finished_at)
                      FROM (SELECT DISTINCT ON (stream) stream, finished_at FROM connector_runs
                             WHERE instance_id = i.id ORDER BY stream, id DESC) r), '{}'::jsonb)
     FROM connector_instances i
     JOIN tenants t ON t.id = i.tenant_id AND t.status = 'active'
    WHERE i.enabled $$;

CREATE FUNCTION runner_report(p_instance uuid, p_stream text, p_trigger text, p_status text, p_records integer,
                              p_error_class text, p_error_detail text, p_health text, p_cursor jsonb,
                              p_started timestamptz, p_finished timestamptz)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_tenant uuid;
BEGIN
  SELECT tenant_id INTO v_tenant FROM connector_instances WHERE id = p_instance;
  IF v_tenant IS NULL THEN RAISE EXCEPTION 'unknown instance' USING ERRCODE = 'P0002'; END IF;
  INSERT INTO connector_runs (tenant_id, instance_id, stream, trigger, status, records_out, error_class, error_detail, started_at, finished_at)
  VALUES (v_tenant, p_instance, p_stream, p_trigger, p_status, p_records, p_error_class, left(p_error_detail, 1000), p_started, p_finished);
  IF p_cursor IS NOT NULL THEN
    INSERT INTO connector_checkpoints (instance_id, tenant_id, stream, cursor, updated_at)
    VALUES (p_instance, v_tenant, p_stream, p_cursor, now())
    ON CONFLICT (instance_id, stream) DO UPDATE SET cursor = EXCLUDED.cursor, updated_at = now();
  END IF;
  UPDATE connector_instances
     SET status = CASE WHEN enabled THEN p_health ELSE 'disabled' END,
         status_detail = CASE WHEN p_status = 'failed' THEN left(coalesce(p_error_class, '') || ': ' || coalesce(p_error_detail, ''), 500) ELSE NULL END,
         last_run_at = p_finished,
         last_success_at = CASE WHEN p_status = 'succeeded' THEN p_finished ELSE last_success_at END,
         last_error_at = CASE WHEN p_status = 'failed' THEN p_finished ELSE last_error_at END,
         sync_requested_at = CASE WHEN p_trigger = 'manual' THEN NULL ELSE sync_requested_at END
   WHERE id = p_instance;
END $$;

CREATE FUNCTION runner_secret(p_instance uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT s.ciphertext FROM connector_instances i JOIN secrets s ON s.id = i.secret_id WHERE i.id = p_instance $$;

CREATE FUNCTION record_dead_letter(p_tenant uuid, p_instance uuid, p_reason text, p_detail text, p_envelope jsonb)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ INSERT INTO ingest_dead_letters (tenant_id, instance_id, reason, detail, envelope)
   VALUES (p_tenant, p_instance, left(p_reason, 64), left(coalesce(p_detail, ''), 1000), p_envelope) $$;

CREATE FUNCTION ingest_seen_cleanup(p_days integer) RETURNS integer
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ WITH d AS (DELETE FROM ingest_seen WHERE seen_at < now() - make_interval(days => p_days) RETURNING 1) SELECT count(*)::int FROM d $$;

-- ---------------------------------------------------------------- RLS
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;               ALTER TABLE secrets FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_instances ENABLE ROW LEVEL SECURITY;   ALTER TABLE connector_instances FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_checkpoints ENABLE ROW LEVEL SECURITY; ALTER TABLE connector_checkpoints FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_runs ENABLE ROW LEVEL SECURITY;        ALTER TABLE connector_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;                ALTER TABLE assets FORCE ROW LEVEL SECURITY;
ALTER TABLE asset_identifiers ENABLE ROW LEVEL SECURITY;     ALTER TABLE asset_identifiers FORCE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;                ALTER TABLE alerts FORCE ROW LEVEL SECURITY;
ALTER TABLE vuln_findings ENABLE ROW LEVEL SECURITY;         ALTER TABLE vuln_findings FORCE ROW LEVEL SECURITY;
ALTER TABLE ingest_seen ENABLE ROW LEVEL SECURITY;           ALTER TABLE ingest_seen FORCE ROW LEVEL SECURITY;
ALTER TABLE ingest_dead_letters ENABLE ROW LEVEL SECURITY;   ALTER TABLE ingest_dead_letters FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_rw ON secrets FOR ALL USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY tenant_rw ON connector_instances FOR ALL USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY tenant_rw ON connector_checkpoints FOR ALL USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY tenant_rw ON connector_runs FOR ALL USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY tenant_rw ON assets FOR ALL USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY tenant_rw ON asset_identifiers FOR ALL USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY tenant_rw ON alerts FOR ALL USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY tenant_rw ON vuln_findings FOR ALL USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY tenant_rw ON ingest_seen FOR ALL USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());
CREATE POLICY tenant_read ON ingest_dead_letters FOR SELECT USING (tenant_id = app_tenant());

CREATE POLICY aggregate_read ON alerts FOR SELECT TO nocsoc_aggregate USING (tenant_id = ANY (app_tenant_ids()));
CREATE POLICY aggregate_read ON assets FOR SELECT TO nocsoc_aggregate USING (tenant_id = ANY (app_tenant_ids()));
CREATE POLICY aggregate_read ON vuln_findings FOR SELECT TO nocsoc_aggregate USING (tenant_id = ANY (app_tenant_ids()));

-- ---------------------------------------------------------------- grants
REVOKE ALL ON FUNCTION connector_instance_owner(uuid), webhook_lookup(uuid), runner_work(),
  runner_report(uuid, text, text, text, integer, text, text, text, jsonb, timestamptz, timestamptz),
  runner_secret(uuid), record_dead_letter(uuid, uuid, text, text, jsonb), ingest_seen_cleanup(integer),
  severity_rank(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION severity_rank(text) TO nocsoc_app, nocsoc_worker, nocsoc_aggregate;
GRANT EXECUTE ON FUNCTION webhook_lookup(uuid), runner_work(),
  runner_report(uuid, text, text, text, integer, text, text, text, jsonb, timestamptz, timestamptz),
  runner_secret(uuid) TO nocsoc_app;
GRANT EXECUTE ON FUNCTION connector_instance_owner(uuid), record_dead_letter(uuid, uuid, text, text, jsonb),
  ingest_seen_cleanup(integer), app_tenant(), app_user(), app_tenant_ids() TO nocsoc_worker;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO nocsoc_app, nocsoc_worker;

GRANT SELECT, INSERT, UPDATE ON secrets TO nocsoc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON connector_instances TO nocsoc_app;
GRANT SELECT ON connector_checkpoints, connector_runs, ingest_dead_letters TO nocsoc_app;
GRANT SELECT ON assets, asset_identifiers, vuln_findings TO nocsoc_app;
GRANT UPDATE (criticality, environment) ON assets TO nocsoc_app;
GRANT SELECT ON alerts TO nocsoc_app;
GRANT UPDATE (status, updated_at, version) ON alerts TO nocsoc_app;
GRANT SELECT ON alerts, assets, vuln_findings TO nocsoc_aggregate;

GRANT SELECT ON connector_instances TO nocsoc_worker;
GRANT SELECT, INSERT, UPDATE ON assets, asset_identifiers, alerts, vuln_findings TO nocsoc_worker;
GRANT SELECT, INSERT ON ingest_seen TO nocsoc_worker;
GRANT SELECT ON tenants TO nocsoc_worker;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SCHEMA)


def downgrade() -> None:
    raise NotImplementedError("use scripts/dev reset in development")
