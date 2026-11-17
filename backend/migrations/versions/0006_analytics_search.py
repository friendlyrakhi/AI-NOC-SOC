"""P6: analytics projection state, reports, hunts, daily AI briefing.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-17

- ``updated_at`` on alerts, incidents, action requests and assets is maintained by triggers, so
  the analytics projector (ClickHouse facts, OpenSearch entity index) sees every change, whichever
  code path made it. Moving an alert between incidents touches the alert too.
- The projector runs as ``nocsoc_worker`` inside each tenant's RLS context; it only learns which
  tenants exist through a SECURITY DEFINER function, and keeps its watermarks per tenant (RLS).
- Reports, saved hunts and hunt runs are tenant tables with FORCE RLS.
"""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

SCHEMA = r"""
-- ---------------------------------------------------------------- change tracking for projection
ALTER TABLE assets ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();

CREATE FUNCTION touch_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END $$;

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON alerts FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER touch_updated_at BEFORE UPDATE ON incidents FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER touch_updated_at BEFORE UPDATE ON action_requests FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER touch_updated_at BEFORE UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- An alert's incident lives in incident_alerts; linking, moving or unlinking it is a change of the alert.
CREATE FUNCTION touch_linked_alert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE alerts SET updated_at = clock_timestamp()
   WHERE id = CASE WHEN TG_OP = 'DELETE' THEN OLD.alert_id ELSE NEW.alert_id END;
  RETURN NULL;
END $$;
CREATE TRIGGER touch_linked_alert AFTER INSERT OR UPDATE OR DELETE ON incident_alerts
  FOR EACH ROW EXECUTE FUNCTION touch_linked_alert();

CREATE INDEX alerts_updated_idx ON alerts (tenant_id, updated_at);
CREATE INDEX incidents_updated_idx ON incidents (tenant_id, updated_at);
CREATE INDEX action_requests_updated_idx ON action_requests (tenant_id, updated_at);
CREATE INDEX assets_updated_idx ON assets (tenant_id, updated_at);

-- One watermark per tenant, stream and sink: an unavailable sink never holds back the other.
CREATE TABLE projection_state (
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  stream     text NOT NULL CHECK (stream IN ('alerts', 'incidents', 'actions', 'assets')),
  sink       text NOT NULL CHECK (sink IN ('facts', 'search')),
  watermark  timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, stream, sink)
);

-- The projector's only cross-tenant knowledge: which tenants to visit.
CREATE FUNCTION projection_tenants() RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT id FROM tenants WHERE status = 'active' ORDER BY id $$;

-- ---------------------------------------------------------------- reports
CREATE TABLE reports (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  kind             text NOT NULL CHECK (kind IN ('kpi_summary', 'incident_register', 'sla_report')),
  domain           text NOT NULL DEFAULT 'all' CHECK (domain IN ('all', 'noc', 'soc')),
  period           text NOT NULL DEFAULT '7d' CHECK (period IN ('24h', '7d', '30d', '90d')),
  created_by       uuid,
  created_at       timestamptz NOT NULL DEFAULT now(),
  last_exported_at timestamptz,
  UNIQUE (tenant_id, name)
);

-- ---------------------------------------------------------------- hunting
CREATE TABLE hunts (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  description text NOT NULL DEFAULT '',
  query       jsonb NOT NULL,
  created_by  uuid,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);

CREATE TABLE hunt_runs (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  hunt_id      uuid REFERENCES hunts(id) ON DELETE SET NULL,
  query        jsonb NOT NULL,
  status       text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
  requested_by uuid,
  created_at   timestamptz NOT NULL DEFAULT now(),
  started_at   timestamptz,
  finished_at  timestamptz,
  hit_count    integer NOT NULL DEFAULT 0,
  truncated    boolean NOT NULL DEFAULT false,
  results      jsonb NOT NULL DEFAULT '[]'::jsonb,
  error        text
);
CREATE INDEX hunt_runs_list_idx ON hunt_runs (tenant_id, created_at DESC);

-- ---------------------------------------------------------------- AI daily briefing
ALTER TABLE ai_runs DROP CONSTRAINT ai_runs_task_check;
ALTER TABLE ai_runs ADD CONSTRAINT ai_runs_task_check CHECK (task IN ('alert_summary', 'incident_summary', 'triage',
  'rca', 'pir_draft', 'query_assist', 'chat', 'daily_briefing'));

-- ---------------------------------------------------------------- RLS and grants
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['projection_state', 'reports', 'hunts', 'hunt_runs'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_rw ON %I FOR ALL USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant())', t);
  END LOOP;
END $$;

REVOKE ALL ON FUNCTION projection_tenants() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION projection_tenants() TO nocsoc_worker;

GRANT SELECT, INSERT, UPDATE ON projection_state TO nocsoc_worker;
GRANT SELECT ON action_requests TO nocsoc_worker;

GRANT SELECT, INSERT, DELETE ON reports TO nocsoc_app;
GRANT UPDATE (last_exported_at) ON reports TO nocsoc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON hunts TO nocsoc_app;
GRANT SELECT, INSERT, UPDATE ON hunt_runs TO nocsoc_app;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SCHEMA)


def downgrade() -> None:
    raise NotImplementedError("use scripts/dev reset in development")
