"""P3: business services and topology, incidents, correlation, maintenance, suppression, ITSM links.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-16

- Every new table is tenant-scoped with FORCE RLS. Defaults that apply to all tenants (SLA
  targets, built-in correlation rules) live in code, so no table needs NULL-tenant rows.
- ``timeline_entries`` is append-only: no role has UPDATE or DELETE on it.
- Correlation runs as ``nocsoc_worker`` inside the ingest transaction. The app role creates
  and changes incidents for user actions.
"""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

SCHEMA = r"""
-- ---------------------------------------------------------------- services and topology
CREATE TABLE services (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  tier               integer NOT NULL DEFAULT 3 CHECK (tier BETWEEN 1 AND 4),
  owner_team         text,
  aliases            text[] NOT NULL DEFAULT '{}',
  external_ref       text,
  source_instance_id uuid REFERENCES connector_instances(id) ON DELETE SET NULL,
  sandbox            boolean NOT NULL DEFAULT true,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  version            integer NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, name)
);
CREATE INDEX services_aliases_idx ON services USING gin (aliases);

-- member: the asset runs the service. dependency: the service needs it (network, database).
CREATE TABLE service_assets (
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  service_id uuid NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  asset_id   uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  role       text NOT NULL CHECK (role IN ('member', 'dependency')),
  PRIMARY KEY (service_id, asset_id, role)
);
CREATE INDEX service_assets_asset_idx ON service_assets (asset_id);

ALTER TABLE alerts ADD COLUMN service_id uuid REFERENCES services(id) ON DELETE SET NULL;
ALTER TABLE alerts ADD COLUMN suppression_reason text;
ALTER TABLE alerts ADD COLUMN search tsvector
  GENERATED ALWAYS AS (to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(description, '') || ' ' || source_alert_id)) STORED;
CREATE INDEX alerts_search_idx ON alerts USING gin (search);
ALTER TABLE assets ADD COLUMN search tsvector GENERATED ALWAYS AS (to_tsvector('simple', name)) STORED;
CREATE INDEX assets_search_idx ON assets USING gin (search);

-- ---------------------------------------------------------------- incidents
CREATE TABLE incident_counters (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  next      bigint NOT NULL
);

CREATE TABLE incidents (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  number               text NOT NULL,
  domain               text NOT NULL CHECK (domain IN ('noc', 'soc', 'joint')),
  title                text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
  summary              text NOT NULL DEFAULT '',
  severity             text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  priority             text NOT NULL CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
  status               text NOT NULL DEFAULT 'open'
                       CHECK (status IN ('open', 'investigating', 'contained', 'mitigated', 'resolved', 'closed')),
  commander_id         uuid,
  assignee_id          uuid,
  impacted_service_ids uuid[] NOT NULL DEFAULT '{}',
  detected_at          timestamptz NOT NULL,
  acknowledged_at      timestamptz,
  resolved_at          timestamptz,
  closed_at            timestamptz,
  correlation_key      text,
  -- Set when correlation merged this incident into another (it is then closed; excluded from KPIs).
  merged_into_id       uuid REFERENCES incidents(id) ON DELETE SET NULL,
  created_by_type      text NOT NULL CHECK (created_by_type IN ('correlation', 'user')),
  created_by           uuid,
  sandbox              boolean NOT NULL DEFAULT true,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  version              integer NOT NULL DEFAULT 1,
  search               tsvector GENERATED ALWAYS AS (to_tsvector('simple', title || ' ' || summary || ' ' || number)) STORED,
  UNIQUE (tenant_id, number)
);
CREATE INDEX incidents_list_idx ON incidents (tenant_id, status, detected_at DESC);
CREATE INDEX incidents_search_idx ON incidents USING gin (search);

-- An alert belongs to at most one incident.
CREATE TABLE incident_alerts (
  alert_id    uuid PRIMARY KEY REFERENCES alerts(id) ON DELETE CASCADE,
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  added_by    text NOT NULL CHECK (added_by IN ('correlation', 'user')),
  rule_key    text,
  reason      text NOT NULL DEFAULT '',
  added_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incident_alerts_incident_idx ON incident_alerts (incident_id);

-- Append-only: no UPDATE/DELETE grant for any role.
CREATE TABLE timeline_entries (
  id          bigserial PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  kind        text NOT NULL CHECK (kind IN ('created', 'state_change', 'comment', 'alert_added', 'alert_removed',
                                            'escalation', 'assignment', 'task', 'external_sync', 'merge', 'ai_analysis',
                                            'action_requested', 'action_result', 'approval')),
  actor_type  text NOT NULL CHECK (actor_type IN ('user', 'system', 'ai', 'connector')),
  actor_id    uuid,
  body        jsonb NOT NULL DEFAULT '{}'::jsonb,
  at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX timeline_incident_idx ON timeline_entries (incident_id, id);

CREATE TABLE incident_tasks (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  title       text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
  status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'done')),
  assignee_id uuid,
  due_at      timestamptz,
  runbook_ref text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  version     integer NOT NULL DEFAULT 1
);
CREATE INDEX incident_tasks_incident_idx ON incident_tasks (incident_id);

-- ITSM links. last_pushed_state lets inbound sync recognise the echo of its own update.
CREATE TABLE external_tickets (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  incident_id       uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  instance_id       uuid REFERENCES connector_instances(id) ON DELETE SET NULL,
  system            text NOT NULL CHECK (system IN ('servicenow')),
  external_id       text NOT NULL,
  external_number   text NOT NULL,
  external_state    text NOT NULL DEFAULT 'new',
  last_pushed_state text,
  sync_state        text NOT NULL DEFAULT 'synced' CHECK (sync_state IN ('synced', 'error')),
  last_synced_at    timestamptz NOT NULL DEFAULT now(),
  last_sync_origin  text NOT NULL CHECK (last_sync_origin IN ('platform', 'external')),
  UNIQUE (tenant_id, system, external_id),
  UNIQUE (incident_id, system)
);

-- Per-tenant SLA targets (minutes per priority). Without a row the built-in defaults apply.
CREATE TABLE sla_policies (
  tenant_id  uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  name       text NOT NULL DEFAULT 'Custom',
  targets    jsonb NOT NULL,
  updated_by uuid,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Per-tenant overrides of the built-in correlation rules.
CREATE TABLE correlation_overrides (
  tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  rule_key       text NOT NULL,
  enabled        boolean NOT NULL,
  window_minutes integer NOT NULL CHECK (window_minutes BETWEEN 1 AND 1440),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, rule_key)
);

-- ---------------------------------------------------------------- maintenance and suppression
CREATE TABLE maintenance_windows (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title        text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
  asset_ids    uuid[] NOT NULL DEFAULT '{}',
  service_ids  uuid[] NOT NULL DEFAULT '{}',
  starts_at    timestamptz NOT NULL,
  ends_at      timestamptz NOT NULL,
  reason       text NOT NULL DEFAULT '',
  created_by   uuid,
  cancelled_at timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  CHECK (ends_at > starts_at AND ends_at - starts_at <= interval '7 days'),
  CHECK (cardinality(asset_ids) + cardinality(service_ids) > 0)
);
CREATE INDEX maintenance_active_idx ON maintenance_windows (tenant_id, ends_at);

CREATE TABLE suppression_rules (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  match      jsonb NOT NULL,
  reason     text NOT NULL DEFAULT '',
  expires_at timestamptz NOT NULL,
  enabled    boolean NOT NULL DEFAULT true,
  hits       integer NOT NULL DEFAULT 0,
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- RLS
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['services', 'service_assets', 'incident_counters', 'incidents', 'incident_alerts',
                           'timeline_entries', 'incident_tasks', 'external_tickets', 'sla_policies',
                           'correlation_overrides', 'maintenance_windows', 'suppression_rules'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_rw ON %I FOR ALL USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant())', t);
  END LOOP;
END $$;

CREATE POLICY aggregate_read ON incidents FOR SELECT TO nocsoc_aggregate USING (tenant_id = ANY (app_tenant_ids()));
CREATE POLICY aggregate_read ON services FOR SELECT TO nocsoc_aggregate USING (tenant_id = ANY (app_tenant_ids()));

-- ---------------------------------------------------------------- grants
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO nocsoc_app, nocsoc_worker;

GRANT SELECT, INSERT, UPDATE, DELETE ON services, correlation_overrides, suppression_rules, sla_policies TO nocsoc_app;
GRANT SELECT, INSERT, DELETE ON service_assets TO nocsoc_app;
GRANT SELECT, INSERT, UPDATE ON incident_counters, incidents, incident_tasks, external_tickets, maintenance_windows TO nocsoc_app;
GRANT SELECT, INSERT, DELETE ON incident_alerts TO nocsoc_app;
GRANT SELECT, INSERT ON timeline_entries TO nocsoc_app;
GRANT UPDATE (status, suppression_reason, updated_at, version) ON alerts TO nocsoc_app;
GRANT SELECT ON incidents, services TO nocsoc_aggregate;

GRANT SELECT, INSERT, UPDATE ON services, incident_counters, incidents TO nocsoc_worker;
GRANT SELECT, INSERT, DELETE ON service_assets TO nocsoc_worker;
GRANT SELECT, INSERT ON incident_alerts, timeline_entries TO nocsoc_worker;
GRANT UPDATE (incident_id, rule_key, reason) ON incident_alerts TO nocsoc_worker;
GRANT SELECT, UPDATE ON external_tickets TO nocsoc_worker;
GRANT SELECT ON correlation_overrides, maintenance_windows, sla_policies TO nocsoc_worker;
GRANT SELECT, UPDATE (hits) ON suppression_rules TO nocsoc_worker;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SCHEMA)


def downgrade() -> None:
    raise NotImplementedError("use scripts/dev reset in development")
