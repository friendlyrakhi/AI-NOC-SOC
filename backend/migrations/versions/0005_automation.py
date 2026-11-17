"""P5: action policies, action requests, approvals, playbooks, workflow runs, kill switches.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-16

Guardrails enforced in the schema itself, whatever the application does:
- ``action_requests.execution_mode`` may only be ``dry_run`` or ``simulate`` (SEC-ACT-03).
- An approval by the requester is rejected by a trigger; approvals are append-only and one per
  approver (SEC-ACT-02).
- A published playbook version cannot be edited or deleted (SEC-ACT-04).
- The global kill switch is changed only through a SECURITY DEFINER function.
"""

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

SCHEMA = r"""
CREATE TABLE action_policies (
  tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  action_key            text NOT NULL,
  tier_override         text CHECK (tier_override IN ('T0', 'T1', 'T2', 'T3')),
  allowed               boolean NOT NULL DEFAULT true,
  require_justification boolean NOT NULL DEFAULT false,
  updated_by            uuid,
  updated_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, action_key)
);

CREATE TABLE playbooks (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  key         text NOT NULL CHECK (key ~ '^[a-z0-9][a-z0-9-]{1,60}$'),
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  domain      text NOT NULL CHECK (domain IN ('noc', 'soc', 'joint')),
  description text NOT NULL DEFAULT '',
  created_by  uuid,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, key)
);

CREATE TABLE playbook_versions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  playbook_id  uuid NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
  version      integer NOT NULL CHECK (version >= 1),
  definition   jsonb NOT NULL,
  status       text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'retired')),
  created_by   uuid,
  created_at   timestamptz NOT NULL DEFAULT now(),
  published_by uuid,
  published_at timestamptz,
  UNIQUE (playbook_id, version)
);
CREATE UNIQUE INDEX playbook_one_published ON playbook_versions (playbook_id) WHERE status = 'published';

-- Published or retired versions are frozen: only the published -> retired status change is allowed.
CREATE FUNCTION playbook_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.status <> 'draft' THEN RAISE EXCEPTION 'published playbook versions cannot be deleted' USING ERRCODE = '42501'; END IF;
    RETURN OLD;
  END IF;
  IF OLD.status <> 'draft' THEN
    IF NEW.definition IS DISTINCT FROM OLD.definition OR NEW.version <> OLD.version
       OR NOT (OLD.status = 'published' AND NEW.status = 'retired') THEN
      RAISE EXCEPTION 'published playbook versions are immutable' USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER playbook_version_guard BEFORE UPDATE OR DELETE ON playbook_versions
  FOR EACH ROW EXECUTE FUNCTION playbook_version_guard();

CREATE TABLE workflow_runs (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  playbook_version_id  uuid NOT NULL REFERENCES playbook_versions(id),
  incident_id          uuid REFERENCES incidents(id) ON DELETE SET NULL,
  temporal_workflow_id text,
  mode                 text NOT NULL CHECK (mode IN ('dry_run', 'simulate')),
  status               text NOT NULL DEFAULT 'running'
                       CHECK (status IN ('running', 'succeeded', 'failed', 'cancelled', 'halted')),
  steps                jsonb NOT NULL DEFAULT '{}'::jsonb,
  error                text,
  started_by           uuid,
  started_at           timestamptz NOT NULL DEFAULT now(),
  ended_at             timestamptz
);
CREATE INDEX workflow_runs_list_idx ON workflow_runs (tenant_id, started_at DESC);

CREATE TABLE action_requests (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  incident_id          uuid REFERENCES incidents(id) ON DELETE SET NULL,
  workflow_run_id      uuid REFERENCES workflow_runs(id) ON DELETE SET NULL,
  step_id              text,
  action_key           text NOT NULL,
  connector_id         text NOT NULL,
  instance_id          uuid REFERENCES connector_instances(id) ON DELETE SET NULL,
  target               jsonb NOT NULL DEFAULT '{}'::jsonb,
  params               jsonb NOT NULL DEFAULT '{}'::jsonb,
  tier                 text NOT NULL CHECK (tier IN ('T0', 'T1', 'T2', 'T3')),
  required_approvals   integer NOT NULL CHECK (required_approvals BETWEEN 0 AND 2),
  requested_by_type    text NOT NULL CHECK (requested_by_type IN ('user', 'ai', 'playbook')),
  requested_by         uuid,
  ai_run_id            uuid REFERENCES ai_runs(id) ON DELETE SET NULL,
  justification        text NOT NULL DEFAULT '',
  policy_decision      jsonb NOT NULL,
  -- Guardrail (SEC-ACT-03): no live execution can even be recorded in this build.
  execution_mode       text NOT NULL CHECK (execution_mode IN ('dry_run', 'simulate')),
  status               text NOT NULL CHECK (status IN ('pending_approval', 'approved', 'denied', 'expired', 'executing',
                                                        'succeeded', 'failed', 'cancelled')),
  result               jsonb,
  error                text,
  idempotency_key      text,
  temporal_workflow_id text,
  expires_at           timestamptz,
  executed_at          timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  version              integer NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX action_requests_list_idx ON action_requests (tenant_id, status, created_at DESC);
CREATE INDEX action_requests_incident_idx ON action_requests (incident_id, created_at DESC);

CREATE TABLE approvals (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  action_request_id uuid NOT NULL REFERENCES action_requests(id) ON DELETE CASCADE,
  approver_id       uuid NOT NULL,
  decision          text NOT NULL CHECK (decision IN ('approve', 'deny')),
  comment           text NOT NULL DEFAULT '' CHECK (length(comment) <= 2000),
  step_up_at        timestamptz NOT NULL,
  decided_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (action_request_id, approver_id)
);

-- Self-approval is impossible at the database level (SEC-ACT-02).
CREATE FUNCTION approval_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE requester uuid;
BEGIN
  SELECT requested_by INTO requester FROM action_requests WHERE id = NEW.action_request_id;
  IF requester IS NOT NULL AND requester = NEW.approver_id THEN
    RAISE EXCEPTION 'requesters cannot approve their own action requests' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER approval_guard BEFORE INSERT ON approvals FOR EACH ROW EXECUTE FUNCTION approval_guard();

CREATE TABLE tenant_kill_switches (
  tenant_id  uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  engaged    boolean NOT NULL,
  reason     text NOT NULL DEFAULT '',
  changed_by uuid,
  changed_at timestamptz NOT NULL DEFAULT now()
);

-- Platform-wide switch: one row, readable by everyone, changed only through the function below.
CREATE TABLE global_kill_switch (
  id         integer PRIMARY KEY CHECK (id = 1),
  engaged    boolean NOT NULL DEFAULT false,
  reason     text NOT NULL DEFAULT '',
  changed_by uuid,
  changed_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO global_kill_switch (id) VALUES (1);

CREATE FUNCTION set_global_kill_switch(p_engaged boolean, p_reason text, p_by uuid) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ UPDATE global_kill_switch SET engaged = p_engaged, reason = left(coalesce(p_reason, ''), 500), changed_by = p_by,
          changed_at = now() WHERE id = 1 $$;

-- Engaged for the current tenant (its own switch or the global one).
CREATE FUNCTION kill_switch_engaged() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT coalesce((SELECT engaged FROM global_kill_switch WHERE id = 1), false)
       OR coalesce((SELECT engaged FROM tenant_kill_switches WHERE tenant_id = app_tenant()), false) $$;

-- The workflow service resolves which tenant an action request or run belongs to (never trusted
-- from the caller), then works inside that tenant's RLS context.
CREATE FUNCTION action_request_owner(p_id uuid) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT tenant_id FROM action_requests WHERE id = p_id $$;
CREATE FUNCTION workflow_run_owner(p_id uuid) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT tenant_id FROM workflow_runs WHERE id = p_id $$;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['action_policies', 'playbooks', 'playbook_versions', 'workflow_runs', 'action_requests',
                           'approvals', 'tenant_kill_switches'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_rw ON %I FOR ALL USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant())', t);
  END LOOP;
END $$;

REVOKE ALL ON FUNCTION set_global_kill_switch(boolean, text, uuid), kill_switch_engaged(), action_request_owner(uuid),
  workflow_run_owner(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION set_global_kill_switch(boolean, text, uuid), kill_switch_engaged(), action_request_owner(uuid),
  workflow_run_owner(uuid) TO nocsoc_app;
GRANT SELECT ON global_kill_switch TO nocsoc_app, nocsoc_aggregate;

GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO nocsoc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON action_policies TO nocsoc_app;
GRANT SELECT, INSERT, UPDATE ON playbooks, workflow_runs, action_requests, tenant_kill_switches TO nocsoc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON playbook_versions TO nocsoc_app;
GRANT SELECT, INSERT ON approvals TO nocsoc_app;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SCHEMA)


def downgrade() -> None:
    raise NotImplementedError("use scripts/dev reset in development")
