"""P7: hardening — MFA-bound sessions, audit anchors, telemetry outbox.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-17

- ``sessions.mfa`` records whether the session was established (or later stepped up) with a
  second factor. Privileged permissions are withheld from sessions without it, which closes the
  "privilege granted mid-session" residual (threat model §7).
- ``audit_heads()`` and ``audit_hash_at()`` let the audit-anchor service read each chain's head
  and re-check earlier anchors without reading any audit content. The anchors themselves live
  outside the database (signed JSON lines on a separate volume), so tail truncation becomes
  detectable (T28).
- ``telemetry_outbox`` makes ClickHouse and OpenSearch event copies at-least-once: rows are
  written in the same transaction as the alerts and delivered after commit; a relay retries what
  could not be delivered (P2/P6 residual).
"""

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

SCHEMA = r"""
-- ---------------------------------------------------------------- MFA-bound sessions
ALTER TABLE sessions ADD COLUMN mfa boolean NOT NULL DEFAULT false;
-- Sessions of users with an authenticator were necessarily established with it.
UPDATE sessions s SET mfa = true
 WHERE EXISTS (SELECT 1 FROM user_credentials c WHERE c.user_id = s.user_id AND c.kind = 'totp');

-- ---------------------------------------------------------------- audit anchors (T28)
CREATE FUNCTION audit_heads() RETURNS TABLE (tenant_id uuid, seq bigint, hash bytea, at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT DISTINCT ON (a.tenant_id) a.tenant_id, a.seq, a.hash, a.at
     FROM audit_log a ORDER BY a.tenant_id, a.seq DESC $$;

CREATE FUNCTION audit_hash_at(p_tenant uuid, p_seq bigint) RETURNS bytea
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT a.hash FROM audit_log a WHERE a.tenant_id IS NOT DISTINCT FROM p_tenant AND a.seq = p_seq $$;

REVOKE ALL ON FUNCTION audit_heads() FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_hash_at(uuid, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_heads() TO nocsoc_worker;
GRANT EXECUTE ON FUNCTION audit_hash_at(uuid, bigint) TO nocsoc_worker;

-- ---------------------------------------------------------------- telemetry outbox
CREATE TABLE telemetry_outbox (
  id          bigserial PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  sinks       text[] NOT NULL CHECK (sinks <@ ARRAY['analytics', 'search']::text[]),
  attempts    integer NOT NULL DEFAULT 0,
  rows        jsonb NOT NULL
);
CREATE INDEX telemetry_outbox_tenant_idx ON telemetry_outbox (tenant_id, id);

ALTER TABLE telemetry_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE telemetry_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rw ON telemetry_outbox FOR ALL
  USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());

GRANT SELECT, INSERT, UPDATE, DELETE ON telemetry_outbox TO nocsoc_worker;
GRANT USAGE ON SEQUENCE telemetry_outbox_id_seq TO nocsoc_worker;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SCHEMA)


def downgrade() -> None:
    raise NotImplementedError("use scripts/dev reset in development")
