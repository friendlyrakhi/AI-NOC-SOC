"""P7: optional OIDC sign-in (SSO) state.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-17

``oidc_states`` holds the short-lived state of an OIDC sign-in: the state hash, and the nonce and
PKCE verifier encrypted with the secrets provider. Identity table: RLS on with no policies, so only
the identity role (BYPASSRLS) can use it.
"""

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

SCHEMA = r"""
-- ---------------------------------------------------------------- OIDC sign-in state (optional SSO)
CREATE TABLE oidc_states (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  state_hash  bytea NOT NULL UNIQUE,
  secret      text NOT NULL,            -- encrypted {"nonce", "verifier"}, bound to the row id
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE oidc_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_states FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON oidc_states TO nocsoc_auth;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SCHEMA)


def downgrade() -> None:
    raise NotImplementedError("use scripts/dev reset in development")
