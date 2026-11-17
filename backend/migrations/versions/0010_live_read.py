"""P8: live-read connector instances (ADR-0019).

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-17

``connector_instances.mode`` may now be ``live`` (reads only). Whether a live instance may exist is
decided by the API (platform switch, OpenBao with Shamir unseal, connector support, step-up) and
re-checked by the runner; live actions stay impossible (execution modes are unchanged).

Also fixes a P2 gap found by the P8 tests: deleting an integration removes its encrypted credentials
and webhook secret, but the application role had no DELETE grant on ``secrets`` (the delete
answered 500). Tenant isolation is unchanged: the FORCE RLS policy on ``secrets`` covers DELETE.
"""

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

SCHEMA = r"""
ALTER TABLE connector_instances DROP CONSTRAINT IF EXISTS connector_instances_mode_check;
ALTER TABLE connector_instances ADD CONSTRAINT connector_instances_mode_check CHECK (mode IN ('sandbox', 'live'));

GRANT DELETE ON secrets TO nocsoc_app;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SCHEMA)


def downgrade() -> None:
    raise NotImplementedError("use scripts/dev reset in development")
