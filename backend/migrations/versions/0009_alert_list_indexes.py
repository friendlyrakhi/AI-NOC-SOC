"""P7 performance (NFR-1): indexes for the alert queue's default order.

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-17

The alert list sorts by ``severity_rank(severity), last_seen DESC, id``. At 100k alerts per tenant
that was a full sort of every row for each page (k6 load test). These expression indexes let a page
be read in order and stop after ``LIMIT`` rows, with or without the domain filter the portals use.
"""

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

SCHEMA = r"""
CREATE INDEX alerts_rank_idx ON alerts (tenant_id, severity_rank(severity), last_seen DESC, id);
CREATE INDEX alerts_domain_rank_idx ON alerts (tenant_id, domain, severity_rank(severity), last_seen DESC, id);
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SCHEMA)


def downgrade() -> None:
    raise NotImplementedError("use scripts/dev reset in development")
