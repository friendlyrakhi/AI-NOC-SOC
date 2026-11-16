"""Alembic environment: uses the connection provided by app.db.migrate."""

from alembic import context

connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("Run migrations with `python -m app.db.migrate`, not the alembic CLI.")

context.configure(connection=connection, target_metadata=None, transaction_per_migration=True)
with context.begin_transaction():
    context.run_migrations()
