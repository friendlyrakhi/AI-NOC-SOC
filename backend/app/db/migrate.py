"""Database migration entrypoint: ``python -m app.db.migrate``.

Runs as the Postgres superuser (dev only; the API never holds these credentials):
1. extensions and database roles (idempotent; passwords synced from secret files),
2. Alembic migrations as ``nocsoc_owner`` so that it owns every object,
3. permission catalog and system roles from ``app.core.authz.catalog``.
"""

import logging
from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy import create_engine, text

from app.config import Settings, get_settings
from app.core.authz.catalog import PERMISSIONS, PRIVILEGED, SYSTEM_ROLES

logger = logging.getLogger("app.db.migrate")

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"

OWNER = "nocsoc_owner"
AGGREGATE = "nocsoc_aggregate"


def _secret(value: object, name: str) -> str:
    if value is None:
        raise SystemExit(f"missing secret: {name}")
    return value.get_secret_value()  # type: ignore[attr-defined, no-any-return]


def _conninfo(settings: Settings) -> str:
    return psycopg.conninfo.make_conninfo(
        host=settings.database_host,
        port=settings.database_port,
        dbname=settings.database_name,
        user=settings.postgres_user,
        password=_secret(settings.postgres_password, "postgres_password"),
    )


def ensure_roles(settings: Settings) -> None:
    roles: list[tuple[str, str, str | None]] = [
        (OWNER, "NOLOGIN BYPASSRLS", None),
        (AGGREGATE, "NOLOGIN NOBYPASSRLS", None),
        (
            settings.database_user,
            "LOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE",
            _secret(settings.database_password, "database_password"),
        ),
        (
            settings.auth_database_user,
            "LOGIN BYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE",
            _secret(settings.auth_database_password, "auth_database_password"),
        ),
    ]
    with psycopg.connect(_conninfo(settings), autocommit=True) as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS citext")
        conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        for name, options, password in roles:
            exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (name,)).fetchone()
            ident = sql.Identifier(name)
            if not exists:
                conn.execute(sql.SQL("CREATE ROLE {}").format(ident))
            conn.execute(sql.SQL("ALTER ROLE {} WITH " + options).format(ident))  # options are constants
            if password is not None:
                conn.execute(sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(ident, sql.Literal(password)))
        db = sql.Identifier(settings.database_name)
        conn.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(db))
        conn.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        conn.execute(sql.SQL("GRANT CREATE, USAGE ON SCHEMA public TO {}").format(sql.Identifier(OWNER)))
        for name in (settings.database_user, settings.auth_database_user):
            conn.execute(sql.SQL("GRANT CONNECT, TEMPORARY ON DATABASE {} TO {}").format(db, sql.Identifier(name)))
        for name in (settings.database_user, settings.auth_database_user, AGGREGATE):
            conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(name)))
        # The app may *switch to* the read-only aggregate role, but does not inherit it.
        conn.execute(
            sql.SQL("GRANT {} TO {} WITH INHERIT FALSE, SET TRUE").format(
                sql.Identifier(AGGREGATE), sql.Identifier(settings.database_user)
            )
        )
    logger.info("roles ensured")


def run_alembic(settings: Settings) -> None:
    engine = create_engine(settings.superuser_database_url())
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql(f"SET ROLE {OWNER}")
            cfg = Config(str(ALEMBIC_INI))
            cfg.attributes["connection"] = conn
            command.upgrade(cfg, "head")
    finally:
        engine.dispose()
    logger.info("migrations applied")


def sync_catalog(settings: Settings) -> None:
    engine = create_engine(settings.superuser_database_url())
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql(f"SET ROLE {OWNER}")
            for key, description in PERMISSIONS.items():
                conn.execute(
                    text(
                        "INSERT INTO permissions (key, description, privileged) VALUES (:k, :d, :p) "
                        "ON CONFLICT (key) DO UPDATE SET description = :d, privileged = :p"
                    ),
                    {"k": key, "d": description, "p": key in PRIVILEGED},
                )
            conn.execute(
                text("DELETE FROM permissions WHERE NOT (key = ANY(:keys))"),
                {"keys": list(PERMISSIONS)},
            )
            for role in SYSTEM_ROLES:
                role_id = conn.execute(
                    text(
                        "INSERT INTO roles (tenant_id, key, name, description, is_system) "
                        "VALUES (NULL, :k, :n, :d, true) "
                        "ON CONFLICT (tenant_id, key) DO UPDATE SET name = :n, description = :d "
                        "RETURNING id"
                    ),
                    {"k": role.key, "n": role.name, "d": role.description},
                ).scalar_one()
                conn.execute(text("DELETE FROM role_permissions WHERE role_id = :r"), {"r": role_id})
                for perm in sorted(role.permissions):
                    conn.execute(
                        text("INSERT INTO role_permissions (role_id, permission_key) VALUES (:r, :p)"),
                        {"r": role_id, "p": perm},
                    )
    finally:
        engine.dispose()
    logger.info("catalog synced: %d permissions, %d system roles", len(PERMISSIONS), len(SYSTEM_ROLES))


def migrate(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    ensure_roles(settings)
    run_alembic(settings)
    sync_catalog(settings)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    migrate()
