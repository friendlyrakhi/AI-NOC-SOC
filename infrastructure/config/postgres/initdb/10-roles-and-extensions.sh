#!/bin/sh
# Runs once, on first initialization of the pgdata volume.
# P0: the application login role (no superuser, no BYPASSRLS) plus pgvector.
# P1 replaces this with app_owner / app_rw / app_worker and RLS (docs/03-data-model.md §2.11).
set -eu

APP_PASSWORD="$(cat /run/secrets/database_password)"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_password="$APP_PASSWORD" <<'SQL'
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE ROLE nocsoc_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
  PASSWORD :'app_password';

REVOKE ALL ON DATABASE nocsoc FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE nocsoc TO nocsoc_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO nocsoc_app;
SQL
