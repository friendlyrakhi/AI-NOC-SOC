#!/usr/bin/env bash
# POSIX counterpart of bootstrap.ps1 (Linux, macOS, CI).
# Usage: scripts/bootstrap.sh [--rotate-secrets] [--skip-install]
set -euo pipefail
cd "$(dirname "$0")/.."

rotate=0; install=1
for arg in "$@"; do
  case "$arg" in
    --rotate-secrets) rotate=1 ;;
    --skip-install) install=0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

umask 077
mkdir -p infrastructure/secrets infrastructure/certs
for name in postgres_password database_password auth_database_password valkey_password master_key worker_database_password runner_token clickhouse_admin_password clickhouse_ingest_password clickhouse_reader_password ai_gateway_token workflow_token audit_anchor_key grafana_admin_password oidc_client_secret sso_demo_password keycloak_admin_password; do
  f="infrastructure/secrets/$name"
  if [[ -f "$f" && $rotate -eq 0 ]]; then
    echo "==> secret $name exists (kept)"
  else
    python3 -c 'import secrets,sys; sys.stdout.write(secrets.token_hex(32))' > "$f"
    echo "==> secret $name generated"
  fi
done
# OpenSearch (P6) insists on upper, lower, digit and special characters; the fixed prefix only
# satisfies that rule, the randomness is the 48 hex characters after it.
for name in opensearch_admin_password opensearch_reader_password opensearch_indexer_password; do
  f="infrastructure/secrets/$name"
  if [[ -f "$f" && $rotate -eq 0 ]]; then
    echo "==> secret $name exists (kept)"
  else
    python3 -c 'import secrets,sys; sys.stdout.write("Os-9" + secrets.token_hex(24))' > "$f"
    echo "==> secret $name generated"
  fi
done

# Build-time CA bundle: empty unless you need one (infrastructure/certs/README.md).
[[ -f infrastructure/certs/extra-ca.pem ]] || : > infrastructure/certs/extra-ca.pem

[[ -f .env ]] || { cp .env.example .env; echo "==> .env created from .env.example"; }

if [[ $install -eq 1 ]]; then
  echo "==> uv sync"; uv sync
  echo "==> pnpm install"; pnpm install --frozen-lockfile
fi
# TLS certificates for the hardened profile (P7). Needs the `cryptography` package (uv sync).
if [[ -x .venv/bin/python ]]; then .venv/bin/python scripts/certs.py
else echo "==> certificates skipped (no Python environment yet): run scripts/certs.py after uv sync"; fi
echo "Bootstrap complete. Next: scripts/dev.sh up"
