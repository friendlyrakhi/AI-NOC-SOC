#!/usr/bin/env bash
# POSIX counterpart of dev.ps1.
# Usage: scripts/dev.sh <command> [--hardened] [args]
#   commands: up [profile...] | down | reset | logs [service] | status | build | migrate | seed | totp <email> | verify-audit
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env && -f infrastructure/secrets/database_password ]] || {
  echo "Not bootstrapped. Run scripts/bootstrap.sh first." >&2; exit 1; }

compose=(docker compose -f infrastructure/compose/docker-compose.yml --env-file .env)
cmd="${1:-status}"; shift || true
# P7 hardened profile: TLS between services, secure cookies, OpenBao (docs/operations/hardened.md).
hardened=0
if [[ "${1:-}" == "--hardened" ]]; then
  hardened=1; shift
  compose=(docker compose -f infrastructure/compose/docker-compose.yml -f infrastructure/compose/hardened.override.yml --env-file .env)
  [[ -f infrastructure/secrets/tls/ca.crt ]] || uv run python scripts/certs.py
fi

profile_args() {
  local p; local -a out=()
  if [[ $# -eq 0 ]]; then set -- core stream ai workflow search; fi  # P6 default; `up core` for a lighter stack
  for p in "$@"; do out+=(--profile "$p"); done
  printf '%s\n' "${out[@]}"
}

case "$cmd" in
  up)
    mapfile -t pargs < <(profile_args "$@")
    # The observability profile (P7) turns on OpenTelemetry export in the platform services.
    if [[ " $* " == *" observability "* ]]; then export NOCSOC_OTEL_ENABLED=true; else export NOCSOC_OTEL_ENABLED=false; fi
    if [[ " $* " == *" sso "* ]]; then export NOCSOC_OIDC_ENABLED=true; else export NOCSOC_OIDC_ENABLED=false; fi
    "${compose[@]}" "${pargs[@]}" up -d --wait --build
    if [[ $hardened -eq 1 ]]; then
      echo "==> moving local-key secrets to OpenBao (idempotent)"
      "${compose[@]}" "${pargs[@]}" run --rm -T migrate python -m app.tools.rewrap_secrets
    fi
    "${compose[@]}" --profile '*' ps
    echo "Web: http://127.0.0.1:3000  API: http://127.0.0.1:8100/api/v1/docs  Mailpit: http://127.0.0.1:8025"
    ;;
  build)  mapfile -t pargs < <(profile_args "$@"); "${compose[@]}" "${pargs[@]}" build ;;
  down)   "${compose[@]}" --profile '*' down ;;
  reset)
    read -r -p 'This deletes ALL local data volumes. Type "reset" to continue: ' answer
    [[ "$answer" == "reset" ]] || { echo "Cancelled."; exit 0; }
    "${compose[@]}" --profile '*' down -v --remove-orphans ;;
  logs)   "${compose[@]}" --profile '*' logs -f --tail 200 "$@" ;;
  status)
    "${compose[@]}" --profile '*' ps
    ids=$("${compose[@]}" --profile '*' ps -q)
    [[ -z "$ids" ]] || docker stats --no-stream --format 'table {{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}' $ids ;;
  migrate) "${compose[@]}" --profile core run --rm -T migrate ;;
  verify-audit) "${compose[@]}" --profile tools run --rm -T audit-verify ;;
  seed)
    out=infrastructure/secrets/dev-users.json
    json=$("${compose[@]}" --profile core run --rm -T migrate python -m app.db.seed 2>/dev/null)
    if grep -q already_seeded <<<"$json"; then
      # Merge users added by later phases (e.g. P5 approvers) into the credentials file.
      python3 - "$out" "$json" <<'PY'
import json, sys
path, data = sys.argv[1], json.loads(sys.argv[2])
new = data.get("new_users") or []
if new:
    current = json.load(open(path, encoding="utf-8"))
    current["users"] = current.get("users", []) + new
    json.dump(current, open(path, "w", encoding="utf-8"), indent=2)
    print(f"added {len(new)} new seed user(s) to {path}")
PY
      echo "Already seeded. Credentials are in $out"; exit 0
    fi
    (umask 077; printf '%s
' "$json" > "$out")
    echo "seeded; credentials written to $out (git-ignored, mock data only)" ;;
  totp)   (cd backend && uv run python -m app.tools.totp "${1:?usage: dev.sh totp <email>}") ;;
  *) echo "unknown command: $cmd" >&2; exit 2 ;;
esac
