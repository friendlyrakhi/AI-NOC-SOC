#!/usr/bin/env bash
# POSIX counterpart of dev.ps1.
# Usage: scripts/dev.sh up [profile...] | down | reset | logs [service] | status | build | migrate | seed | totp <email>
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env && -f infrastructure/secrets/database_password ]] || {
  echo "Not bootstrapped. Run scripts/bootstrap.sh first." >&2; exit 1; }

compose=(docker compose -f infrastructure/compose/docker-compose.yml --env-file .env)
cmd="${1:-status}"; shift || true

profile_args() {
  local p; local -a out=()
  if [[ $# -eq 0 ]]; then set -- core stream; fi  # P2 default; `up core` for a lighter stack
  for p in "$@"; do out+=(--profile "$p"); done
  printf '%s\n' "${out[@]}"
}

case "$cmd" in
  up)
    mapfile -t pargs < <(profile_args "$@")
    "${compose[@]}" "${pargs[@]}" up -d --wait --build
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
  seed)
    out=infrastructure/secrets/dev-users.json
    json=$("${compose[@]}" --profile core run --rm -T migrate python -m app.db.seed 2>/dev/null)
    if grep -q already_seeded <<<"$json"; then echo "Already seeded. Credentials are in $out"; exit 0; fi
    (umask 077; printf '%s
' "$json" > "$out")
    echo "seeded; credentials written to $out (git-ignored, mock data only)" ;;
  totp)   (cd backend && uv run python -m app.tools.totp "${1:?usage: dev.sh totp <email>}") ;;
  *) echo "unknown command: $cmd" >&2; exit 2 ;;
esac
