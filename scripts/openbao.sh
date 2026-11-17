#!/usr/bin/env bash
# POSIX counterpart of openbao.ps1 (P8, ADR-0019). Usage: scripts/openbao.sh init|unseal|status
set -euo pipefail
cd "$(dirname "$0")/.."
compose=(docker compose -f infrastructure/compose/docker-compose.yml -f infrastructure/compose/hardened.override.yml --env-file .env)
job=(--profile core run --rm --no-deps -T openbao-setup python -m app.tools.openbao_setup)
case "${1:-status}" in
  init)
    out=$("${compose[@]}" "${job[@]}" init 2>/dev/null | tail -1)
    echo "OpenBao is initialised, unsealed and configured. The root token was revoked."
    echo "These 3 key shares are shown ONCE. Any 2 unseal OpenBao. Store them separately and offline:"
    python3 -c 'import json,sys; [print(f"  share {i+1}: {s}") for i,s in enumerate(json.loads(sys.argv[1])["shares"])]' "$out" ;;
  unseal)
    read -rsp "Key share 1: " a; echo; read -rsp "Key share 2: " b; echo
    printf '%s\n%s\n' "$a" "$b" | "${compose[@]}" "${job[@]}" unseal ;;
  status)
    "${compose[@]}" exec -T openbao sh -c 'wget -qO- --no-check-certificate "https://127.0.0.1:8200/v1/sys/seal-status"' ;;
  *) echo "usage: scripts/openbao.sh init|unseal|status" >&2; exit 2 ;;
esac
