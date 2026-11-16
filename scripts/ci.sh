#!/usr/bin/env bash
# CI gates (used by .github/workflows/ci.yml). Mirrors scripts/ci.ps1.
# Usage: scripts/ci.sh [gate...]   (no args = all gates)
set -uo pipefail
cd "$(dirname "$0")/.."

GITLEAKS_IMAGE='zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f' # v8.30.1
ALL=(ruff mypy imports bandit pytest pip-audit eslint typecheck vitest npm-audit build compose gitleaks)
gates=("$@"); [[ ${#gates[@]} -gt 0 ]] || gates=("${ALL[@]}")
failed=()

run_gate() {
  case "$1" in
    ruff)      uv run ruff check . && uv run ruff format --check . ;;
    mypy)      uv run mypy ;;
    imports)   uv run lint-imports ;;
    bandit)    uv run bandit -q -c pyproject.toml -r backend/app connectors ai-engine automation ;;
    pytest)    uv run pytest -q ;;
    pip-audit)
      req="$(mktemp)"
      uv export --frozen --no-dev --no-emit-workspace --no-hashes -o "$req" -q &&
        uv run pip-audit --strict -r "$req" --no-deps --disable-pip ;;
    eslint)    pnpm --filter frontend lint ;;
    typecheck) pnpm --filter frontend typecheck ;;
    vitest)    pnpm --filter frontend test ;;
    npm-audit) pnpm audit --prod --audit-level high ;;
    build)     pnpm --filter frontend build ;;
    compose)   python3 scripts/check-compose.py ;;
    gitleaks)
      docker run --rm -v "$PWD:/repo" "$GITLEAKS_IMAGE" dir /repo --no-banner --redact \
        --config /repo/.gitleaks.toml ;;
    *) echo "unknown gate $1"; return 2 ;;
  esac
}

for g in "${gates[@]}"; do
  echo "==> $g"
  if run_gate "$g"; then echo "    passed"; else echo "    FAILED"; failed+=("$g"); fi
done

if [[ ${#failed[@]} -gt 0 ]]; then echo "CI FAILED: ${failed[*]}"; exit 1; fi
echo "CI passed."
