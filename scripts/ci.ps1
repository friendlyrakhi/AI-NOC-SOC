<#
.SYNOPSIS
  Runs the same checks as GitHub Actions CI, locally.
.EXAMPLE
  scripts\ci.ps1              # everything
  scripts\ci.ps1 -Skip build  # skip the frontend production build
#>
[CmdletBinding()]
param([string[]]$Skip = @())
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib.ps1"
$root = Get-RepoRoot
Push-Location $root
$failed = @()

function Gate([string]$Name, [scriptblock]$Body) {
    if ($Skip -contains $Name) { Write-Host "--- skip $Name" -ForegroundColor DarkGray; return }
    Write-Step $Name
    try { & $Body; Write-Host "    passed" -ForegroundColor Green }
    catch { Write-Host "    FAILED: $_" -ForegroundColor Red; $script:failed += $Name }
}

# gitleaks v8.30.1, pinned by digest
$gitleaksImage = 'zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f'

try {
    Gate 'ruff'        { Invoke-Uv run ruff check .; Invoke-Uv run ruff format --check . }
    Gate 'mypy'        { Invoke-Uv run mypy }
    Gate 'imports'     { Invoke-Uv run lint-imports }
    Gate 'bandit'      { Invoke-Uv run bandit -q -c pyproject.toml -r backend/app connectors ai-engine automation }
    Gate 'pytest'      { Invoke-Uv run pytest -q }  # includes integration tests (Docker required)
    Gate 'fuzz'        { Invoke-Uv run pytest -q -m fuzz backend/tests/fuzz }  # Schemathesis API fuzzing (P7)
    Gate 'openapi'     { Push-Location backend; try { Invoke-Uv run python -m app.tools.export_openapi --check } finally { Pop-Location } }
    Gate 'pip-audit'   {
        $req = Join-Path $env:TEMP 'nocsoc-requirements.txt'
        Invoke-Uv export --frozen --no-dev --no-emit-workspace --no-hashes -o $req -q
        Invoke-Uv run pip-audit --strict -r $req --no-deps --disable-pip
    }
    Gate 'eslint'      { Invoke-Checked pnpm --filter frontend lint }
    Gate 'typecheck'   { Invoke-Checked pnpm --filter frontend typecheck }
    Gate 'vitest'      { Invoke-Checked pnpm --filter frontend test }
    Gate 'npm-audit'   { Invoke-Checked pnpm audit --prod --audit-level high }
    Gate 'build'       { Invoke-Checked pnpm --filter frontend build }
    Gate 'compose'     {
        Invoke-Checked python scripts/check-compose.py
    }
    Gate 'gitleaks'    {
        Invoke-Checked docker run --rm -v "${root}:/repo" $gitleaksImage dir /repo --no-banner --redact `
            --config /repo/.gitleaks.toml
    }
} finally { Pop-Location }

Write-Host ''
if ($failed.Count -gt 0) { Write-Host "CI FAILED: $($failed -join ', ')" -ForegroundColor Red; exit 1 }
Write-Host 'CI passed.' -ForegroundColor Green
