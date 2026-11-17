<#
.SYNOPSIS
  Runs the local stack.
.EXAMPLE
  scripts\dev.ps1 up                     # core + stream + ai + workflow + search profiles (P6 default)
  scripts\dev.ps1 up -Profiles core      # without ingestion (lighter: no Redpanda/ClickHouse)
  scripts\dev.ps1 up -Build
  scripts\dev.ps1 status                 # containers + memory use
  scripts\dev.ps1 logs api
  scripts\dev.ps1 down
  scripts\dev.ps1 reset                  # down + DELETE volumes (asks first)
  scripts\dev.ps1 seed                   # create mock MSP/customers/users (writes dev-users.json)
  scripts\dev.ps1 totp msp.admin@acme.example   # current MFA code for a seeded user
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][ValidateSet('up', 'down', 'reset', 'logs', 'status', 'build', 'seed', 'totp', 'migrate')]
    [string]$Command = 'status',
    [Parameter(Position = 1)][string]$Service,
    [string[]]$Profiles = @('core', 'stream', 'ai', 'workflow', 'search'),
    [switch]$Build,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib.ps1"

$root = Get-RepoRoot
if (-not (Test-Path (Join-Path $root '.env')) -or -not (Test-Path (Join-Path $root 'infrastructure\secrets\database_password'))) {
    throw 'Not bootstrapped. Run scripts\bootstrap.ps1 first.'
}

$compose = Get-ComposeArgs
$profileArgs = @()
foreach ($p in $Profiles) { $profileArgs += @('--profile', $p) }
# Teardown and inspection cover every profile, so nothing is left running.
$allProfiles = @('--profile', '*')

switch ($Command) {
    'up' {
        $upArgs = @('up', '-d', '--wait')
        if ($Build) { $upArgs += '--build' }
        Write-Step "starting profiles: $($Profiles -join ', ')"
        Invoke-Checked docker @compose @profileArgs @upArgs
        & docker @compose @allProfiles ps
        Write-Host ''
        Write-Host 'Web:     http://127.0.0.1:3000'
        Write-Host 'API:     http://127.0.0.1:8100/api/v1/docs'
        Write-Host 'Mailpit: http://127.0.0.1:8025'
    }
    'build' { Invoke-Checked docker @compose @profileArgs build }
    'down' { Invoke-Checked docker @compose @allProfiles down }
    'reset' {
        if (-not $Force) {
            $answer = Read-Host 'This deletes ALL local data volumes (Postgres etc.). Type "reset" to continue'
            if ($answer -ne 'reset') { Write-Host 'Cancelled.'; return }
        }
        Invoke-Checked docker @compose @allProfiles down -v --remove-orphans
    }
    'logs' {
        $logArgs = @('logs', '-f', '--tail', '200')
        if ($Service) { $logArgs += $Service }
        & docker @compose @allProfiles @logArgs
    }
    'migrate' { Invoke-Checked docker @compose @profileArgs run --rm -T migrate }
    'seed' {
        $out = Join-Path $root 'infrastructure\secrets\dev-users.json'
        $ErrorActionPreference = 'Continue'
        $json = & docker @compose @profileArgs run --rm -T migrate python -m app.db.seed 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'seed failed; run scripts\dev.ps1 up first' }
        $text = ($json -join "`n")
        if ($text -match '"already_seeded"') {
            # Users added by later phases (e.g. P5 approvers) are created now; merge their credentials.
            $added = @(($text | ConvertFrom-Json).new_users)
            if ($added.Count -gt 0 -and (Test-Path $out)) {
                $existing = Get-Content $out -Raw | ConvertFrom-Json
                $existing.users = @($existing.users) + $added
                [System.IO.File]::WriteAllText($out, ($existing | ConvertTo-Json -Depth 6))
                Write-Step "added $($added.Count) new seed user(s) to $out"
                $added | Select-Object email, tenant, @{n = 'roles'; e = { $_.roles -join ',' } } | Format-Table -AutoSize
            }
            Write-Host 'Already seeded. Credentials are in' $out
            return
        }
        [System.IO.File]::WriteAllText($out, $text)
        Write-Step "seeded; credentials written to $out (git-ignored, mock data only)"
        $users = ($text | ConvertFrom-Json).users
        $users | Select-Object email, tenant, @{n = 'roles'; e = { $_.roles -join ',' } }, @{n = 'mfa'; e = { [bool]$_.totp_secret } } | Format-Table -AutoSize
        Write-Host 'MFA codes: scripts\dev.ps1 totp <email>  (or add the totp_secret to an authenticator app)'
    }
    'totp' {
        if (-not $Service) { throw 'usage: scripts\dev.ps1 totp <email>' }
        Push-Location (Join-Path $root 'backend')
        try { Invoke-Uv run python -m app.tools.totp $Service } finally { Pop-Location }
    }
    'status' {
        & docker @compose @allProfiles ps
        Write-Host ''
        & docker stats --no-stream --format 'table {{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}' `
            $(docker @compose @allProfiles ps -q)
    }
}
