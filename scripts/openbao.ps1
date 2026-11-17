<#
.SYNOPSIS
  Operator commands for OpenBao with Shamir unseal (P8, ADR-0019). Hardened profile only.
.EXAMPLE
  scripts\openbao.ps1 init     # once: prints 3 key shares (any 2 unseal). Store them apart, offline.
  scripts\openbao.ps1 unseal   # after every restart: enter 2 shares (input is hidden)
  scripts\openbao.ps1 status
.NOTES
  Requires NOCSOC_OPENBAO_UNSEAL=shamir in .env before the first hardened start. The shares are
  printed once and never written to disk; nothing on this machine can unseal OpenBao without them.
#>
[CmdletBinding()]
param([Parameter(Position = 0)][ValidateSet('init', 'unseal', 'status')][string]$Command = 'status')
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib.ps1"
$compose = Get-ComposeArgs -Hardened
$job = @('--profile', 'core', 'run', '--rm', '--no-deps', '-T', 'openbao-setup', 'python', '-m', 'app.tools.openbao_setup')

switch ($Command) {
    'init' {
        $out = (& docker @compose @job init 2>$null) | Select-Object -Last 1
        if ($LASTEXITCODE -ne 0) { throw 'init failed (is OpenBao running and still uninitialised?)' }
        $shares = ($out | ConvertFrom-Json).shares
        Write-Host ''
        Write-Host 'OpenBao is initialised, unsealed and configured. The root token was revoked.' -ForegroundColor Green
        Write-Host 'These 3 key shares are shown ONCE. Any 2 unseal OpenBao. Store them separately and offline:' -ForegroundColor Yellow
        for ($i = 0; $i -lt $shares.Count; $i++) { Write-Host ("  share {0}: {1}" -f ($i + 1), $shares[$i]) }
        Write-Host ''
        Write-Host 'Clear this terminal window after you have stored them.'
    }
    'unseal' {
        $lines = @()
        foreach ($i in 1..2) {
            $secure = Read-Host -AsSecureString "Key share $i"
            $lines += [System.Net.NetworkCredential]::new('', $secure).Password
        }
        ($lines -join "`n") | & docker @compose @job unseal
        if ($LASTEXITCODE -ne 0) { throw 'unseal did not complete' }
    }
    'status' {
        & docker @compose exec -T openbao sh -c 'wget -qO- --no-check-certificate "https://127.0.0.1:8200/v1/sys/seal-status"'
    }
}
