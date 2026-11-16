<#
.SYNOPSIS
  One-time local setup: generates dev secrets and .env, and installs dependencies.
.DESCRIPTION
  Safe to re-run. Existing secrets are kept unless -RotateSecrets is given. Rotating
  secrets after Postgres has been initialized requires `scripts/dev.ps1 reset`.
#>
[CmdletBinding()]
param(
    [switch]$RotateSecrets,
    [switch]$SkipInstall
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib.ps1"

$root = Get-RepoRoot
$secretsDir = Join-Path $root 'infrastructure\secrets'
New-Item -ItemType Directory -Force $secretsDir | Out-Null

function New-HexSecret([int]$Bytes = 32) {
    $buf = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buf) } finally { $rng.Dispose() }
    return -join ($buf | ForEach-Object { $_.ToString('x2') })
}

foreach ($name in 'postgres_password', 'database_password', 'auth_database_password', 'valkey_password', 'master_key', 'worker_database_password', 'runner_token', 'clickhouse_admin_password', 'clickhouse_ingest_password', 'clickhouse_reader_password', 'ai_gateway_token') {
    $path = Join-Path $secretsDir $name
    if ((Test-Path $path) -and -not $RotateSecrets) {
        Write-Step "secret $name exists (kept)"
        continue
    }
    # UTF-8 without BOM and without a trailing newline.
    [System.IO.File]::WriteAllText($path, (New-HexSecret))
    Write-Step "secret $name generated"
}

# Restrict the secrets folder to the current user (threat model T19).
& icacls $secretsDir /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
Write-Step "secrets folder ACL restricted to $($env:USERNAME)"

# Build-time CA bundle for TLS-inspecting antivirus/proxies (infrastructure/certs/README.md).
# Exports the root certificate this machine actually sees for the package registries.
function Get-ObservedRootCa([string]$HostName) {
    $tcp = New-Object Net.Sockets.TcpClient($HostName, 443)
    try {
        $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ({ $true }))
        $ssl.AuthenticateAsClient($HostName)
        $leaf = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        [void]$chain.Build($leaf)
        return $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
    } finally { $tcp.Close() }
}

$certsDir = Join-Path $root 'infrastructure\certs'
New-Item -ItemType Directory -Force $certsDir | Out-Null
$caFile = Join-Path $certsDir 'extra-ca.pem'
$roots = @{}
foreach ($h in 'pypi.org', 'files.pythonhosted.org', 'registry.npmjs.org') {
    try {
        $c = Get-ObservedRootCa $h
        $roots[$c.Thumbprint] = $c
        Write-Step "registry $h is signed by root: $($c.Subject)"
    } catch {
        Write-Host "    could not inspect TLS for ${h}: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
$pem = foreach ($c in $roots.Values) {
    "# $($c.Subject)"
    '-----BEGIN CERTIFICATE-----'
    [Convert]::ToBase64String($c.RawData, 'InsertLineBreaks')
    '-----END CERTIFICATE-----'
}
[System.IO.File]::WriteAllText($caFile, (($pem -join "`n") -replace "`r", '') + "`n")
Write-Step "build CA bundle written ($($roots.Count) root(s))"

$envFile = Join-Path $root '.env'
if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path $root '.env.example') $envFile
    Write-Step '.env created from .env.example'
} else {
    Write-Step '.env exists (kept)'
}

if (-not $SkipInstall) {
    Push-Location $root
    try {
        Write-Step 'uv sync (Python workspace)'
        Invoke-Uv sync
        Write-Step 'pnpm install (frontend)'
        Invoke-Checked pnpm install --frozen-lockfile
    } finally { Pop-Location }
}

Write-Host ''
Write-Host 'Bootstrap complete. Next: scripts\dev.ps1 up' -ForegroundColor Green
