<#
.SYNOPSIS
  Checks this machine against the project's requirements. Read-only.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib.ps1"
$root = Get-RepoRoot
$script:problems = 0

function Report([string]$Name, [bool]$Ok, [string]$Detail, [switch]$WarnOnly) {
    if ($Ok) { $tag = '[ ok ]'; $color = 'Green' }
    elseif ($WarnOnly) { $tag = '[warn]'; $color = 'Yellow' }
    else { $tag = '[FAIL]'; $color = 'Red'; $script:problems++ }
    Write-Host ("{0} {1,-22} {2}" -f $tag, $Name, $Detail) -ForegroundColor $color
}

function Get-Version([string]$Exe, [string[]]$VersionArgs) {
    try { return (& $Exe @VersionArgs 2>$null | Select-Object -First 1) } catch { return $null }
}

$node = Get-Version 'node' @('--version')
Report 'node' ($node -match '^v26\.') "$node (expected v26.x, see .nvmrc)"

$py = Get-Version 'python' @('--version')
Report 'python' ($py -match '3\.12\.') "$py (expected 3.12.x)"

try { $uv = Get-UvPath; Report 'uv' $true (Get-Version $uv @('--version')) }
catch { Report 'uv' $false 'missing: python -m pip install --user uv' }

$pnpm = Get-Version 'pnpm' @('--version')
Report 'pnpm' ($null -ne $pnpm) "$pnpm"

$dockerMem = Get-Version 'docker' @('info', '--format', '{{.MemTotal}}')
if ($dockerMem -match '^\d+$' -and [int64]$dockerMem -gt 0) {
    $gb = [math]::Round([int64]$dockerMem / 1GB, 1)
    Report 'docker engine' $true "running, VM memory $gb GB"
    Report 'docker memory' ($gb -ge 6) "$gb GB (>= 6 GB recommended for core+stream+analytics)" -WarnOnly
} else {
    Report 'docker engine' $false 'not reachable; start Docker Desktop'
}

$wslconfig = Join-Path $env:USERPROFILE '.wslconfig'
Report '.wslconfig' (Test-Path $wslconfig) 'optional: cap WSL2 memory, e.g. [wsl2] memory=10GB' -WarnOnly

$free = (Get-PSDrive C).Free / 1GB
Report 'disk C: free' ($free -ge 20) ("{0:N1} GB (>= 20 GB recommended)" -f $free) -WarnOnly

$ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
Report 'host RAM' ($ram -ge 15) ("{0:N1} GB" -f $ram) -WarnOnly

Report 'bootstrapped' ((Test-Path (Join-Path $root '.env')) -and (Test-Path (Join-Path $root 'infrastructure\secrets\database_password'))) 'run scripts\bootstrap.ps1 if FAIL'

foreach ($port in 5432, 6379, 8100, 3000, 8025, 1025) {
    $listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $listener) { Report "port $port" $true 'free' }
    else {
        $proc = (Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        $isOurs = $proc -match 'docker|wslrelay|com.docker'
        Report "port $port" $isOurs "in use by $proc$(if ($isOurs) { ' (probably this stack)' })" -WarnOnly
    }
}

$autocrlf = (& git -C $root config --get core.autocrlf)
Report 'git autocrlf' $true "core.autocrlf=$autocrlf (.gitattributes enforces LF regardless)"

Write-Host ''
if ($script:problems -gt 0) { Write-Host "$script:problems problem(s) found." -ForegroundColor Red; exit 1 }
Write-Host 'Environment looks good.' -ForegroundColor Green
