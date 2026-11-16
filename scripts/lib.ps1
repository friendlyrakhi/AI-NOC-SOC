# Shared helpers for the PowerShell scripts. Compatible with Windows PowerShell 5.1.

function Get-RepoRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

# Runs a native command and throws on a non-zero exit code.
# Deliberately a simple function (no param block) so flags like -q pass through untouched.
function Invoke-Checked {
    $command = $args[0]
    $rest = @($args | Select-Object -Skip 1)
    # PowerShell 5.1 turns native stderr into terminating errors under 'Stop'; tools like
    # uv write progress to stderr, so only the exit code decides success here.
    $ErrorActionPreference = 'Continue'
    & $command @rest 2>&1 | ForEach-Object { Write-Host "$_" }
    if ($LASTEXITCODE -ne 0) {
        throw "'$command $($rest -join ' ')' failed with exit code $LASTEXITCODE"
    }
}

# Finds uv on PATH, or in the per-user pip Scripts folder.
function Get-UvPath {
    $cmd = Get-Command uv -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }
    $candidate = Join-Path $env:APPDATA 'Python\Python312\Scripts\uv.exe'
    if (Test-Path $candidate) { return $candidate }
    throw 'uv not found. Install with: python -m pip install --user uv'
}

function Invoke-Uv {
    $uv = Get-UvPath
    Invoke-Checked $uv @args
}

function Get-ComposeArgs {
    $root = Get-RepoRoot
    return @(
        'compose',
        '-f', (Join-Path $root 'infrastructure\compose\docker-compose.yml'),
        '--env-file', (Join-Path $root '.env')
    )
}
