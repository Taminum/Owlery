# Creates the local development secrets in ./secrets (git-ignored). Existing files are kept.
# Nothing is printed: open the files yourself when you need a value.
#   ./deploy/init-dev-secrets.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dir = Join-Path $root 'secrets'
New-Item -ItemType Directory -Force $dir | Out-Null

function New-RandomBytes([int]$n) {
    $b = New-Object byte[] $n
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return $b
}
function New-UrlToken([int]$n) { return [Convert]::ToBase64String((New-RandomBytes $n)).TrimEnd('=').Replace('+', '-').Replace('/', '_') }

function Write-Secret([string]$name, [string]$value) {
    $path = Join-Path $dir $name
    if (Test-Path $path) { Write-Host "kept    $name"; return }
    [System.IO.File]::WriteAllText($path, $value + "`n", (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "created $name"
}

Write-Secret 'master_key'      ("1:" + [Convert]::ToBase64String((New-RandomBytes 32)))
Write-Secret 'owner_password'  (New-UrlToken 24)
Write-Secret 'mock_home_token' (New-UrlToken 24)
Write-Secret 'mock_work_token' (New-UrlToken 24)
Write-Host "Secrets are in $dir. Back up master_key: without it stored panel tokens cannot be decrypted."
