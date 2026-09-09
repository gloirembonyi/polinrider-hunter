<#
    polinrider-hunter installer for Windows.

    One-liner:

        irm https://raw.githubusercontent.com/OWNER/polinrider-hunter/main/install.ps1 | iex

    What it does, in order:
      1. Puts the binary in %LOCALAPPDATA%\Programs\polinrider-hunter and adds
         that directory to your PATH (user scope - no administrator rights).
      2. Runs a full hunt across this machine, cleaning what it finds.
      3. Registers the background guard so it keeps watching after every logon.

    Prefers a published release binary; falls back to building from source with
    cargo. Set $env:POLINRIDER_REPO to point at a fork.
#>

$ErrorActionPreference = 'Stop'

$Repo    = if ($env:POLINRIDER_REPO) { $env:POLINRIDER_REPO } else { 'OWNER/polinrider-hunter' }
$InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\polinrider-hunter'
$Exe     = Join-Path $InstallDir 'polinrider-hunter.exe'

function Info  ($m) { Write-Host "  $m" }
function Step  ($m) { Write-Host "`n$m" -ForegroundColor Cyan }
function Ok    ($m) { Write-Host "  $m" -ForegroundColor Green }
function Warn  ($m) { Write-Host "  $m" -ForegroundColor Yellow }
function Die   ($m) { Write-Host "`n$m" -ForegroundColor Red; exit 1 }

Write-Host "polinrider-hunter installer" -ForegroundColor White
New-Item -ItemType Directory -Force $InstallDir | Out-Null

# ---------------------------------------------------------------------------
# 1. Obtain a binary
# ---------------------------------------------------------------------------
Step 'Fetching polinrider-hunter'

$got = $false

# Try the newest published release asset first: no toolchain needed.
try {
    $api = "https://api.github.com/repos/$Repo/releases/latest"
    $rel = Invoke-RestMethod -Uri $api -Headers @{ 'User-Agent' = 'polinrider-hunter-installer' } -TimeoutSec 20
    $asset = $rel.assets | Where-Object { $_.name -like '*windows*' -and $_.name -like '*.exe' } | Select-Object -First 1
    if ($asset) {
        Info "release $($rel.tag_name): $($asset.name)"
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $Exe -TimeoutSec 300
        $got = $true
        Ok "installed to $Exe"
    } else {
        Warn 'no Windows binary in the latest release'
    }
} catch {
    Warn "no release available ($($_.Exception.Message.Split([Environment]::NewLine)[0]))"
}

# Otherwise build it. The project has zero dependencies, so this needs only a
# Rust toolchain and no network access to a package registry.
if (-not $got) {
    Step 'Building from source'
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Die @"
Need either a published release or a Rust toolchain, and found neither.

Install Rust (a few minutes, no admin required):
    winget install Rustlang.Rustup
    # or see https://rustup.rs

Then re-run this installer.
"@
    }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Die 'git is required to fetch the source. Install it and re-run.'
    }

    $src = Join-Path $env:TEMP "polinrider-hunter-src-$(Get-Random)"
    Info "cloning https://github.com/$Repo"
    & git clone --depth 1 "https://github.com/$Repo.git" $src 2>&1 | Out-Null
    if (-not (Test-Path (Join-Path $src 'Cargo.toml'))) {
        Die "could not fetch the source from https://github.com/$Repo"
    }

    Info 'cargo build --release (this takes a minute)'
    Push-Location $src
    try {
        & cargo build --release 2>&1 | Where-Object { $_ -match '^error' } | ForEach-Object { Write-Host $_ }
        $built = Join-Path $src 'target\release\polinrider-hunter.exe'
        if (-not (Test-Path $built)) { Die 'build failed' }
        Copy-Item $built $Exe -Force
        Ok "installed to $Exe"
    } finally {
        Pop-Location
        Remove-Item -Recurse -Force $src -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# 2. PATH
# ---------------------------------------------------------------------------
Step 'Adding to PATH'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$InstallDir", 'User')
    Ok 'added (open a new terminal to pick it up)'
} else {
    Info 'already on PATH'
}
$env:Path = "$env:Path;$InstallDir"

# ---------------------------------------------------------------------------
# 3. Clean the machine now
# ---------------------------------------------------------------------------
Step 'Hunting for PolinRider across this machine'
& $Exe hunt
$huntCode = $LASTEXITCODE

# ---------------------------------------------------------------------------
# 4. Keep it clean
# ---------------------------------------------------------------------------
Step 'Setting up the background guard'
& $Exe install

Write-Host "`nDone." -ForegroundColor Green
Write-Host @"
  polinrider-hunter status      what the guard is doing
  polinrider-hunter hunt        sweep the whole machine again
  polinrider-hunter hunt --drives   include every drive
  polinrider-hunter uninstall   stop the guard, remove the hooks
"@
if ($huntCode -ne 0) {
    Write-Host "The hunt flagged files it could not clean automatically - see above." -ForegroundColor Yellow
}
