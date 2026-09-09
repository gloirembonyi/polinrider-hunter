<#
    polinrider-hunter installer for Windows.

        irm https://gloirembonyi.github.io/polinrider-hunter/install.ps1 | iex

    What it does, in order:
      1. Puts the binary in %LOCALAPPDATA%\Programs\polinrider-hunter and adds
         that directory to your user PATH (no administrator rights).
      2. Runs a full hunt across this machine, cleaning what it finds.
      3. Registers the background guard so it keeps watching after every logon.

    It prefers the prebuilt binary published alongside this script, falls back
    to a GitHub release, and finally to building from source with cargo. If none
    of those is possible it says which, rather than failing quietly.
#>

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Where the binary is fetched from. Override with $env:POLINRIDER_SITE if you
# host it somewhere else.
# ---------------------------------------------------------------------------
$Site = if ($env:POLINRIDER_SITE) { $env:POLINRIDER_SITE.TrimEnd('/') } else { 'https://gloirembonyi.github.io/polinrider-hunter' }

# Set either of these to 1 to stop after installing the binary. Useful in CI, and
# for anyone who wants the tool on PATH without it sweeping or starting a guard.
$SkipHunt  = $env:POLINRIDER_NO_HUNT -eq '1'
$SkipGuard = $env:POLINRIDER_NO_INSTALL -eq '1'
$Repo = if ($env:POLINRIDER_REPO) { $env:POLINRIDER_REPO } else { 'gloirembonyi/polinrider-hunter' }

$Asset      = 'polinrider-hunter-windows-x86_64.exe'
$InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\polinrider-hunter'
$Exe        = Join-Path $InstallDir 'polinrider-hunter.exe'

function Step ($m) { Write-Host "`n$m" -ForegroundColor Cyan }
function Info ($m) { Write-Host "  $m" }
function Ok   ($m) { Write-Host "  $m" -ForegroundColor Green }
function Warn ($m) { Write-Host "  $m" -ForegroundColor Yellow }
function Die  ($m) { Write-Host "`n$m" -ForegroundColor Red; exit 1 }

Write-Host 'polinrider-hunter installer' -ForegroundColor White
New-Item -ItemType Directory -Force $InstallDir | Out-Null

# ---------------------------------------------------------------------------
# 0. Make way for the new binary.
#
# Windows will not let you overwrite a running image. If a guard from an earlier
# install is alive it holds this exact file open, and the download lands on a
# locked path - which surfaces as "Cannot create a file when that file already
# exists" and leaves the old build in charge while the installer claims success.
# Ask it to stop, then verify nothing is still holding the file.
# ---------------------------------------------------------------------------
if ((Test-Path $Exe) -and (Get-Process -Name 'polinrider-hunter' -ErrorAction SilentlyContinue)) {
    Step 'Stopping the running guard'
    # Ask politely first. Output is discarded on purpose: a version old enough
    # not to have `stop` answers with its entire help text, which is noise here.
    try { & $Exe stop *>$null } catch { }
    Get-Process -Name 'polinrider-hunter' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    # Handles close a moment after the process exits.
    $free = $false
    for ($i = 0; $i -lt 20; $i++) {
        try { [IO.File]::Open($Exe, 'Open', 'Write').Dispose(); $free = $true; break }
        catch { Start-Sleep -Milliseconds 250 }
    }
    if ($free) { Ok 'stopped' }
    else { Warn 'it is still holding the program file; the upgrade may fail' }
}

# ---------------------------------------------------------------------------
# 1. Obtain the binary
# ---------------------------------------------------------------------------
Step 'Fetching polinrider-hunter'
$got = $false

# (a) Published next to this script — no toolchain needed.
try {
    $url = "$Site/bin/$Asset"
    Info "trying $url"
    Invoke-WebRequest -Uri $url -OutFile "$Exe.part" -UseBasicParsing -TimeoutSec 180
    # A single-page app would answer 200 with HTML for a missing path, so check
    # that what arrived is actually a PE image rather than an error page.
    $head = [System.IO.File]::ReadAllBytes("$Exe.part") | Select-Object -First 2
    if ($head.Count -eq 2 -and $head[0] -eq 0x4D -and $head[1] -eq 0x5A) {
        # Replace rather than move-over: if the file is somehow still held,
        # renaming it aside works where overwriting does not, and Windows is
        # happy to delete a renamed image once its last handle closes.
        if (Test-Path $Exe) {
            $old = "$Exe.old-$(Get-Random)"
            try { Move-Item $Exe $old -Force; Remove-Item $old -Force -ErrorAction SilentlyContinue }
            catch { Remove-Item $Exe -Force -ErrorAction SilentlyContinue }
        }
        Move-Item "$Exe.part" $Exe -Force
        $got = $true
        Ok "installed to $Exe"
    } else {
        Remove-Item "$Exe.part" -ErrorAction SilentlyContinue
        Warn 'that URL did not return an executable'
    }
} catch {
    Remove-Item "$Exe.part" -ErrorAction SilentlyContinue
    Warn "not published there ($($_.Exception.Message.Split([Environment]::NewLine)[0]))"
}

# (b) A GitHub release, if a repository is configured.
if (-not $got -and $Repo) {
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
                                 -Headers @{ 'User-Agent' = 'polinrider-hunter-installer' } -TimeoutSec 20
        $a = $rel.assets | Where-Object { $_.name -like '*windows*' -and $_.name -like '*.exe' } | Select-Object -First 1
        if ($a) {
            Info "release $($rel.tag_name): $($a.name)"
            Invoke-WebRequest -Uri $a.browser_download_url -OutFile $Exe -UseBasicParsing -TimeoutSec 300
            $got = $true
            Ok "installed to $Exe"
        }
    } catch { Warn 'no usable GitHub release' }
}

# (c) Build it. Zero dependencies, so this needs no package registry.
if (-not $got) {
    Step 'Building from source'
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Die @"
Could not download a binary, and there is no Rust toolchain to build one with.

Install Rust (a few minutes, no admin required):
    winget install Rustlang.Rustup
    # or see https://rustup.rs

Then run this installer again.
"@
    }
    if (-not $Repo) { Die "No prebuilt binary at $Site/bin/$Asset and no `$env:POLINRIDER_REPO to build from." }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Die 'git is required to fetch the source.' }

    $src = Join-Path $env:TEMP "polinrider-hunter-src-$(Get-Random)"
    Info "cloning https://github.com/$Repo"
    & git clone --depth 1 "https://github.com/$Repo.git" $src 2>&1 | Out-Null
    if (-not (Test-Path (Join-Path $src 'Cargo.toml'))) { Die "could not fetch source from https://github.com/$Repo" }

    Info 'cargo build --release (about a minute)'
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
$huntCode = 0
if ($SkipHunt) {
    Step 'Skipping the hunt (POLINRIDER_NO_HUNT=1)'
    Info 'run it yourself with: polinrider-hunter hunt'
} else {
    Step 'Hunting for PolinRider across this machine'
    Info 'this reads every candidate file under your home directory; it prints each'
    Info 'directory as it goes, and runs at background priority'
    & $Exe hunt
    $huntCode = $LASTEXITCODE
}

# ---------------------------------------------------------------------------
# 4. Keep it clean
# ---------------------------------------------------------------------------
if ($SkipGuard) {
    Step 'Skipping the background guard (POLINRIDER_NO_INSTALL=1)'
    Info 'set it up later with: polinrider-hunter install'
} else {
    Step 'Setting up the background guard'
    & $Exe install
}

Write-Host "`nDone." -ForegroundColor Green
Write-Host @"
  polinrider-hunter status            what the guard is doing
  polinrider-hunter hunt              sweep the whole machine again
  polinrider-hunter hunt --drives     include every drive
  polinrider-hunter uninstall         stop the guard, remove the hooks
"@
if ($huntCode -ne 0) {
    Write-Host 'The hunt flagged files it would not clean automatically - see above.' -ForegroundColor Yellow
}
