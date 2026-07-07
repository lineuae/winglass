# winglass dev setup — Windows 10/11.
# Idempotent: safe to re-run. Installs only what's missing.
#
# Usage from a fresh clone:
#   .\scripts\setup.ps1
#
# Requires Windows Package Manager (winget), preinstalled on Win11 and
# available on Win10 via the App Installer package from the Microsoft Store.

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

function Write-Step($msg) { Write-Host ">> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "   $msg"  -ForegroundColor Green }
function Write-Skip($msg) { Write-Host "   $msg"  -ForegroundColor DarkGray }
function Write-Fail($msg) { Write-Host "!! $msg" -ForegroundColor Red }

# --- winget ---------------------------------------------------------------

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Fail "winget not found. Install 'App Installer' from the Microsoft Store, then re-run this script."
    exit 1
}

function Install-Winget($id, $args = @()) {
    winget list --id $id --exact 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Skip "$id already installed"
        return
    }
    Write-Ok "installing $id"
    $winArgs = @(
        "install", "--id", $id, "--exact",
        "--accept-source-agreements", "--accept-package-agreements",
        "--disable-interactivity"
    ) + $args
    & winget @winArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "$id install failed (exit $LASTEXITCODE)"
        exit 1
    }
}

# --- Node.js --------------------------------------------------------------

Write-Step "Node.js LTS"
Install-Winget "OpenJS.NodeJS.LTS"

# --- Rust MSVC toolchain --------------------------------------------------

Write-Step "Rustup (installs rustc + cargo)"
Install-Winget "Rustlang.Rustup"

# Make sure the rustup shim is on PATH for this session.
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path

Write-Step "MSVC as the default Rust toolchain"
& "$env:USERPROFILE\.cargo\bin\rustup.exe" default stable-x86_64-pc-windows-msvc | Out-Null

# --- Visual Studio Build Tools with the C++ workload ----------------------
# Required for link.exe; the tauri + windows-rs graph needs the MSVC linker,
# the GNU/mingw linker cannot handle the export table size.

Write-Step "Visual Studio 2022 Build Tools with C++ workload"
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$hasVctools = $false
if (Test-Path $vswhere) {
    & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $hasVctools = $true }
}
if ($hasVctools) {
    Write-Skip "VC++ Tools already present"
} else {
    Install-Winget "Microsoft.VisualStudio.2022.BuildTools" @(
        "--override",
        "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
    )
}

# --- Front-end deps -------------------------------------------------------

Write-Step "npm install"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot
& npm install
if ($LASTEXITCODE -ne 0) {
    Write-Fail "npm install failed"
    exit 1
}

# --- GeoIP database -------------------------------------------------------
# Fetched here so a fresh clone is ready to run without any manual download.
# Non-fatal: the country-code badges are the only thing that needs it, and
# they degrade to empty if the download can't happen (offline setup, etc.).

Write-Step "GeoIP country database"
try {
    & "$PSScriptRoot\fetch-geoip.ps1"
} catch {
    Write-Skip "GeoIP download skipped ($($_.Exception.Message)). Country badges stay empty; re-run scripts\fetch-geoip.ps1 later. Not fatal."
}

Write-Host ""
Write-Ok "Setup complete."
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  npm run tauri dev     # run with live reload" -ForegroundColor Gray
Write-Host "  npm run tauri build   # produce a release .exe + .msi installer" -ForegroundColor Gray
