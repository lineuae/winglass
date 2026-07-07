# Fetches the db-ip.com IP-to-Country Lite database (CC BY 4.0) into
# src-tauri/resources/ so the country-code badges work in dev, in release
# builds, and in the packaged installers. This is the single source of truth
# for the fetch: scripts/setup.ps1 and the release workflow both call it, so
# nobody has to run a download command by hand.
#
# Idempotent: skips the download when the file already exists, unless -Force.

[CmdletBinding()]
param([switch]$Force)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$destDir  = Join-Path $repoRoot "src-tauri/resources"
$dest     = Join-Path $destDir "GeoLite2-Country.mmdb"

if ((Test-Path $dest) -and -not $Force) {
    Write-Host "   GeoIP database already present - skipping (pass -Force to refresh)" -ForegroundColor DarkGray
    return
}

New-Item -ItemType Directory -Force -Path $destDir | Out-Null

# db-ip publishes one file per calendar month. In the first days of a new month
# the current file can 404 until they cut it, so fall back to the previous month.
$candidates = @((Get-Date), (Get-Date).AddMonths(-1)) | ForEach-Object { $_.ToString("yyyy-MM") }
$gz = Join-Path $destDir "GeoLite2-Country.mmdb.gz"

$got = $null
foreach ($ym in $candidates) {
    $url = "https://download.db-ip.com/free/dbip-country-lite-$ym.mmdb.gz"
    try {
        Write-Host "   downloading GeoIP database ($ym)" -ForegroundColor Cyan
        Invoke-WebRequest $url -OutFile $gz -UseBasicParsing
        $got = $ym
        break
    } catch {
        Write-Host "   $ym not published yet, trying the previous month" -ForegroundColor DarkGray
    }
}

if (-not $got) {
    throw "could not download the GeoIP database from db-ip.com (tried $($candidates -join ', '))"
}

# The download is a single gzipped .mmdb (a raw gzip stream, not a tar archive),
# so decompress the gzip directly. GZipStream lives in System.dll, present on
# every Win10/11 .NET, and behaves the same under Windows PowerShell 5.1 and pwsh
# -- unlike `tar`, which rejects a bare .gz as an unrecognized archive.
$in = $null; $gzs = $null; $out = $null
try {
    $in  = [System.IO.File]::OpenRead($gz)
    $gzs = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
    $out = [System.IO.File]::Create($dest)
    $gzs.CopyTo($out)
} finally {
    if ($out) { $out.Dispose() }
    if ($gzs) { $gzs.Dispose() }
    if ($in)  { $in.Dispose() }
}
Remove-Item $gz

$size = (Get-Item $dest).Length
if ($size -lt 1MB) {
    throw "decompressed GeoIP database looks wrong ($size bytes)"
}
Write-Host "   GeoIP database ready: $dest ($([math]::Round($size / 1MB, 1)) MB)" -ForegroundColor Green
