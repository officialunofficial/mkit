# SPDX-License-Identifier: MIT OR Apache-2.0
#
# mkit installer for native Windows PowerShell — downloads the signed
# `x86_64-pc-windows-msvc` release archive from a public GitHub Release,
# verifies its cosign signature, verifies its SHA256, and installs
# `mkit.exe` atomically into $InstallDir (default: $env:LOCALAPPDATA\mkit\bin).
#
# This is the Windows counterpart to install.sh — same trust model, same
# environment-variable names where a Windows equivalent makes sense, same
# downgrade guard. Git-Bash/MSYS/WSL users can use install.sh directly
# instead; this script is for users running plain `powershell.exe` /
# `pwsh.exe` with no POSIX layer.
#
# Usage:
#   irm https://mkit.sh/install.ps1 | iex
#   iwr -useb https://mkit.sh/install.ps1 | iex
#   $s = iwr -useb https://mkit.sh/install.ps1; ($s.Content) > install.ps1; ./install.ps1 -Version v0.3.0
#   # The raw GitHub URL serves the same script as a fallback:
#   #   https://raw.githubusercontent.com/officialunofficial/mkit/main/install.ps1
#
# Trust model:
#   * cosign keyless verification is REQUIRED by default. The script fetches
#     the per-archive `.cosign.bundle`, validates that it was signed by this
#     repo's release.yml workflow at a strict-semver tag, and only then
#     installs. The published .sha256 file is fetched from the same origin
#     as the archive and proves NOTHING about authenticity on its own — it's
#     a defense-in-depth integrity check.
#   * If `cosign.exe` is not on PATH on a release-track install (i.e. you
#     have not passed -InsecureSkipCosign), the script exits non-zero with
#     installation instructions. Use -InsecureSkipCosign to proceed without
#     signature verification at your own risk.
#
# Version pinning:
#   * -Version (or $env:MKIT_VERSION) pins the install to a specific tag.
#     RECOMMENDED for production use — it's the only way to get a
#     repeatable install.
#   * Without a version pin the script resolves the GitHub "latest" release.
#     The resolved tag is recorded at $StateDir\installed-tag; subsequent
#     unpinned installs compare against this file and warn loudly on a
#     silent downgrade.
#
# Only x86_64 Windows is published today (target: x86_64-pc-windows-msvc).
# There is no prebuilt arm64 Windows binary yet.
#
# Requires PowerShell 5.1+ (ships with every supported Windows release) or
# PowerShell 7+ (pwsh).

[CmdletBinding()]
param(
    [string]$Version = $env:MKIT_VERSION,
    [string]$InstallDir,
    [string]$StateDir,
    [switch]$InsecureSkipCosign,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # Invoke-WebRequest is far faster without the progress UI.

$Owner = 'officialunofficial'
$Repo = 'mkit'
$Api = "https://api.github.com/repos/$Owner/$Repo"
$Dl = "https://github.com/$Owner/$Repo/releases/download"
# Only target published for Windows today — see docs/RELEASE.md.
$Target = 'x86_64-pc-windows-msvc'

function Write-Log { param([string]$Message) Write-Host "==> $Message" }
function Write-Warn { param([string]$Message) Write-Warning $Message }
function Die {
    param([string]$Message)
    Write-Error "error: $Message" -ErrorAction Continue
    exit 1
}

function Show-Help {
    @'
mkit installer (Windows PowerShell)

Usage:
  irm https://mkit.sh/install.ps1 | iex
  ./install.ps1 [-Version <tag>] [-InstallDir <dir>] [-InsecureSkipCosign]

Flags:
  -Version <tag>          Pin to a specific release tag (e.g. v0.3.0).
                           RECOMMENDED for production / reproducible installs.
  -InstallDir <dir>       Install prefix. Default: $env:LOCALAPPDATA\mkit\bin.
  -InsecureSkipCosign     Skip cosign signature verification. DANGEROUS — use
                           only when cosign is unavailable and you have
                           verified the binary by other means.
  -Help                   Show this help.

Environment:
  MKIT_VERSION            Same as -Version.
  MKIT_INSTALL_DIR        Same as -InstallDir.
  MKIT_STATE_DIR          State dir for downgrade bookkeeping.
                           Default: $env:LOCALAPPDATA\mkit\state.
  MKIT_SKIP_COSIGN=1      Same as -InsecureSkipCosign.

Trust model:
  cosign keyless signature verification is REQUIRED by default. Install
  cosign from https://docs.sigstore.dev/cosign/installation/ before running,
  or pass -InsecureSkipCosign at your own risk.
'@ | Write-Host
}

if ($Help) {
    Show-Help
    exit 0
}

if (-not $InstallDir) {
    $InstallDir = if ($env:MKIT_INSTALL_DIR) { $env:MKIT_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'mkit\bin' }
}
if (-not $StateDir) {
    $StateDir = if ($env:MKIT_STATE_DIR) { $env:MKIT_STATE_DIR } else { Join-Path $env:LOCALAPPDATA 'mkit\state' }
}
$SkipCosign = $InsecureSkipCosign -or ($env:MKIT_SKIP_COSIGN -eq '1')

# ---- arch detection ----
#
# Only x86_64 is published. Fail closed on arm64/x86 rather than silently
# fetching a binary that won't run.
$arch = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
if ($arch -ne 'AMD64') {
    Die "unsupported arch: $arch (only x86_64/AMD64 has a prebuilt Windows binary — target $Target)"
}

# ---- version resolution ----

$resolvedFromLatest = $false
if (-not $Version) {
    Write-Log 'resolving latest release tag (no -Version pinned)'
    Write-Warn 'for reproducible installs, pin a tag with -Version vX.Y.Z or MKIT_VERSION=vX.Y.Z'
    try {
        $latest = Invoke-RestMethod -Uri "$Api/releases/latest" -Headers @{ 'User-Agent' = 'mkit-install.ps1' }
    } catch {
        Die "could not resolve latest release: $_"
    }
    $Version = $latest.tag_name
    if (-not $Version) { Die 'could not parse latest release tag' }
    $resolvedFromLatest = $true
}

# Normalise (accept either 'v0.1.0' or '0.1.0').
if ($Version.StartsWith('v')) {
    $tag = $Version
    $bare = $Version.Substring(1)
} else {
    $tag = "v$Version"
    $bare = $Version
}

# ---- silent-downgrade guard ----
#
# Same two-file scheme as install.sh: a global per-user record and a
# local-to-binary record. Both are written on every install; a downgrade
# fires if EITHER disagrees with the tag being installed. Comparison is a
# plain MAJOR.MINOR.PATCH numeric compare (pre-release suffixes are
# stripped for the compare, matching install.sh's `sort -V` behavior on the
# common case); if a tag doesn't parse as MAJOR.MINOR.PATCH the guard is
# skipped with a warning rather than blocking the install.
$stateFile = Join-Path $StateDir 'installed-tag'
$binStateFile = Join-Path $InstallDir '.mkit-installed-tag'

function Read-StateFile {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        return (Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue).Trim()
    }
    return ''
}

function Get-VersionCore {
    param([string]$BareVersion)
    # Strip a '-prerelease' / '+build' suffix and parse MAJOR.MINOR.PATCH.
    $core = $BareVersion.Split('-')[0].Split('+')[0]
    try {
        return [version]$core
    } catch {
        return $null
    }
}

$prevTagGlobal = Read-StateFile $stateFile
$prevTagLocal = Read-StateFile $binStateFile

$prevTag = ''
if ($prevTagGlobal -and $prevTagLocal) {
    $gCore = Get-VersionCore ($prevTagGlobal.TrimStart('v'))
    $lCore = Get-VersionCore ($prevTagLocal.TrimStart('v'))
    if ($gCore -and $lCore -and ($lCore -gt $gCore)) {
        $prevTag = $prevTagLocal
    } else {
        $prevTag = $prevTagGlobal
    }
} elseif ($prevTagGlobal) {
    $prevTag = $prevTagGlobal
} elseif ($prevTagLocal) {
    $prevTag = $prevTagLocal
}

if ($prevTag -and ($prevTag -ne $tag)) {
    $prevCore = Get-VersionCore ($prevTag.TrimStart('v'))
    $newCore = Get-VersionCore $bare
    if ($prevCore -and $newCore -and ($prevCore -gt $newCore)) {
        Write-Warn "you are installing $tag but $prevTag is already recorded — this is a DOWNGRADE."
        if ($resolvedFromLatest) {
            Die "refusing to silently downgrade from $prevTag to $tag via 'latest'. Pin -Version $prevTag or newer, or delete $stateFile and $binStateFile."
        } else {
            Write-Warn 'proceeding because -Version was passed explicitly.'
        }
    }
}

# Independent check: the two state files MUST agree when both exist. A
# mismatch means one was tampered with (or a parallel installer
# misbehaved). Refuse rather than picking a winner silently.
if ($prevTagGlobal -and $prevTagLocal -and ($prevTagGlobal -ne $prevTagLocal)) {
    Die "installed-tag mismatch: $stateFile says '$prevTagGlobal' but $binStateFile says '$prevTagLocal'. Refusing to install. Resolve manually."
}

$archive = "mkit-$bare-$Target.zip"
$archiveUrl = "$Dl/$tag/$archive"
$shaUrl = "$archiveUrl.sha256"
$bundleUrl = "$archiveUrl.cosign.bundle"

Write-Log "installing mkit $tag ($Target) into $InstallDir"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "mkit-install-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    # ---- download ----

    Write-Log "fetching $archiveUrl"
    $archivePath = Join-Path $tmp $archive
    try {
        Invoke-WebRequest -Uri $archiveUrl -OutFile $archivePath -Headers @{ 'User-Agent' = 'mkit-install.ps1' }
    } catch {
        Die "download failed — the release may not include a build for $Target ($_)"
    }

    Write-Log "fetching $archive.sha256"
    $shaPath = Join-Path $tmp "$archive.sha256"
    Invoke-WebRequest -Uri $shaUrl -OutFile $shaPath -Headers @{ 'User-Agent' = 'mkit-install.ps1' }

    # ---- cosign verification (default-on) ----
    #
    # This is the AUTHENTICATION step. The .sha256 check below is integrity
    # only — it shows nothing about provenance because the file is served
    # from the same origin as the archive. Cosign verifies that this
    # archive was produced by this repo's release.yml workflow at a
    # strict-semver tag.
    if ($SkipCosign) {
        Write-Warn 'cosign verification SKIPPED (-InsecureSkipCosign / MKIT_SKIP_COSIGN=1)'
        Write-Warn 'the only authenticity check disabled. SHA256 alone proves nothing.'
    } else {
        $cosign = Get-Command cosign.exe -ErrorAction SilentlyContinue
        if (-not $cosign) { $cosign = Get-Command cosign -ErrorAction SilentlyContinue }
        if (-not $cosign) {
            Write-Host @'
error: cosign is not in PATH.

cosign keyless signature verification is required by default — without it
the .sha256 file you just downloaded proves nothing about authenticity (it
comes from the same origin as the archive). Install cosign from:

  https://docs.sigstore.dev/cosign/installation/

Or, if you have verified the binary by other means and accept the risk,
re-run with -InsecureSkipCosign (or $env:MKIT_SKIP_COSIGN=1).
'@
            exit 1
        }

        Write-Log 'fetching cosign bundle'
        $bundlePath = Join-Path $tmp "$archive.cosign.bundle"
        try {
            Invoke-WebRequest -Uri $bundleUrl -OutFile $bundlePath -Headers @{ 'User-Agent' = 'mkit-install.ps1' }
        } catch {
            Die "cosign bundle missing for $tag — refusing to install. Pass -InsecureSkipCosign to override."
        }

        Write-Log 'cosign verify-blob'
        # Strict-semver regex on the tag, anchored to the exact workflow
        # path. Accepts e.g. v0.1.0 and v1.2.3-rc.1 but rejects v.* glob
        # matches, branch refs, and rogue workflows in the same repo.
        & $cosign.Source verify-blob `
            --certificate-identity-regexp '^https://github\.com/officialunofficial/mkit/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$' `
            --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' `
            --bundle $bundlePath `
            $archivePath
        if ($LASTEXITCODE -ne 0) { Die 'cosign verification failed — refusing to install' }
    }

    # ---- integrity (SHA256) ----
    #
    # Defense-in-depth integrity check. Comes AFTER cosign because cosign is
    # the authenticity check; sha256 only catches transport corruption.
    Write-Log 'verifying SHA256'
    # sha256sum format: "<hex>  <filename>" — same format written by
    # release.yml's build job (`sha256sum` / `shasum -a 256` on the runner).
    $shaLine = (Get-Content -LiteralPath $shaPath -Raw).Trim()
    $expectedHash = ($shaLine -split '\s+')[0].ToLowerInvariant()
    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expectedHash -ne $actualHash) {
        Die "SHA256 mismatch for $archive`: expected $expectedHash, got $actualHash"
    }

    # ---- extract ----

    Write-Log 'extracting'
    Expand-Archive -LiteralPath $archivePath -DestinationPath $tmp -Force

    $stageDir = "mkit-$bare-$Target"
    $binSrc = Join-Path $tmp "$stageDir\mkit.exe"
    if (-not (Test-Path -LiteralPath $binSrc -PathType Leaf)) {
        Die "extracted archive missing expected binary at $stageDir\mkit.exe"
    }

    # ---- install (best-effort atomic) ----
    #
    # Stage into a temp file in the SAME directory as the final install
    # path, then Move-Item on top of the old binary. Move-Item within one
    # volume is a metadata-only rename on NTFS, same rationale as
    # install.sh's mv-based install — but note Windows additionally
    # refuses to overwrite a file that's currently executing, unlike
    # POSIX rename(2); if `mkit.exe` is running, close it first and re-run.
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $installPath = Join-Path $InstallDir 'mkit.exe'
    $staged = Join-Path $InstallDir "mkit.exe.$([guid]::NewGuid().ToString('N')).tmp"
    Copy-Item -LiteralPath $binSrc -Destination $staged -Force
    Move-Item -LiteralPath $staged -Destination $installPath -Force

    # ---- record installed tag for downgrade guard ----

    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    Set-Content -LiteralPath $stateFile -Value $tag -NoNewline
    Set-Content -LiteralPath $binStateFile -Value $tag -NoNewline

    Write-Log "installed $installPath ($tag)"

    # ---- PATH check ----

    $pathEntries = $env:Path -split ';'
    if ($pathEntries -contains $InstallDir) {
        & $installPath version
    } else {
        Write-Warn "$InstallDir is not in PATH"
        Write-Host @"
Add it to your user PATH (persists across sessions):
  [Environment]::SetEnvironmentVariable('Path', "`$([Environment]::GetEnvironmentVariable('Path','User'));$InstallDir", 'User')

Then open a new terminal, or run directly:
  $installPath version
"@
    }
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
