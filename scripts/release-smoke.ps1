# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Mechanizes docs/RELEASE.md's "Smoke test" checklist for the Windows
# release archive (`x86_64-pc-windows-msvc.zip`): verify the cosign
# signature and the SHA256SUMS entry, extract it, check the
# `mkit.exe version` contract and the bundled man page/completions, run a
# basic init/keygen/add/commit flow, and (unless -SkipNpm) check the
# matching npm package. This is the Windows counterpart to
# scripts/release-smoke.sh — same checks, same trust model (mirrors the
# cosign invocation in install.ps1).
#
# Usage:
#   .\scripts\release-smoke.ps1 -Archive .\mkit-X.Y.Z-x86_64-pc-windows-msvc.zip -Version X.Y.Z
#
# Looks for, alongside -Archive (all optional — a missing sidecar is
# skipped with a warning so this also works against a bare local build):
#   <Archive>.cosign.bundle   cosign signature bundle
#   SHA256SUMS                aggregate hash file, same directory as -Archive

param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [Parameter(Mandatory = $true)][string]$Version,
    [switch]$SkipNpm,
    [switch]$SkipCosign,
    [switch]$SkipSha256Sums
)

$ErrorActionPreference = 'Stop'
$script:Failed = $false

function Write-Log { param([string]$Message) Write-Host "release-smoke: $Message" }
function Write-Warn { param([string]$Message) Write-Warning "release-smoke: $Message" }
function Write-Err {
    param([string]$Message)
    Write-Error "release-smoke: ERROR: $Message" -ErrorAction Continue
    $script:Failed = $true
}

if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) {
    throw "release-smoke: archive not found: $Archive"
}
if ($Archive -notlike '*.zip') {
    throw "release-smoke: only .zip archives are supported here — use scripts/release-smoke.sh for Linux/macOS .tar.gz archives"
}

$ArchiveFull = (Resolve-Path -LiteralPath $Archive).Path
$ArchiveDir = Split-Path -Parent $ArchiveFull
$ArchiveName = Split-Path -Leaf $ArchiveFull

# ---- cosign signature ----
if ($SkipCosign) {
    Write-Log 'skipping cosign verification (-SkipCosign)'
} elseif (-not (Test-Path -LiteralPath "$ArchiveFull.cosign.bundle" -PathType Leaf)) {
    Write-Warn "no $ArchiveName.cosign.bundle found next to the archive — skipping cosign verification (expected for a local pre-flight build)"
} else {
    $cosign = Get-Command cosign -ErrorAction SilentlyContinue
    if (-not $cosign) {
        Write-Warn 'cosign not installed — skipping signature verification. Install: https://docs.sigstore.dev/cosign/installation/'
    } else {
        Write-Log "verifying cosign signature for $ArchiveName"
        & $cosign.Source verify-blob `
            --certificate-identity-regexp '^https://github\.com/officialunofficial/mkit/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$' `
            --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' `
            --bundle "$ArchiveFull.cosign.bundle" `
            $ArchiveFull
        if ($LASTEXITCODE -ne 0) {
            Write-Err "cosign signature verification failed for $ArchiveName"
        } else {
            Write-Log 'cosign: Verified OK'
        }
    }
}

# ---- SHA256SUMS entry ----
if ($SkipSha256Sums) {
    Write-Log 'skipping SHA256SUMS check (-SkipSha256Sums)'
} else {
    $sumsPath = Join-Path $ArchiveDir 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) {
        Write-Warn "no SHA256SUMS found in $ArchiveDir — skipping hash check (expected for a local pre-flight build)"
    } else {
        $entry = Select-String -LiteralPath $sumsPath -Pattern ([regex]::Escape($ArchiveName) + '$') | Select-Object -First 1
        if (-not $entry) {
            Write-Err "SHA256SUMS has no entry for $ArchiveName"
        } else {
            $expected = ($entry.Line -split '\s+')[0]
            $actual = (Get-FileHash -LiteralPath $ArchiveFull -Algorithm SHA256).Hash.ToLower()
            if ($expected -ne $actual) {
                Write-Err "SHA256SUMS mismatch for $ArchiveName`: expected $expected, got $actual"
            } else {
                Write-Log "SHA256SUMS matches $ArchiveName"
            }
        }
    }
}

if ($script:Failed) {
    throw 'release-smoke: aborting before extraction — signature/hash checks failed'
}

# ---- extract and locate the binary ----
$WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("mkit-smoke-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $WorkDir | Out-Null
try {
    Write-Log "extracting $ArchiveName"
    Expand-Archive -LiteralPath $ArchiveFull -DestinationPath $WorkDir

    $bin = Get-ChildItem -Path $WorkDir -Filter 'mkit.exe' -Recurse -Depth 2 | Select-Object -First 1
    if (-not $bin) {
        throw "release-smoke: no 'mkit.exe' executable found in the extracted archive"
    }
    $archiveRoot = $bin.Directory.FullName

    # ---- version contract ----
    $out = (& $bin.FullName version).Trim()
    $expected = "mkit $Version"
    if ($out -ne $expected) {
        Write-Err "version contract violated: got [$out], expected [$expected]"
    } else {
        Write-Log "version contract OK: $out"
    }

    # ---- man page / completions present ----
    foreach ($f in @(
        'share\man\man1\mkit.1',
        'share\completions\mkit.bash',
        'share\completions\_mkit',
        'share\completions\mkit.fish'
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $archiveRoot $f) -PathType Leaf)) {
            Write-Err "missing $f in extracted archive"
        }
    }
    if (-not $script:Failed) { Write-Log 'man page and completions present' }

    # ---- basic flow: init, keygen, add, commit ----
    $RepoDir = Join-Path ([System.IO.Path]::GetTempPath()) ("mkit-smoke-repo-" + [System.Guid]::NewGuid())
    New-Item -ItemType Directory -Path $RepoDir | Out-Null
    try {
        Push-Location $RepoDir
        & $bin.FullName init
        & $bin.FullName keygen
        'hello' | Out-File -FilePath 'README.md' -Encoding utf8
        & $bin.FullName add README.md
        & $bin.FullName commit -m 'smoke test commit'
        if ($LASTEXITCODE -ne 0) { throw 'basic init/keygen/add/commit flow failed' }
        Write-Log 'basic init/keygen/add/commit flow OK'
    } catch {
        Write-Err "basic init/keygen/add/commit flow failed: $_"
    } finally {
        Pop-Location
        Remove-Item -Recurse -Force $RepoDir -ErrorAction SilentlyContinue
    }

    # ---- npm package ----
    if ($SkipNpm) {
        Write-Log 'skipping npm checks (-SkipNpm)'
    } elseif (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        Write-Warn 'npm not installed — skipping npm checks'
    } else {
        Write-Log "checking @officialunofficial/mkit-wasm@$Version on npm"
        & npm view "@officialunofficial/mkit-wasm@$Version" | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Err "npm view @officialunofficial/mkit-wasm@$Version failed" }

        $NpmDir = Join-Path ([System.IO.Path]::GetTempPath()) ("mkit-smoke-npm-" + [System.Guid]::NewGuid())
        New-Item -ItemType Directory -Path $NpmDir | Out-Null
        try {
            Push-Location $NpmDir
            & npm init -y | Out-Null
            & npm install --save-exact "@officialunofficial/mkit-wasm@$Version" | Out-Null
            & npm audit signatures
            if ($LASTEXITCODE -ne 0) { throw "npm audit signatures failed for @officialunofficial/mkit-wasm@$Version" }
        } catch {
            Write-Err $_
        } finally {
            Pop-Location
            Remove-Item -Recurse -Force $NpmDir -ErrorAction SilentlyContinue
        }
    }
} finally {
    Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
}

if ($script:Failed) {
    throw "release-smoke: FAILED — see errors above"
}
Write-Host "release-smoke: all checks passed for $ArchiveName ($Version)"
