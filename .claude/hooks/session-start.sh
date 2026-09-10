#!/bin/bash
# Wires sccache to a Cloudflare R2 cache in a Claude Code cloud-sandbox
# session, so a Rust build there does not recompile the whole dependency
# graph from zero every run. Idempotent and synchronous.
#
# This sandbox has no GCP service-account identity, so it cannot reach the
# sccache+GCS bucket cloudbuild/ci.yaml uses for real CI (that one
# authenticates through the Cloud Build SA's ADC, which only exists on a
# GCP-run build). R2's static access-key/secret pair is the credential shape
# a non-GCP sandbox can hold, via SCCACHE_BUCKET/SCCACHE_ENDPOINT/
# SCCACHE_REGION/AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY set as plain
# environment variables on the Claude Code environment (NOT the AWS SigV4
# credential-injection feature — its proxy only pattern-matches
# *.amazonaws.com hostnames, so it can never sign requests to
# *.r2.cloudflarestorage.com; that environment's Network access must also
# allow the R2 host directly). Every check below is a soft-fail: an
# unprovisioned or unreachable cache must degrade to a plain uncached build,
# never break the session.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

if [ -n "${SCCACHE_BUCKET:-}" ] && [ -n "${SCCACHE_ENDPOINT:-}" ]; then
  SCCACHE_BIN="$HOME/.local/bin/sccache"
  if [ ! -x "$SCCACHE_BIN" ]; then
    pip install --quiet --user sccache
  fi
  # curl WITHOUT -f/--fail: an unauthenticated GET against an R2/S3 endpoint
  # correctly answers 400 InvalidArgument (missing signature), not 2xx — a
  # healthy, reachable response. -f treats any non-2xx as failure, which
  # would reject a working endpoint every time. curl's own exit code still
  # catches a real outage (DNS/TCP/TLS failure); any HTTP response at all,
  # whatever its status, means the host is up.
  if [ -x "$SCCACHE_BIN" ] \
    && curl -sS -o /dev/null --max-time 5 "$SCCACHE_ENDPOINT" \
    && ! grep -q '^\[build\]' "$HOME/.cargo/config.toml" 2>/dev/null; then
    mkdir -p "$HOME/.cargo"
    {
      echo ""
      echo "[build]"
      echo "rustc-wrapper = \"$SCCACHE_BIN\""
      echo "incremental = false" # required: sccache can't cache incremental builds
    } >>"$HOME/.cargo/config.toml"
  else
    echo "session-start.sh: sccache not wired (endpoint unreachable, install failed, or ~/.cargo/config.toml already has a [build] table) — build will run uncached" >&2
  fi
fi
