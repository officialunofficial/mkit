#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Local release-only R1/R2 publication and extraction evidence.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/vcs-worker-launch-runtime.py "$@"
