#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Optimized ordinary release Worker + isolated admission/Outcome binding.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/vcs-worker-launch-read-runtime.py "$@"
