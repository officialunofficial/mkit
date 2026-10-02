#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Local native default-zstd push/clone against the optimized launch Worker.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/vcs-worker-launch-push-runtime.py "$@"
