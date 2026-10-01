#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/vcs-worker-launch-inspection-runtime.py "$@"
