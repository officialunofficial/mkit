#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Local-only WP-4.18 driver. Python handles exact-SHA evidence and owned PIDs.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/vcs-worker-launch.py "$@"
