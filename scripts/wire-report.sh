#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Summarize wire-suite TAP logs as Markdown tables: one row per suite run
# (target profile and result counts), then every skipped case with its reason.
# Input is any log holding `mkit-server-conformance` TAP output: a nextest run
# with `--no-capture` over the native wire lanes, or the output of
# `scripts/vcs-worker-conformance.sh`. Use the tables in conformance reports.
# Run the native lanes one at a time (`--no-capture` does),
# or their TAP blocks interleave.
#
#   scripts/wire-report.sh LOG...
set -euo pipefail

if [ $# -eq 0 ]; then
    echo "usage: $0 LOG..." >&2
    exit 2
fi

cat -- "$@" | awk '
    { sub(/^[ \t]+/, "") }
    /^TAP version/ { run++; next }
    /^# profile / { profile[run] = $0; sub(/^# profile /, "", profile[run]); next }
    /^# features / { features[run] = $0; sub(/^# features /, "", features[run]); next }
    /^# pass [0-9]+ fail [0-9]+ skip [0-9]+/ { counts[run] = $3 " | " $5 " | " $7; next }
    /^(not )?ok [0-9]+ - .* # SKIP / {
        name = ($1 == "not") ? $5 : $4
        reason = $0; sub(/^.* # SKIP /, "", reason)
        key = name " | " reason
        if (!(key in seen)) { seen[key] = 1; skips[++nskips] = key }
        next
    }
    END {
        print "| Run | Profile | Features | Pass | Fail | Skip |"
        print "|---|---|---|---|---|---|"
        for (i = 1; i <= run; i++) {
            p = profile[i]; gsub(/\|/, "/", p)
            printf "| %d | `%s` | `%s` | %s |\n", i, p, features[i], counts[i]
        }
        print ""
        print "| Skipped case | Reason |"
        print "|---|---|"
        for (i = 1; i <= nskips; i++) print "| " skips[i] " |"
    }'
