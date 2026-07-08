#!/usr/bin/env python3
"""perf-write-path-guard.py — fast, dependency-free write-path perf
regression guard (#608, tier 2 of #609's assertion design).

Mirrors the append-1m row of scripts/bench-vs-git.sh (mkit side only) —
init/keygen, add + commit a ~100 MiB random blob, append 1 MiB, add +
commit again — but drops hyperfine, the git comparison, and any checked-in
fixtures, and asserts a machine-independent RATIO instead of an absolute
wall-clock threshold:

    default `mkit commit` must run within BOUND times `mkit commit -q`
    on the same append-1m scenario.

Why a ratio: both commands run back-to-back on the same machine in the
same invocation, so machine speed cancels out — no calibration against a
"good" baseline machine, no flakiness budget for slow CI runners (#609's
"Timing ratios ... machine-independent comparisons of two commands in the
same process/run" tier, which belongs in the serial/slow CI lane).

Why this scenario catches regressions: `commit -q` suppresses the
post-commit diffstat summary; default `commit` computes and prints it.
This is exactly what caught #606 (first-bad commit 36b9808d): the summary
reassembled the *entire* chunked blob to compute a diffstat, so after a
1 MiB append to a 100 MiB file, default `commit` ran ~1.7x slower than
`commit -q`. #613 fixed the summary to read blob metadata instead of
reassembling content, restoring the ratio to ~1.0x. See the calibration
numbers in the PR that introduced this guard for the measured spread.

Usage:
    scripts/perf-write-path-guard.py <path-to-release-mkit-binary> [--runs N] [--bound X]
    scripts/perf-write-path-guard.py --bisect [--runs N] [--bound X]

`--bisect` builds `mkit-cli` in release mode from the current worktree
HEAD and runs the guard against that binary — see "Bisecting a future
regression" below.

Exit codes (git-bisect-run compatible):
    0   ratio within bound (good)
    1   ratio exceeds bound (bad — regression present)
    125 setup/build failure — tell `git bisect run` to skip this commit

Requires only a release mkit binary and python3. No hyperfine, no git
side, no checked-in fixtures (random data is generated fresh into a temp
dir per run). Five runs of both variants takes ~15s on a warm build;
with a from-scratch `cargo build --release` (~30-40s) the whole guard
comfortably finishes in well under the ~2 minute CI budget.

## Bisecting a future regression

The pattern that found #606:

    git bisect start
    git bisect bad <commit-that-feels-slow>
    git bisect good <commit-that-felt-fine>
    git bisect run python3 scripts/perf-write-path-guard.py --bisect

`--bisect` rebuilds `mkit-cli` at each visited commit (skipping it with
exit 125 on a build failure, so bisect keeps searching) and re-runs the
ratio check. Narrow `--bound` for a faster bisect once you have a rough
idea of the good/bad ratio split (e.g. `--bound 1.3`).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

BIG_SIZE = 100 * 1024 * 1024
APPEND_SIZE = 1 * 1024 * 1024
DEFAULT_RUNS = 5
# Calibrated (min-of-N, the statistic used below) against a
# known-regressed binary built at 36b9808d (ratio ~1.6-2.1x across
# repeated rounds, including under heavy concurrent machine load) and a
# binary built from the post-#613 fix (~0.65-1.32x, also under load):
# 1.35 sits comfortably inside the gap.
DEFAULT_BOUND = 1.35


def run_quiet(cmd: str, cwd: str) -> None:
    subprocess.run(
        cmd, cwd=cwd, shell=True, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def timed(cmd: str, cwd: str) -> float:
    t0 = time.perf_counter()
    run_quiet(cmd, cwd)
    return time.perf_counter() - t0


def one_trial(mkit: str, quiet: bool, big: bytes, append: bytes) -> float:
    """Fresh repo: init/keygen, commit a 100 MiB blob, append 1 MiB, then
    time a second add+commit — with or without the `-q` summary flag."""
    work = tempfile.mkdtemp(prefix="mkit-perf-guard.")
    try:
        run_quiet(f"'{mkit}' init && '{mkit}' keygen", work)
        with open(os.path.join(work, "video100m.bin"), "wb") as f:
            f.write(big)
        run_quiet(f"'{mkit}' add video100m.bin && '{mkit}' commit -q -m v1", work)
        with open(os.path.join(work, "video100m.bin"), "ab") as f:
            f.write(append)
        flag = "-q " if quiet else ""
        return timed(f"'{mkit}' add video100m.bin && '{mkit}' commit {flag}-m v2", work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def build_bisect_binary() -> str:
    """Build mkit-cli in release mode from the current HEAD. Returns the
    binary path, or raises on build failure (caller maps to exit 125)."""
    toplevel = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    rust_dir = os.path.join(toplevel, "rust")
    subprocess.run(
        ["cargo", "build", "--release", "-p", "mkit-cli"],
        cwd=rust_dir, check=True,
    )
    return os.path.join(rust_dir, "target", "release", "mkit")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary", nargs="?", help="path to a release mkit binary")
    parser.add_argument("--bisect", action="store_true", help="build mkit-cli --release from HEAD and use that binary")
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS, help=f"measured runs per variant (default {DEFAULT_RUNS})")
    parser.add_argument("--bound", type=float, default=DEFAULT_BOUND, help=f"max allowed default/quiet ratio (default {DEFAULT_BOUND})")
    parser.add_argument("--json", action="store_true", help="also print a machine-readable JSON summary line")
    args = parser.parse_args()

    if args.bisect:
        if args.binary:
            parser.error("pass either a binary path or --bisect, not both")
        try:
            mkit = build_bisect_binary()
        except subprocess.CalledProcessError as e:
            print(f"perf-write-path-guard: build failed, skipping this commit: {e}", file=sys.stderr)
            return 125
    else:
        if not args.binary:
            parser.error("a release mkit binary path is required (or pass --bisect)")
        mkit = os.path.abspath(args.binary)

    if not (os.path.isfile(mkit) and os.access(mkit, os.X_OK)):
        print(f"perf-write-path-guard: not an executable file: {mkit}", file=sys.stderr)
        return 125

    big = os.urandom(BIG_SIZE)
    append = os.urandom(APPEND_SIZE)

    try:
        one_trial(mkit, True, big, append)  # warmup, discarded

        default_times = []
        quiet_times = []
        for _ in range(args.runs):
            default_times.append(one_trial(mkit, False, big, append))
            quiet_times.append(one_trial(mkit, True, big, append))
    except subprocess.CalledProcessError as e:
        print(f"perf-write-path-guard: mkit invocation failed, skipping: {e}", file=sys.stderr)
        return 125

    # Use the minimum, not mean/median: both variants run interleaved
    # (default, quiet, default, quiet, ...) on a shared machine, so a
    # scheduler/CPU-contention spike can hit either arm on any given
    # iteration. The minimum across runs is each arm's best approximation
    # of an uncontended sample, which is what the ratio should compare —
    # this is also what the #606 bisect prototype used (append_min) to get
    # a non-overlapping good/bad split at just 3 runs.
    dmin = min(default_times)
    qmin = min(quiet_times)
    ratio = dmin / qmin

    def fmt(xs: list[float]) -> str:
        return " ".join(f"{x:.3f}" for x in xs)

    print(f"append-1m commit (default):    min {dmin:.4f}s  runs [{fmt(default_times)}]")
    print(f"append-1m commit -q (quiet):   min {qmin:.4f}s  runs [{fmt(quiet_times)}]")
    print(f"ratio (default/quiet):         {ratio:.3f}  bound {args.bound:.3f}")

    if args.json:
        print("JSON " + json.dumps({
            "mkit": mkit,
            "runs": args.runs,
            "bound": args.bound,
            "default_min_s": dmin,
            "quiet_min_s": qmin,
            "default_runs_s": default_times,
            "quiet_runs_s": quiet_times,
            "ratio": ratio,
            "pass": ratio <= args.bound,
        }))

    if ratio > args.bound:
        print(
            f"perf-write-path-guard: FAIL — default commit is {ratio:.3f}x slower "
            f"than commit -q on the append-1m scenario (bound {args.bound:.3f}x). "
            f"Measured minimums: default {dmin:.4f}s vs quiet {qmin:.4f}s over {args.runs} runs. "
            "This is the #606 write-path regression shape (post-commit summary "
            "reassembling the full blob instead of reading metadata) — see "
            "docs/PROFILING.md and `git bisect run python3 scripts/perf-write-path-guard.py --bisect`.",
            file=sys.stderr,
        )
        return 1

    print(f"perf-write-path-guard: PASS — ratio {ratio:.3f}x within bound {args.bound:.3f}x")
    return 0


if __name__ == "__main__":
    sys.exit(main())
