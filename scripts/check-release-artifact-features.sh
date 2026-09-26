#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Checks what a release build of `mkit` or `mkit-server` actually compiled,
# from cargo's own `--message-format=json-render-diagnostics` output, plus a
# string scan of the stripped binary.
#
# WHY: `mkit` and `mkit-server` ship from the same workspace and the same
# `target/` dir, but in separate cargo invocations (release.yml, WP-M0-18).
# Cargo unifies features across every package selected in one invocation,
# so `cargo build --bin mkit --bin mkit-server` (or a bare `--bin mkit`
# from the workspace root, which selects every member) compiles the
# shipped `mkit` with hyper `server`, connectrpc `axum`, the server's
# tower-http layers, `mkit-server` `connect`/`sql` and a bundled SQLite. A `cargo tree -p mkit-cli` model
# cannot see that; the compiler-artifact messages of the real build can.
# The server check pins the shipped feature set and keeps the pipeline's
# test seam (`test-faults`) out of the release.
#
# Usage:
#   scripts/check-release-artifact-features.sh <mkit-build.jsonl> <mkit-binary>
#   scripts/check-release-artifact-features.sh --server <features> \
#       <mkit-server-build.jsonl> <mkit-server-binary>
#
# <features> is the full comma-separated feature set `mkit-server-native`
# must have been compiled with (implied features included), e.g.
# `enc,http,s3,sqlite`.

set -euo pipefail

mode=cli
expect=""
if [ "${1:-}" = "--server" ]; then
  mode=server
  expect="${2:-}"
  shift 2 || true
  if [ -z "$expect" ]; then
    echo "check-release-artifact-features: --server needs a feature list" >&2
    exit 2
  fi
fi
if [ $# -ne 2 ]; then
  echo "usage: $0 [--server <features>] <build.jsonl> <binary>" >&2
  exit 2
fi
jsonl="$1"
binary="$2"
for f in "$jsonl" "$binary"; do
  if [ ! -f "$f" ]; then
    echo "check-release-artifact-features: not found: $f" >&2
    exit 1
  fi
done

fail=0

python3 - "$mode" "$expect" "$jsonl" <<'PY' || fail=1
import json
import sys

mode, expect, path = sys.argv[1], sys.argv[2], sys.argv[3]


def pkg_name(pid):
    # Package id spec (cargo >= 1.77): `<source-url>#<name>@<version>`, or
    # `<source-url>#<version>` when the name is the URL's last segment.
    # Older cargo: `<name> <version> (<source>)`.
    if "#" not in pid:
        return pid.split(" ", 1)[0]
    url, frag = pid.rsplit("#", 1)
    if "@" in frag:
        return frag.split("@", 1)[0]
    return url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]


features = {}
bins = set()
with open(path, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        if msg.get("reason") != "compiler-artifact":
            continue
        name = pkg_name(msg["package_id"])
        features.setdefault(name, set()).update(msg.get("features", []))
        target = msg.get("target", {})
        if "bin" in target.get("kind", []):
            bins.add(target.get("name"))

errors = []


def err(text):
    errors.append(text)


if not features:
    err("no compiler-artifact messages: was the build run with --message-format=json*?")

for name, feats in sorted(features.items()):
    if "test-faults" in feats:
        err(f"{name} was compiled with the `test-faults` test seam")

if mode == "cli":
    if "mkit" not in bins:
        err("the build did not produce the `mkit` binary")
    for banned in ("mkit-server-native", "axum", "rusqlite", "libsqlite3-sys"):
        if banned in features:
            err(f"server-only package `{banned}` is in the mkit build")
    # Server-side features of shared HTTP crates. tower-http itself is a
    # legitimate mkit dependency (reqwest's `follow-redirect`); only the
    # server's tower layers are banned.
    for name, banned in (
        ("hyper", {"server"}),
        ("hyper-util", {"server", "server-auto", "server-graceful"}),
        ("connectrpc", {"server", "axum"}),
        ("tower-http", {"cors", "limit", "sensitive-headers", "trace"}),
    ):
        bad = features.get(name, set()) & banned
        if bad:
            err(f"{name} was compiled with server features {sorted(bad)}")
    # mkit-cli's own `mkit-server` dependency (WP-M0-13): ssh + fs only.
    extra = features.get("mkit-server", set()) - {"ssh", "fs"}
    if extra:
        err(f"mkit-server was compiled with {sorted(extra)} (mkit-cli declares only ssh, fs)")
    print(f"check-release-artifact-features: mkit: {len(features)} packages compiled; "
          f"hyper={sorted(features.get('hyper', []))} "
          f"hyper-util={sorted(features.get('hyper-util', []))} "
          f"connectrpc={sorted(features.get('connectrpc', []))} "
          f"tower-http={sorted(features.get('tower-http', []))} "
          f"mkit-server={sorted(features['mkit-server']) if 'mkit-server' in features else 'absent'}")
else:
    want = {x for x in expect.split(",") if x}
    if "mkit-server" not in bins:
        err("the build did not produce the `mkit-server` binary")
    got = features.get("mkit-server-native")
    if got is None:
        err("mkit-server-native is not in the build")
    elif got != want:
        err(f"mkit-server-native features {sorted(got)} != expected {sorted(want)}")
    print(f"check-release-artifact-features: mkit-server: {len(features)} packages compiled; "
          f"mkit-server-native={sorted(got or [])} "
          f"mkit-server={sorted(features.get('mkit-server', []))}")

for e in errors:
    print(f"check-release-artifact-features: ERROR: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
PY

# The binary itself: the stripped release binary has no symbol table, so
# scan its bytes (a superset of `strings`). `sqlite3_` names come from the
# bundled SQLite; `x-mkit-test-` headers exist only under `test-faults`.
scan() {
  if LC_ALL=C grep -a -q -- "$1" "$binary"; then
    echo "check-release-artifact-features: ERROR: $(basename "$binary") contains \`$1\` ($2)" >&2
    fail=1
  fi
}
if [ "$mode" = cli ]; then
  scan 'sqlite3_' 'SQLite linked into mkit'
fi
scan 'x-mkit-test-' 'test-faults seam compiled in'

if [ "$fail" -ne 0 ]; then
  echo "check-release-artifact-features: FAILED ($mode): $(basename "$binary")" >&2
  exit 1
fi
echo "check-release-artifact-features: OK ($mode): $(basename "$binary")"
