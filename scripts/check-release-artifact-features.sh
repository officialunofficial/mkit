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
# tower-http layers, `mkit-server` `connect`/`sql` and a bundled SQLite. A
# `cargo tree -p mkit-cli` model cannot see that; the compiler-artifact
# messages of the real build can. The server check pins the shipped feature
# set and keeps the pipeline's test seam (`test-faults`) out of the release.
#
# Usage:
#   scripts/check-release-artifact-features.sh <mkit-build.jsonl> <mkit-binary>
#   scripts/check-release-artifact-features.sh --server <features> \
#       <mkit-server-build.jsonl> <mkit-server-binary>
#   scripts/check-release-artifact-features.sh --server-features
#   scripts/check-release-artifact-features.sh --update-golden
#
# <features> is the full comma-separated feature set `mkit-server-native`
# must have been compiled with (implied features included). The shipped set
# lives in scripts/release/mkit-server-features, the one source both
# release.yml and release-artifact-check.yml read; `--server-features`
# prints it, validated.
#
# The mkit check also allowlists the packages the CLI may compile:
# scripts/release/mkit-packages.golden, the union over every release target
# of `cargo tree -p mkit-cli` (normal + build dependencies, which matches
# the release build's compiler artifacts exactly). A package outside it
# fails the check. If the new package is intended, run `--update-golden`
# (it needs no toolchain for the other targets) and commit the diff with
# the change that brought the package in.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
features_file="$here/release/mkit-server-features"
golden="$here/release/mkit-packages.golden"

# The shipped mkit-server feature list: the one non-comment line of
# $features_file, strictly `name,name,...`.
server_features() {
  local list
  list="$(grep -v '^[[:space:]]*#' "$features_file" | grep -v '^[[:space:]]*$')"
  if ! printf '%s' "$list" | grep -Eqx '[a-z0-9_-]+(,[a-z0-9_-]+)*'; then
    echo "check-release-artifact-features: $features_file must hold exactly one line like 'a,b,c'" >&2
    exit 1
  fi
  printf '%s\n' "$list"
}

case "${1:-}" in
  --server-features)
    server_features
    exit 0
    ;;
  --update-golden)
    # Every release target, straight from release.yml's build matrix.
    targets="$(sed -n 's/^ *- target: *//p' "$root/.github/workflows/release.yml")"
    if [ -z "$targets" ]; then
      echo "check-release-artifact-features: no targets found in release.yml" >&2
      exit 1
    fi
    tmp="$(mktemp)"
    trap 'rm -f "$tmp"' EXIT
    {
      echo "# Packages the release \`mkit\` build may compile: the union over"
      echo "# release.yml's targets of \`cargo tree -p mkit-cli -e normal,build\`."
      echo "# Checked by scripts/check-release-artifact-features.sh; regenerate with"
      echo "# \`scripts/check-release-artifact-features.sh --update-golden\` and review"
      echo "# the diff: every new name is a new dependency of the shipped CLI."
      for t in $targets; do
        (cd "$root/rust" && cargo tree --locked -p mkit-cli --target "$t" \
          -e normal,build --prefix none -f '{p}') | awk '{print $1}'
      done | LC_ALL=C sort -u
    } > "$tmp"
    mv "$tmp" "$golden"
    trap - EXIT
    echo "check-release-artifact-features: wrote $golden ($(grep -vc '^#' "$golden") packages; targets: $(echo "$targets" | tr '\n' ' '))"
    exit 0
    ;;
esac

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
  echo "usage: $0 [--server <features>] <build.jsonl> <binary> | --server-features | --update-golden" >&2
  exit 2
fi
jsonl="$1"
binary="$2"
for f in "$jsonl" "$binary" "$golden"; do
  if [ ! -f "$f" ]; then
    echo "check-release-artifact-features: not found: $f" >&2
    exit 1
  fi
done

fail=0

python3 - "$mode" "$expect" "$jsonl" "$binary" "$golden" <<'PY' || fail=1
import json
import os
import sys

mode, expect, path, binary, golden_path = sys.argv[1:6]


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
executables = {}
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
        if "bin" in target.get("kind", []) and msg.get("executable"):
            executables[target.get("name")] = msg["executable"]

errors = []


def err(text):
    errors.append(text)


if not features:
    err("no compiler-artifact messages: was the build run with --message-format=json*?")

for name, feats in sorted(features.items()):
    if "test-faults" in feats:
        err(f"{name} was compiled with the `test-faults` test seam")

# The binary being scanned must be the one this log built.
bin_name = "mkit" if mode == "cli" else "mkit-server"
exe = executables.get(bin_name)
if exe is None:
    err(f"the build did not produce the `{bin_name}` binary")
elif os.path.realpath(exe) != os.path.realpath(binary):
    err(f"the log built `{bin_name}` at {exe}, but the scanned binary is {binary}")

if mode == "cli":
    for banned in ("mkit-server-native", "axum", "rusqlite", "libsqlite3-sys"):
        if banned in features:
            err(f"server-only package `{banned}` is in the mkit build")
    # Server-side features of shared HTTP crates.
    for name, banned in (
        ("hyper", {"server"}),
        ("hyper-util", {"server", "server-auto", "server-graceful"}),
        ("connectrpc", {"server", "axum"}),
    ):
        bad = features.get(name, set()) & banned
        if bad:
            err(f"{name} was compiled with server features {sorted(bad)}")
    # tower-http is reqwest's redirect layer in the CLI: exactly these
    # features, never the server's layers (cors, limit, trace, ...).
    tower_http_allowed = {"follow-redirect", "futures-util", "tower"}
    extra = features.get("tower-http", set()) - tower_http_allowed
    if extra:
        err(f"tower-http was compiled with {sorted(extra)}; mkit allows only {sorted(tower_http_allowed)}")
    # mkit-cli's own `mkit-server` dependency (WP-M0-13): ssh + fs only.
    extra = features.get("mkit-server", set()) - {"ssh", "fs"}
    if extra:
        err(f"mkit-server was compiled with {sorted(extra)} (mkit-cli declares only ssh, fs)")
    # Package allowlist.
    with open(golden_path, encoding="utf-8") as f:
        golden = {l.strip() for l in f if l.strip() and not l.startswith("#")}
    new = sorted(set(features) - golden)
    if new:
        err(f"{len(new)} package(s) not in {os.path.relpath(golden_path)}: {', '.join(new)}. "
            "If this dependency of the mkit CLI is intended, run "
            "`scripts/check-release-artifact-features.sh --update-golden` and commit "
            "the golden diff with the change that brought it in.")
    print(f"check-release-artifact-features: mkit: {len(features)} packages compiled "
          f"(golden: {len(golden)}); "
          f"hyper={sorted(features.get('hyper', []))} "
          f"hyper-util={sorted(features.get('hyper-util', []))} "
          f"connectrpc={sorted(features.get('connectrpc', []))} "
          f"tower-http={sorted(features.get('tower-http', []))} "
          f"mkit-server={sorted(features['mkit-server']) if 'mkit-server' in features else 'absent'}")
else:
    want = {x for x in expect.split(",") if x}
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
