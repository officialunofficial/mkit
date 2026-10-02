#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Checks the release mkit compiler-artifact log and stripped binary.
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
golden="$here/release/mkit-packages.golden"

case "${1:-}" in
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

if [ $# -ne 2 ]; then
  echo "usage: $0 <build.jsonl> <binary> | --update-golden" >&2
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

python3 - "$jsonl" "$binary" "$golden" <<'PY' || fail=1
import json
import os
import sys

path, binary, golden_path = sys.argv[1:4]


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
    for seam in ("test-faults", "stubs"):
        if seam in feats:
            err(f"{name} was compiled with the `{seam}` test seam")

# The binary being scanned must be the one this log built.
bin_name = "mkit"
exe = executables.get(bin_name)
if exe is None:
    err(f"the build did not produce the `{bin_name}` binary")
elif os.path.realpath(exe) != os.path.realpath(binary):
    err(f"the log built `{bin_name}` at {exe}, but the scanned binary is {binary}")

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
scan 'sqlite3_' 'SQLite linked into mkit'
scan 'x-mkit-test-' 'test-faults seam compiled in'
scan '/__stub/' 'MPP stub control plane compiled in'
scan 'TEST_OUTBOX_BACKLOG_ROWS' 'test-only Worker backlog var compiled in'
scan 'TEST_TICKET_TTL_MS' 'test-only Worker ticket var compiled in'

if [ "$fail" -ne 0 ]; then
  echo "check-release-artifact-features: FAILED (cli): $(basename "$binary")" >&2
  exit 1
fi
echo "check-release-artifact-features: OK (cli): $(basename "$binary")"
