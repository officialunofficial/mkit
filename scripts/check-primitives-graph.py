#!/usr/bin/env python3
"""Inspect package-rooted target dependencies, excluding host proc macros."""
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1] / "rust"
banned = {"tokio", "async-std", "smol", "reqwest", "hyper", "sqlx", "rusqlite", "diesel", "mkit-server", "commonware-runtime", "commonware-storage"}
rows = [("native", features) for features in ([], ["pack-ruzstd"], ["pack-zstd"], ["pack-ruzstd", "pack-zstd"])]
rows += [("wasm32-unknown-unknown", []), ("wasm32-unknown-unknown", ["pack-ruzstd"])]
allowlist = {line for line in (root.parent / "scripts/primitives-target-dependencies.txt").read_text().splitlines() if line and not line.startswith("#")}
for target, features in rows:
    command = ["cargo", "tree", "--locked", "-p", "mkit-primitives", "--no-default-features", "-e", "normal,build,no-proc-macro", "--prefix", "none"]
    if target != "native":
        command += ["--target", target]
    if features:
        command += ["--features", ",".join(features)]
    output = subprocess.check_output(command, cwd=root, text=True)
    packages = {line.split()[0] for line in output.splitlines() if line.strip()}
    violations = sorted((packages & banned) | (packages - allowlist))
    if violations:
        sys.exit(f"forbidden target dependencies: {violations}")
    if "pack-zstd" not in features and packages & {"zstd", "zstd-safe", "zstd-sys"}:
        sys.exit("native decoder enabled outside the native backend row")
    if ("mkit-ruzstd" in packages) != ("pack-ruzstd" in features):
        sys.exit("pure-Rust decoder feature propagation mismatch")
    if "mkit-core" not in packages:
        sys.exit("graph canary failed: mkit-core absent")
    print(f"primitives graph {target} [{','.join(features) or 'raw'}]: {len(packages)} target/build packages; no server, runtime, HTTP, or database edge")

# The fabricating `synthetic-artifacts` feature must stay out of every shipped
# package's normal and build graph. The fuzz crate enables it, and a positive
# control proves the probe can see it.
FEATURE = "synthetic-artifacts"
shipped = ["mkit-primitives", "mkit-server", "mkit-cli", "mkit-client", "mkit-sync", "mkit-wasm", "mkit-repo-client"]


def primitives_features(package, target=None):
    command = ["cargo", "tree", "--locked", "-p", package, "-e", "normal,build,no-proc-macro",
               "--prefix", "none", "-f", "{p} {f}", "-i", "mkit-primitives"]
    if target:
        command += ["--target", target]
    done = subprocess.run(command, cwd=root, text=True, capture_output=True)
    if done.returncode == 0:
        return done.stdout
    if "did not match any packages" in done.stderr:
        return None  # the package does not depend on mkit-primitives
    sys.exit(f"cargo tree failed for {package}: {done.stderr.strip()}")


for target in (None, "wasm32-unknown-unknown"):
    control = primitives_features("mkit-primitives-fuzz", target)
    if control is None or FEATURE not in control:
        sys.exit(f"graph canary failed: {FEATURE} not visible through the fuzz crate ({target or 'native'})")
for package in shipped:
    for target in (None, "wasm32-unknown-unknown"):
        output = primitives_features(package, target)
        if output is not None and FEATURE in output:
            sys.exit(f"{FEATURE} reaches the {package} production graph")
print(f"{FEATURE}: absent from the production graphs of {', '.join(shipped)}")
