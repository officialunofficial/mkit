#!/usr/bin/env python3
"""Prove the bounded decoder is a named dependency with no workspace patches."""
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parent.parent
manifests = subprocess.check_output(
    ["git", "ls-files", "-z", "**/Cargo.toml"], cwd=ROOT
).decode().split("\0")
for name in filter(None, manifests):
    manifest = tomllib.loads((ROOT / name).read_text())
    if "patch" in manifest:
        raise SystemExit(f"workspace patches are not inherited: remove [patch] from {name}")

for target in (None, "wasm32-unknown-unknown"):
    command = [
        "cargo", "tree", "--locked", "--manifest-path", str(ROOT / "rust/Cargo.toml"),
        "-p", "mkit-core", "--no-default-features", "--features", "pack-ruzstd",
        "-e", "normal", "--prefix", "none", "--format", "{p}",
    ]
    if target:
        command += ["--target", target]
    tree = subprocess.check_output(command, cwd=ROOT, text=True)
    names = {line.split()[0] for line in tree.splitlines() if line.strip()}
    if "ruzstd" in names or "mkit-ruzstd" not in names:
        raise SystemExit("pack-ruzstd must select mkit-ruzstd and exclude upstream ruzstd")
    # Print package identities without checkout paths for portable hand-off evidence.
    identity = next(" ".join(line.split()[:2]) for line in tree.splitlines()
                    if line.startswith("mkit-ruzstd "))
    print(f"pack-ruzstd [{target or 'native'}]: {identity}; upstream ruzstd absent")
print("PASS: no [patch] tables in tracked Cargo manifests")
