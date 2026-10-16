#!/usr/bin/env python3
"""Keep the server's wasm decoder graph on the bounded pure-Rust backend."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def check():
    # Select the server's normal graph. Workspace-wide metadata also unifies
    # native CLI and test dependencies, which intentionally use the C decoder.
    tree = subprocess.check_output([
        "cargo", "tree", "--locked", "--manifest-path", str(ROOT / "rust/Cargo.toml"),
        "-p", "mkit-server", "--target", "wasm32-unknown-unknown",
        "--no-default-features", "--features", "pack-ruzstd", "--edges", "normal",
        "--prefix", "none", "--format", "{p}|{f}",
    ], text=True)
    resolved = {}
    decoder = set()
    for line in tree.splitlines():
        package, features = line.removesuffix(" (*)").split("|", 1)
        name = package.split()[0]
        resolved.setdefault(name, set()).update(features.split(","))
        if name == "ruzstd":
            decoder.add(package)
    expected = ROOT / "rust/vendor/ruzstd"
    if len(decoder) != 1 or f"({expected})" not in next(iter(decoder)):
        raise SystemExit("server must resolve the patched vendored decoder")
    for name in ("mkit-server", "mkit-core"):
        if "pack-ruzstd" not in resolved.get(name, set()):
            raise SystemExit(f"missing {name}/pack-ruzstd")
    forbidden = {"__test-faults", "test-support", "sql"} & resolved["mkit-server"]
    if forbidden:
        raise SystemExit(f"wasm decoder graph enables unexpected server features: {sorted(forbidden)}")
    if "pack-zstd" in resolved["mkit-core"]:
        raise SystemExit("wasm decoder graph must use the pure-Rust decoder")
    print("PASS server -> core pack-ruzstd: vendored decoder, no native/test features")


if __name__ == "__main__":
    check()
