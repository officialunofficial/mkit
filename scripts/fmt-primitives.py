#!/usr/bin/env python3
"""Format macro-declared module files that cargo fmt does not discover."""
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1] / "rust"
files = sorted((root / "crates/mkit-primitives").rglob("*.rs"))
# Target output must never be fed back to the formatter.
files = [path for path in files if "target" not in path.parts]
args = ["rustfmt", "--edition", "2024"]
if "--check" in sys.argv:
    args.append("--check")
subprocess.run(args + [str(path) for path in files], cwd=root, check=True)
