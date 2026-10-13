#!/usr/bin/env python3
"""Reject build-dir configuration in tracked Cargo, Docker, and CI inputs."""

import argparse
from pathlib import Path
import re
import subprocess
import sys


def is_input(path):
    name = path.name.lower()
    return ((".cargo" in path.parts and (name == "config" or path.suffix == ".toml"))
            or name in ("cargo.toml", "rust-toolchain.toml")
            or name.startswith("dockerfile") or name.endswith(".dockerfile")
            or (path.suffix in (".yml", ".yaml")
                and path.parts[0] in (".github", "cloudbuild")))


def check(root):
    files = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    # Conservative text scan includes comments and quoted/dotted/inline TOML keys.
    pattern = re.compile(r"build[\s\"'.]*[-_]dir|CARGO_BUILD_BUILD_DIR|MKIT_BUILD_ROOT", re.I)
    failed = False
    for name in files.decode("utf-8", errors="surrogateescape").split("\0"):
        path = Path(name)
        if not name or not is_input(path):
            continue
        for number, line in enumerate((root / path).read_text().splitlines(), 1):
            if pattern.search(line):
                print(f"{path}:{number}: build-dir must be set only by opt-in local recipes", file=sys.stderr)
                failed = True
    if not failed:
        print("ok: tracked Cargo, Docker, and CI inputs do not set build-dir")
    return int(failed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    sys.exit(check(parser.parse_args().root))
