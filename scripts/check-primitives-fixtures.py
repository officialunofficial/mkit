#!/usr/bin/env python3
"""Read-only inventory validation; encoded formats register before landing."""
import pathlib
import sys
import tomllib


def check(root):
    manifest = tomllib.loads((root / "manifest.toml").read_text())
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported fixture manifest schema")
    registered = set()
    for row in manifest.get("fixtures", []):
        for key in ("type", "format_version", "ruleset", "profile", "decode_config", "expected", "spec"):
            if key not in row:
                raise ValueError(f"missing fixture metadata: {key}")
        for key in ("path", "semantic"):
            name = row[key]
            path = root / name
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                raise ValueError(f"fixture escapes inventory: {name}")
            if not path.is_file():
                raise ValueError(f"missing fixture: {name}")
            if key == "path" and name in registered:
                raise ValueError(f"duplicate fixture: {name}")
            registered.add(name)
    actual = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and p.name != "manifest.toml"}
    if actual != registered:
        raise ValueError(f"orphan or missing fixtures: {sorted(actual ^ registered)}")
    return len(manifest.get("fixtures", []))


if __name__ == "__main__":
    root = pathlib.Path(__file__).resolve().parents[1] / "rust/crates/mkit-primitives/fixtures"
    try:
        print(f"primitives fixtures: {check(root)} registered (read-only)")
    except (ValueError, KeyError) as error:
        sys.exit(str(error))
