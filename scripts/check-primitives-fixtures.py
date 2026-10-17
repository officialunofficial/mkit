#!/usr/bin/env python3
"""Read-only byte and inventory validation for encoded and semantic fixtures."""
import hashlib
import pathlib
import re
import sys
import tomllib


MAX_FIXTURE_BYTES = 1024 * 1024


def verify_digest(path, name, declared):
    if not isinstance(declared, str) or re.fullmatch(r"[0-9a-f]{64}", declared) is None:
        raise ValueError(f"missing or invalid SHA256 digest: {name}")
    # Read at most one byte beyond the cap, including when a file grows after
    # it was opened. CI checks committed bytes and never rewrites fixtures.
    with path.open("rb") as source:
        contents = source.read(MAX_FIXTURE_BYTES + 1)
    if len(contents) > MAX_FIXTURE_BYTES:
        raise ValueError(f"fixture exceeds {MAX_FIXTURE_BYTES}-byte cap: {name}")
    actual = hashlib.sha256(contents).hexdigest()
    if actual != declared:
        raise ValueError(f"changed fixture bytes: {name} (SHA256 expected {declared}, got {actual})")


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
            verify_digest(path, name, row.get("sha256" if key == "path" else "semantic_sha256"))
            registered.add(name)
    contracts = set()
    for row in manifest.get("contracts", []):
        for key in ("type", "ruleset", "path", "sha256", "spec"):
            if key not in row or not row[key]:
                raise ValueError(f"missing semantic contract metadata: {key}")
        identity = (row["type"], row["ruleset"])
        if identity in contracts:
            raise ValueError(f"duplicate semantic contract: {identity}")
        contracts.add(identity)
        name = row["path"]
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"fixture escapes inventory: {name}")
        if not path.is_file():
            raise ValueError(f"missing fixture: {name}")
        if name in registered:
            raise ValueError(f"duplicate fixture: {name}")
        verify_digest(path, name, row["sha256"])
        registered.add(name)
    actual = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and p != root / "manifest.toml"}
    if actual != registered:
        raise ValueError(f"orphan or missing fixtures: {sorted(actual ^ registered)}")
    formats = {}
    for row in manifest.get("formats", []):
        for key in ("type", "format_version", "decoder", "fuzz_target", "spec"):
            if key not in row or not row[key]:
                raise ValueError(f"missing format metadata: {key}")
        identity = (row["type"], row["format_version"])
        if identity in formats:
            raise ValueError(f"duplicate encoded format: {identity}")
        formats[identity] = row
    covered = {(row["type"], row["format_version"]) for row in manifest.get("fixtures", [])}
    if covered != set(formats):
        raise ValueError(f"unregistered or uncovered encoded formats: {sorted(covered ^ set(formats))}")
    return len(manifest.get("fixtures", []))


if __name__ == "__main__":
    root = pathlib.Path(__file__).resolve().parents[1] / "rust/crates/mkit-primitives/fixtures"
    try:
        encoded = check(root)
        semantic = len(tomllib.loads((root / "manifest.toml").read_text()).get("contracts", []))
        print(f"primitives fixtures: {encoded} encoded, {semantic} semantic contracts (read-only)")
    except (ValueError, KeyError) as error:
        sys.exit(str(error))
