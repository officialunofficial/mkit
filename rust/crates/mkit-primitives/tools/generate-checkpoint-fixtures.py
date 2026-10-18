#!/usr/bin/env python3
"""Deliberately regenerate the version-3 verification and unsupported-version fixtures.

Run from the repository root. Requires the normal Rust development tools. The
ordinary fixture test compares bytes and never writes; only this command sets
its explicit regeneration destination. Review all resulting bytes and digests.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[4]
fixtures = root / "rust/crates/mkit-primitives/fixtures"
env = dict(os.environ, CARGO_BUILD_JOBS="3", CARGO_PROFILE_DEV_DEBUG="0",
           CARGO_INCREMENTAL="0", MKIT_CHECKPOINT_FIXTURES=str(fixtures / "evidence"))
subprocess.run(["just", "cargo-cached", "test", "-p", "mkit-primitives", "--lib",
                "pack_verify::verify::tests::checkpoints::canonical_verify_checkpoint_fixture", "--", "--exact"],
               cwd=root / "rust", env=env, check=True)
version_path = fixtures / "evidence/checkpoint-version.json"
version = json.loads(version_path.read_text())
version["format_version"] = 4
try:
    import blake3
except ImportError as exc:
    raise SystemExit("Install the Python blake3 package before regenerating fixtures") from exc
version["blake3"] = blake3.blake3((fixtures / "evidence/checkpoint-version.bin").read_bytes()).hexdigest()
version_path.write_text(json.dumps(version, indent=2, sort_keys=True) + "\n")
manifest_path = fixtures / "manifest.toml"
manifest = manifest_path.read_text().replace('type = "verify-checkpoint"\nformat_version = 2', 'type = "verify-checkpoint"\nformat_version = 3')
for name in ("checkpoint-verify", "checkpoint-version"):
    pattern = r'\[\[fixtures\]\]\n(?:(?!\[\[fixtures\]\]).)*?path = "evidence/' + name + r'\.bin"(?:(?!\[\[fixtures\]\]).)*'
    match = re.search(pattern, manifest, re.S)
    if match is None:
        raise SystemExit(f"Missing manifest entry: {name}")
    block = match.group()
    if name == "checkpoint-verify":
        block = block.replace('format_version = 2', 'format_version = 3')
    for extension, key in (("bin", "sha256"), ("json", "semantic_sha256")):
        digest = hashlib.sha256((fixtures / f"evidence/{name}.{extension}").read_bytes()).hexdigest()
        block = re.sub(rf'(?m)^{key} = "[0-9a-f]+"$', f'{key} = "{digest}"', block)
    manifest = manifest[:match.start()] + block + manifest[match.end():]
manifest_path.write_text(manifest)
