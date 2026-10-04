#!/usr/bin/env python3
"""Keep both independent launch graphs on the server's bounded decoder path."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def check(manifest, features=()):
    command = ["cargo", "metadata", "--locked", "--format-version", "1",
               "--filter-platform", "wasm32-unknown-unknown",
               "--manifest-path", str(ROOT / manifest)]
    if features:
        command += ["--features", ",".join(features)]
    metadata = json.loads(subprocess.check_output(command))
    decoder = [p for p in metadata["packages"] if p["name"] == "ruzstd"]
    expected = (ROOT / "rust/vendor/ruzstd/Cargo.toml").resolve()
    if len(decoder) != 1 or Path(decoder[0]["manifest_path"]).resolve() != expected or decoder[0]["source"] is not None:
        raise SystemExit(f"{manifest}: launch must resolve the patched vendored decoder")
    packages = {p["id"]: p["name"] for p in metadata["packages"]}
    resolved = {packages[node["id"]]: set(node["features"])
                for node in metadata["resolve"]["nodes"]}
    for name in ("mkit-server-worker", "mkit-server", "mkit-core"):
        if "pack-ruzstd" not in resolved[name]:
            raise SystemExit(f"{manifest}: missing {name}/pack-ruzstd")
    for name in ("mkit-server", "mkit-server-worker"):
        if "__test-faults" in resolved[name]:
            raise SystemExit(f"{manifest}: launch enables internal fault injection")
    if "sql" in resolved["mkit-server"]:
        raise SystemExit(f"{manifest}: SQL belongs in the Workers adapter")
    if "pack-zstd" in resolved["mkit-core"]:
        raise SystemExit(f"{manifest}: launch must use the pure-Rust decoder")
    print(f"PASS {manifest}: Worker -> server -> core pack-ruzstd")


if __name__ == "__main__":
    check("apps/vcs-worker/Cargo.toml", ("launch",))
    check("apps/embedded-worker/tests/embedding-conformance/Cargo.toml")
