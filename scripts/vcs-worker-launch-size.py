#!/usr/bin/env python3
"""Measure decoder-enabled release variants locally, with immutable source pins."""
import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps/vcs-worker"
VARIANTS = {
    "minimal": "pack-ruzstd",
    "http": "pack-ruzstd,http-objects",
    "signed": "pack-ruzstd,signed-http-hooks",
    "http-signed": "pack-ruzstd,http-objects,signed-http-hooks",
    "snapshots": "launch",
}
LIMIT = 64 * 1024 * 1024


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    if args.sha != git("rev-parse", "HEAD") or git("status", "--porcelain"):
        raise RuntimeError("use a clean committed candidate SHA")
    if "CARGO_TARGET_DIR" in os.environ:
        raise RuntimeError("CARGO_TARGET_DIR must remain unset")
    scratch = Path(os.environ.get("TMPDIR", ""))
    owned = Path.home() / ".cache/mkit-test-tmp/wp-4-18"
    if not scratch.is_absolute() or not scratch.is_relative_to(owned):
        raise RuntimeError("use the owned WP-4.18 TMPDIR")
    scratch.mkdir(parents=True, exist_ok=True)
    if scratch.resolve() != scratch:
        raise RuntimeError("TMPDIR must contain no symlink")
    run = Path(tempfile.mkdtemp(prefix="launch-sizes-", dir=scratch))
    env = dict(os.environ, CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")
    evidence = {"source_sha": args.sha, "tree_sha": git("rev-parse", "HEAD^{tree}"),
                "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "worker_build": subprocess.check_output(["worker-build", "--version"], text=True).strip(),
                "variants": {}, "result": "RUNNING", "uncompressed_bundle_limit": LIMIT,
                "limit_source": "https://developers.cloudflare.com/changelog/post/2026-09-04-increased-worker-size-limit/",
                "limitations": ["Local emitted Wasm and JavaScript sizes; no remote deployment acceptance",
                                "gzip is deterministic informational encoding, not an upload limit"]}
    print("Evidence directory:", run, flush=True)
    try:
        for variant, features in VARIANTS.items():
            command = ["worker-build", "--release", "--features", features]
            log = run / f"{variant}-build.log"
            with log.open("w") as output:
                subprocess.run(command, cwd=APP, env=env, stdout=output, stderr=output,
                               check=True, timeout=900)
            artifact = run / variant
            shutil.copytree(APP / "build", artifact)
            wasm = artifact / "index_bg.wasm"
            raw = wasm.read_bytes()
            if not raw.startswith(b"\0asm"):
                raise RuntimeError("invalid release wasm")
            files = {str(p.relative_to(artifact)): {"bytes": p.stat().st_size,
                     "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                     for p in artifact.rglob("*") if p.is_file()}
            if not {"index_bg.wasm", "index.js", "worker/shim.mjs"}.issubset(files):
                raise RuntimeError("incomplete release bundle")
            # Include all emitted files conservatively; packaging acceptance is
            # a separate remote gate and is never inferred from this local sum.
            emitted = sum(item["bytes"] for item in files.values())
            if emitted >= LIMIT:
                raise RuntimeError("emitted release files reach the fixed script-size limit")
            evidence["variants"][variant] = {"argv": command, "features": features.split(","),
                "wasm_raw_bytes": len(raw), "wasm_gzip_bytes": len(gzip.compress(raw, mtime=0)),
                "all_emitted_bytes": emitted, "below_local_limit": True, "files": files,
                "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
            print(variant, len(raw), "raw,", evidence["variants"][variant]["wasm_gzip_bytes"], "gzip", flush=True)
        if git("rev-parse", "HEAD") != args.sha or git("status", "--porcelain"):
            raise RuntimeError("candidate changed during measurement")
        evidence["result"] = "PASS"
    except Exception as error:
        evidence["result"] = "FAIL"
        evidence["error"] = str(error)
        raise
    finally:
        evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (run / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
