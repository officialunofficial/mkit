#!/usr/bin/env python3
"""Release embedding example on pinned local workerd; never contacts a cloud account."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps/embedded-worker"
WRANGLER = "4.134.0"


def artifact_hashes(app=APP):
    artifacts = {}
    for name in ["build/index_bg.wasm", "build/index.js", "build/worker/shim.mjs", "build/package.json"]:
        path = app / name
        if not path.is_file():
            raise RuntimeError(f"missing embedded release artifact: {path}")
        data = path.read_bytes()
        if not data:
            raise RuntimeError(f"empty embedded release artifact: {path}")
        if name.endswith(".wasm") and not data.startswith(b"\0asm\x01\0\0\0"):
            raise RuntimeError(f"invalid embedded release wasm: {path}")
        artifacts[name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    return artifacts


def request_json(url, body=None):
    headers = {"content-type": "application/json", "connect-protocol-version": "1"}
    request = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.load(response)


def wait_ready(url, process, timeout=120, body=b"{}"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("local wrangler exited before readiness")
        try:
            return request_json(url, body)
        except (urllib.error.URLError, TimeoutError):
            time.sleep(0.25)
    raise RuntimeError("local wrangler did not become ready")


def stop(process):
    if process is None:
        return
    # Only this script's own detached process group.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait(timeout=10)
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-build", action="store_true", help="use the already built release bundle and runner")
    parser.add_argument("--port", type=int, default=int(os.environ.get("VCS_CONFORMANCE_PORT", "8795")))
    args = parser.parse_args()
    scratch = Path(os.environ.get("TMPDIR", Path.home() / ".cache/mkit-test-tmp/reference-embedding"))
    scratch.mkdir(parents=True, exist_ok=True)
    if scratch.resolve() != scratch or scratch.is_symlink():
        raise RuntimeError("embedding scratch must be an absolute nonsymlink path")
    work = Path(tempfile.mkdtemp(prefix="runtime-", dir=scratch))
    env = dict(os.environ, TMPDIR=str(scratch), CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
               WRANGLER_SEND_METRICS="false", WRANGLER_REGISTRY_PATH=str(work / "registry"))
    if env.get("CARGO_TARGET_DIR"):
        raise RuntimeError("CARGO_TARGET_DIR must remain unset")
    origin = f"http://127.0.0.1:{args.port}"
    base = f"{origin}/_embedding/mkit"
    runner = ROOT / "rust/target/debug/mkit-server-conformance"
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    if dirty:
        raise RuntimeError("commit the candidate first; embedding evidence requires a clean worktree")
    with (work / "build.log").open("w") as log:
        if not args.no_build:
            subprocess.run(["cargo", "build", "--locked", "--manifest-path", str(ROOT / "rust/Cargo.toml"),
                            "-p", "mkit-server-conformance", "--bin", "mkit-server-conformance"],
                           cwd=ROOT / "rust", env=env, stdout=log, stderr=log, check=True)
            subprocess.run(["worker-build", "--release"], cwd=APP, env=env, stdout=log, stderr=log, check=True)
    artifacts = artifact_hashes()
    # Copy the example's config into this run's private directory with absolute
    # module paths. Different ports, registry and state keep other runs isolated.
    configs = []
    for source in [APP / "wrangler.jsonc"]:
        text = "\n".join(line for line in source.read_text().splitlines() if not line.lstrip().startswith("//"))
        config = json.loads(text)
        config["main"] = str((source.parent / config["main"]).resolve())
        config["dev"] = {"port": args.port if source.parent == APP else args.port + 1}
        if source.parent == APP:
            config["vars"]["AUTH_AUDIENCE"] = origin
        target = work / f"{config['name']}.json"
        target.write_text(json.dumps(config))
        configs.append(target)

    def command(config, port, state):
        return ["npx", "--yes", f"wrangler@{WRANGLER}", "dev", "--local",
                "--config", str(config), "--ip", "127.0.0.1", "--port", str(port),
                "--persist-to", str(work / state), "--show-interactive-dev-session=false"]

    process = None
    try:
        with (work / "wrangler.log").open("w") as log:
            process = subprocess.Popen(command(configs[0], args.port, "state"),
                                       cwd=APP, env=env, stdout=log, stderr=log,
                                       start_new_session=True)
            wait_ready(f"{base}/grpc.health.v1.Health/Check", process)
            common = [str(runner), "wire", "--base-url", base, "--auth", "auth-v2", "--audience", origin,
                      "--repository", "default", "--random-signer", "--milestone", "M1", "--sharding", "single",
                      "--features", "multipart,tickets", "--list-refs", "0"]
            for case in ["multipart.three_parts", "auth.v2_wrong_audience",
                         "tickets.advance_marker_then_upload"]:
                result = subprocess.run([*common, "--filter", case], cwd=ROOT / "rust", env=env,
                                        capture_output=True, text=True, timeout=180)
                (work / f"{case}.tap").write_text(result.stdout + result.stderr)
                if result.returncode or "# SKIP" in result.stdout or f"ok 1 - {case}" not in result.stdout:
                    raise RuntimeError(f"embedding {case} failed; see {work}")
                print(f"PASS embedded release {case}")
            before_admissions = (work / "wrangler.log").read_text().count("REFERENCE admit ")
            # Auth remains bound to the public audience despite the in-process
            # Request URL. Signing for that internal origin must be rejected.
            internal = common.copy()
            internal[internal.index("--audience") + 1] = "https://embedded.invalid"
            rejected = subprocess.run([*internal, "--filter", "multipart.three_parts"],
                                      cwd=ROOT / "rust", env=env, capture_output=True, text=True, timeout=30)
            (work / "internal-audience-rejected.tap").write_text(rejected.stdout + rejected.stderr)
            if rejected.returncode == 0 or "unauthenticated" not in rejected.stdout + rejected.stderr:
                raise RuntimeError("internal audience was not rejected as unauthenticated")
            assert (work / "wrangler.log").read_text().count("REFERENCE admit ") == before_admissions, "bad audience reached admission"
            deadline = time.monotonic() + 30
            while "REFERENCE outcome committed" not in (work / "wrangler.log").read_text():
                if time.monotonic() >= deadline:
                    raise RuntimeError("custom DO outcome sink did not deliver after AdvanceRefs")
                time.sleep(0.25)
            assert "REFERENCE admit" in (work / "wrangler.log").read_text(), "in-process admission not reached"
            if artifact_hashes() != artifacts:
                raise RuntimeError("embedded release artifacts changed during the conformance run")
            if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != sha \
                    or subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True):
                raise RuntimeError("embedding source changed during the conformance run")
            evidence = {"source_sha": sha, "dirty_worktree": dirty.splitlines(), "wrangler": WRANGLER,
                        "features": "default (no test-faults)", "origin": origin,
                        "artifacts": artifacts,
                        "wasm_sha256": artifacts["build/index_bg.wasm"]["sha256"],
                        "js_sha256": artifacts["build/index.js"]["sha256"],
                        "shim_sha256": artifacts["build/worker/shim.mjs"]["sha256"],
                        "cases": ["multipart.three_parts", "auth.v2_wrong_audience",
                                  "tickets.advance_marker_then_upload", "internal_audience_rejected",
                                  "custom_outcome_sink"]}
            (work / "evidence.json").write_text(json.dumps(evidence, indent=2))
            print("PASS in-process hooks, DO outcome sink and public audience isolation")
    finally:
        stop(process)
        print(f"Embedding evidence: {work}")


if __name__ == "__main__":
    main()
