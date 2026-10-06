#!/usr/bin/env python3
"""Run real Paid Workers indexed writes against an optimized local release Worker."""
import http.client
import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps/vcs-worker"
WRANGLER = "4.134.0"
AUDIENCE = "https://vcs.launch.invalid"
SEED = "5e" * 32
RUN_ID = "launch-runtime"
REQUIRED_CASE = "launch.indexed_verification_commits"


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(command, cwd, log, env, evidence):
    evidence["commands"].append({"argv": command, "cwd": str(cwd),
                                 "log": str(log.relative_to(evidence["directory"]))})
    with log.open("w") as output:
        process = subprocess.run(command, cwd=cwd, env=env, stdout=output,
                                 stderr=subprocess.STDOUT, timeout=900)
    if process.returncode:
        raise RuntimeError(f"command failed ({process.returncode}); see {log}")


def request(origin, path, body=None):
    headers = {"content-type": "application/json", "connect-protocol-version": "1"}
    req = urllib.request.Request(origin + path, data=body, headers=headers,
                                 method="POST" if body is not None else "GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=5) as response:
            return response.status, response.read(65537)
    except urllib.error.HTTPError as response:
        return response.code, response.read(65537)


def stop(process):
    # Only the process group this invocation created belongs to this fixture.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)


def extracted_object(state, object_id, size):
    """Read pinned Miniflare's local metadata; never a cloud or production RPC."""
    matches = []
    # Wrangler 4.134.0's Miniflare R2 schema is _mf_objects(key, size, ...).
    # Restrict inspection to R2 databases, not the application's DO tables.
    databases = [path for path in state.rglob("*.sqlite") if "r2" in path.parts]
    for path in databases:
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as database:
            tables = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "_mf_objects" in tables:
                rows = database.execute("SELECT key, size FROM _mf_objects WHERE key = ?",
                                        ("objects/" + object_id,)).fetchall()
                matches += [{"database": str(path.relative_to(state)), "key": key, "size": length}
                            for key, length in rows]
    if len(matches) != 1 or matches[0]["size"] != size:
        raise RuntimeError(f"extracted R2 object missing or wrong size: {matches}")
    return matches[0]


def run_fixture(namespace, mode, port, run, runner, artifact, env, evidence):
    folder = run / f"{mode}-{namespace}"
    folder.mkdir()
    origin = f"http://127.0.0.1:{port}"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))
    vars_ = {
        "AUTH_AUDIENCE": AUDIENCE, "LAUNCH_PROFILE": "paid-workers", "WORKERS_PLAN": "paid",
        "INDEXED_MODE": "true", "ADDRESSING": "multi", "SHARDING": "d34",
        "NAMESPACE_POLICY": namespace, "RETENTION": "permanent",
        "STORAGE_LEASES": "false", "GC_ENABLED": "false",
        "TICKET_KEYS": "launch-ticket " + "11" * 32,
    }
    auth = ["--auth", "auth-v2", "--audience", AUDIENCE, "--repository", "default",
            "--signer-seed-hex", SEED, "--run-id", RUN_ID]
    if namespace == "allowlist":
        text = subprocess.check_output([str(runner), "allowlist", *auth], cwd=ROOT,
                                       env=env, text=True)
        vars_["NAMESPACE_ALLOWLIST"] = ",".join(text.splitlines())
    else:
        vars_["UNSAFE_OPEN_NAMESPACES"] = "true"
    if mode == "http":
        vars_.update({"HTTP_OBJECTS": "true", "URL_TOKEN_KEYS": "active " + "22" * 32})
    classes = [("REFSTORE", "RefStore"), ("NS_COORD", "NsCoordinator"),
               ("REF_SHARD", "RefShard"), ("REPO_INDEX", "RepoIndexShard"),
               ("CONTENT_INDEX", "ContentIndexShard")]
    config = {
        "name": "mkit-launch-runtime", "main": str(artifact / "worker/shim.mjs"),
        "compatibility_date": "2026-09-09", "build": {"command": "true"}, "vars": vars_,
        "r2_buckets": [{"binding": "STORAGE", "bucket_name": "launch-objects"},
                       {"binding": "BACKUPS", "bucket_name": "launch-backups"}],
        "durable_objects": {"bindings": [{"name": binding, "class_name": cls}
                                          for binding, cls in classes]},
        "migrations": [{"tag": "v1", "new_sqlite_classes": [cls for _, cls in classes]}],
    }
    config_path = folder / "wrangler.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    fixture = {"namespace_policy": namespace, "mode": mode,
               "config_sha256": digest(config_path), "result": "RUNNING",
               "checks": [], "cases": []}
    evidence["fixtures"].append(fixture)
    command = ["npx", "--yes", "wrangler@" + WRANGLER, "dev", "--local", "--config",
               str(config_path), "--ip", "127.0.0.1", "--port", str(port),
               "--persist-to", str(folder / "state"), "--show-interactive-dev-session=false"]
    evidence["commands"].append({"argv": command, "cwd": str(APP),
                                 "log": str((folder / "wrangler.log").relative_to(run))})
    with (folder / "wrangler.log").open("w") as output:
        process = subprocess.Popen(command, cwd=APP, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + 120
            while True:
                if process.poll() is not None:
                    raise RuntimeError("wrangler exited; see " + str(folder / "wrangler.log"))
                try:
                    status, body = request(origin,
                                           "/mkit.transport.v1.TransportService/GetServerInfo", b"{}")
                    if status == 200:
                        break
                    (folder / "startup-response.json").write_bytes(body)
                except (urllib.error.URLError, TimeoutError, ConnectionError, http.client.HTTPException):
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("release launch startup timed out; see " + str(folder))
                time.sleep(0.25)
            (folder / "discovery.json").write_bytes(body)
            info = json.loads(body)
            for name, expected in {"indexedMode": True, "leases": False, "asyncInspection": False,
                                   "namespacePolicy": namespace,
                                   "beginUploadThresholdBytes": "0"}.items():
                if info.get(name) != expected:
                    raise RuntimeError(f"discovery {name}: {info.get(name)!r}, expected {expected!r}")
            if info.get("inspectionMaxObjects") is not None or info.get("receiptPublicKey"):
                raise RuntimeError("inactive inspection or receipt capability advertised")
            if any(value for key, value in info.items() if "proof" in key.lower()):
                raise RuntimeError("release Worker advertises unsupported proof capability")
            status, body = request(origin, "/__mkit_test/stats")
            if status == 200:
                raise RuntimeError("release artifact exposes test-faults stats")
            fixture["checks"] += ["Paid Workers indexed discovery", "leases/async disabled",
                                   "threshold zero", "no inspector/receipt/proof claim",
                                   "test-faults route absent"]
            features = "indexed-async,indexed-mode,multi-repo,tickets,timers"
            if mode == "http":
                features += ",http-objects"
            for filter_ in ["info.", REQUIRED_CASE]:
                tap = folder / (filter_.replace(".", "-") + ".tap")
                invoke([str(runner), "wire", "--base-url", origin, *auth, "--atomic-advance",
                        "--fresh-target", "--milestone", "M4", "--sharding", "d34",
                        "--max-pack-bytes", "1073741824", "--features", features,
                        "--filter", filter_], ROOT, tap, env, evidence)
                cases = re.findall(r"^(ok|not ok) \d+ - ([^\n]+)", tap.read_text(), re.MULTILINE)
                if not cases or any(verdict != "ok" or "# SKIP" in name for verdict, name in cases):
                    raise RuntimeError("required release cases skipped or failed; see " + str(tap))
                names = [name.split(" #", 1)[0] for _, name in cases]
                expected = ["info.shape_and_policy", "info.ignores_repository_header"] if filter_ == "info." else [REQUIRED_CASE]
                if names != expected:
                    raise RuntimeError(f"unexpected case execution: {names}; wanted {expected}")
                fixture["cases"] += [{"name": name, "result": "PASS"} for name in names]
                if filter_ == REQUIRED_CASE:
                    note = re.search(r"extracted_blob=([0-9a-f]{64}) extracted_blob_bytes=(\d+)", tap.read_text())
                    if note is None:
                        raise RuntimeError("release case omitted the extraction identity")
                    fixture["extraction"] = extracted_object(folder / "state", note[1], int(note[2]))
                    fixture["checks"].append("actual extracted object in local R2 metadata")
            fixture["result"] = "PASS"
        except Exception:
            fixture["result"] = "FAIL"
            raise
        finally:
            stop(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True, help="exact committed clean candidate")
    parser.add_argument("--namespace", choices=["both", "allowlist", "any"], default="both")
    parser.add_argument("--mode", choices=["minimal", "http", "both"], default="both")
    args = parser.parse_args()
    head = git("rev-parse", "HEAD")
    if head != args.sha or len(args.sha) != 40:
        raise RuntimeError("--sha must equal current immutable HEAD: " + head)
    if git("status", "--porcelain", "--untracked-files=normal"):
        raise RuntimeError("commit the candidate before recording release evidence")
    if "CARGO_TARGET_DIR" in os.environ:
        raise RuntimeError("CARGO_TARGET_DIR must remain unset")
    scratch = Path(os.environ.get("TMPDIR", ""))
    owned = Path.home() / ".cache/mkit-test-tmp/wp-4-18"
    if not scratch.is_absolute() or not scratch.is_relative_to(owned):
        raise RuntimeError("TMPDIR must be under ~/.cache/mkit-test-tmp/wp-4-18")
    scratch.mkdir(parents=True, exist_ok=True)
    if scratch.resolve() != scratch:
        raise RuntimeError("TMPDIR must not contain symlinks")
    port_text = os.environ.get("VCS_CONFORMANCE_PORT", "")
    if not port_text.isdecimal() or not 1024 <= int(port_text) <= 65535:
        raise RuntimeError("set a private VCS_CONFORMANCE_PORT in 1024..65535")
    runner = ROOT / "rust/target/debug/mkit-server-conformance"
    run = Path(tempfile.mkdtemp(prefix="launch-runtime-", dir=scratch))
    env = dict(os.environ, CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
               WRANGLER_SEND_METRICS="false", WRANGLER_REGISTRY_PATH=str(run / "registry"))
    versions = {}
    for tool in ["cargo", "rustc", "node", "worker-build"]:
        try:
            versions[tool] = subprocess.check_output([tool, "--version"], cwd=ROOT, env=env,
                                                    stderr=subprocess.STDOUT, text=True,
                                                    timeout=10).strip()
        except (OSError, subprocess.SubprocessError):
            versions[tool] = "UNAVAILABLE"
    evidence = {"schema": 1, "candidate_sha": head, "tree_sha": git("rev-parse", "HEAD^{tree}"),
                "base_sha": git("merge-base", "HEAD", "origin/feat/mkit-server"),
                "origin_feature_sha": git("rev-parse", "origin/feat/mkit-server"),
                "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "directory": str(run), "wrangler_version": WRANGLER,
                "tool_versions": versions,
                "runner_sha256": None, "commands": [], "fixtures": [],
                "result": "RUNNING", "launch_matrix_result": "UNRUN",
                "limitations": ["Local workerd and R2 emulation, no deployed platform resource claim",
                                "Raw-only PackWriter fixture; not native CLI default compressed push/clone",
                                "Single-pack scheduled verification/extraction and paired-ref publication",
                                "No multi-pack overlap/delta/recovery/inspection/admin/takedown/settlement coverage",
                                "No whole-dispatch or whole-alarm physical-call instrumentation in this lane"]}
    print("Evidence directory:", run, flush=True)
    try:
        import shutil
        # Build at the same pin, rather than trusting a potentially stale runner.
        invoke(["cargo", "build", "--locked", "-p", "mkit-server-conformance", "--bin",
                "mkit-server-conformance"], ROOT / "rust", run / "runner-build.log", env, evidence)
        evidence["runner_sha256"] = digest(runner)
        modes = ["minimal", "http"] if args.mode == "both" else [args.mode]
        namespaces = ["allowlist", "any"] if args.namespace == "both" else [args.namespace]
        for mode in modes:
            build = ["worker-build", "--release", "--features", "pack-ruzstd"]
            if mode == "http":
                build[-1] += ",http-objects"
            invoke(build, APP, run / (mode + "-build.log"), env, evidence)
            artifact = run / (mode + "-artifact")
            # The shim imports ../index.js, which loads ../index_bg.wasm.
            # Preserve and hash the complete worker-build tree.
            shutil.copytree(APP / "build", artifact)
            hashes = {str(path.relative_to(artifact)): digest(path)
                      for path in artifact.rglob("*") if path.is_file()}
            wasm = artifact / "index_bg.wasm"
            if not hashes or not all(path.is_file() for path in
                                     [artifact / "worker/shim.mjs", artifact / "index.js", wasm]):
                raise RuntimeError("worker-build produced no complete release artifact")
            wasm_bytes = wasm.read_bytes()
            if not wasm_bytes.startswith(b"\0asm"):
                raise RuntimeError("worker-build emitted an invalid wasm artifact")
            evidence.setdefault("artifacts", {})[mode] = {
                "features": ["pack-ruzstd"] if mode == "minimal" else ["http-objects", "pack-ruzstd"], "sha256": hashes,
                "wasm_raw_bytes": len(wasm_bytes),
                "wasm_gzip_bytes": len(gzip.compress(wasm_bytes, compresslevel=9, mtime=0))}
            for namespace in namespaces:
                run_fixture(namespace, mode, int(port_text), run, runner, artifact, env, evidence)
        if git("rev-parse", "HEAD") != head or git("status", "--porcelain", "--untracked-files=normal"):
            raise RuntimeError("candidate changed during execution; evidence invalidated")
        evidence["result"] = "PASS"
    except Exception as error:
        evidence["result"] = "FAIL"
        evidence["error"] = str(error)
        raise
    finally:
        evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evidence["log_sha256"] = {str(path.relative_to(run)): digest(path)
                                  for path in run.rglob("*")
                                  if path.is_file() and path.suffix in {".log", ".tap", ".json"}
                                  and path.name != "evidence.json"}
        (run / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("Release R1/R2 component PASS; full matrix remains UNRUN:", run / "evidence.json")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as error:
        print("release launch probe failed:", error, file=sys.stderr)
        sys.exit(1)
