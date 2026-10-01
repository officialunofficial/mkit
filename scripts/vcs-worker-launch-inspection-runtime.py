#!/usr/bin/env python3
"""Ordinary release signed Inspect and mounted scanner evidence, local only."""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps/vcs-worker"
FIXTURE = APP / "tests/launch-inspection"
spec = importlib.util.spec_from_file_location("release_runtime", ROOT / "scripts/vcs-worker-launch-runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
MODES = ("pass", "reject", "redirect", "oversize", "stall", "body")


def get_json(url, timeout=5):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as response:
        return json.loads(response.read(2097153))


def run_mode(mode, port, run, artifact, runner, env, evidence):
    folder = run / mode
    folder.mkdir()
    origin = f"http://127.0.0.1:{port}"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))
    ready = folder / "receiver-ready.json"
    fixture_env = dict(env, INSPECTION_MODE=mode, INSPECTION_WORKER_ORIGIN=origin,
                       INSPECTION_READY_FILE=str(ready))
    result = {"mode": mode, "result": "RUNNING", "checks": [], "cases": []}
    evidence["fixtures"].append(result)
    with (folder / "receiver.log").open("w") as receiver_log:
        receiver = subprocess.Popen(["node", str(FIXTURE / "receiver.mjs")], cwd=ROOT,
                                    env=fixture_env, stdout=receiver_log,
                                    stderr=subprocess.STDOUT, start_new_session=True)
        worker = None
        try:
            deadline = time.monotonic() + 15
            while not ready.is_file():
                if receiver.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("receiver failed to start; see " + str(folder))
                time.sleep(0.1)
            receiver_info = json.loads(ready.read_text())
            wrapper = (FIXTURE / "wrapper.mjs").read_text().replace(
                "__RELEASE_SHIM__", str(artifact / "worker/shim.mjs")).replace(
                "__RECEIVER_ORIGIN__", receiver_info["origin"])
            wrapper_path = folder / "wrapper.mjs"
            wrapper_path.write_text(wrapper)
            auth = ["--auth", "auth-v2", "--audience", runtime.AUDIENCE,
                    "--repository", "default", "--signer-seed-hex", runtime.SEED,
                    "--run-id", runtime.RUN_ID]
            allowlist = subprocess.check_output([str(runner), "allowlist", *auth],
                                               cwd=ROOT, env=env, text=True)
            variables = {
                "AUTH_AUDIENCE": runtime.AUDIENCE, "LAUNCH_PROFILE": "uno",
                "WORKERS_PLAN": "paid", "INDEXED_MODE": "true", "ADDRESSING": "multi",
                "SHARDING": "d34", "NAMESPACE_POLICY": "allowlist",
                "NAMESPACE_ALLOWLIST": ",".join(allowlist.splitlines()), "RETENTION": "permanent",
                "STORAGE_LEASES": "false", "GC_ENABLED": "false",
                "TICKET_KEYS": "launch-ticket " + "11" * 32,
                "HTTP_OBJECTS": "true", "URL_TOKEN_KEYS": "active " + "22" * 32,
                "HOOK_ROLES": "inspect", "HOOK_URL": "https://inspection.launch.invalid",
                "MKIT_HOOK_KEY": "launch-hook " + "55" * 32,
                "HOOK_TIMEOUT_MS": "30000" if mode == "pass" else "1000",
                "INSPECT_MODE": "sync", "INSPECT_ON_UNAVAILABLE": "fail_closed",
                "SCANNER_RETRIEVAL": "true",
                "SCANNER_RETRIEVAL_KEYS": "active launch-retrieval " + "66" * 32,
                "SCANNER_KEYS": receiver_info["scanner_public_key"],
            }
            classes = [("REFSTORE", "RefStore"), ("NS_COORD", "NsCoordinator"),
                       ("REF_SHARD", "RefShard"), ("REPO_INDEX", "RepoIndexShard"),
                       ("CONTENT_INDEX", "ContentIndexShard")]
            config = {"name": "mkit-launch-inspection", "main": str(wrapper_path),
                      "compatibility_date": "2026-09-09", "build": {"command": "true"},
                      "vars": variables,
                      "r2_buckets": [{"binding": "STORAGE", "bucket_name": "inspection-objects"},
                                     {"binding": "BACKUPS", "bucket_name": "inspection-backups"}],
                      "durable_objects": {"bindings": [{"name": binding, "class_name": cls}
                                                         for binding, cls in classes]},
                      "migrations": [{"tag": "v1", "new_sqlite_classes": [cls for _, cls in classes]}]}
            config_path = folder / "wrangler.json"
            config_path.write_text(json.dumps(config, indent=2) + "\n")
            result["config_sha256"] = runtime.digest(config_path)
            result["wrapper_sha256"] = runtime.digest(wrapper_path)
            command = ["npx", "--yes", "wrangler@" + runtime.WRANGLER, "dev", "--local",
                       "--config", str(config_path), "--ip", "127.0.0.1", "--port", str(port),
                       "--persist-to", str(folder / "state"), "--show-interactive-dev-session=false"]
            evidence["commands"].append({"argv": command, "cwd": str(APP),
                                         "log": str((folder / "wrangler.log").relative_to(run))})
            with (folder / "wrangler.log").open("w") as worker_log:
                worker = subprocess.Popen(command, cwd=APP, env=env, stdout=worker_log,
                                          stderr=subprocess.STDOUT, start_new_session=True)
                deadline = time.monotonic() + 120
                while True:
                    if worker.poll() is not None:
                        raise RuntimeError("wrangler exited; see " + str(folder))
                    try:
                        status, body = runtime.request(origin,
                            "/mkit.transport.v1.TransportService/GetServerInfo", b"{}")
                        if status == 200:
                            break
                    except (OSError, TimeoutError):
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError("release inspection startup timed out")
                    time.sleep(0.25)
                info = json.loads(body)
                (folder / "discovery.json").write_bytes(body)
                if not info.get("indexedMode") or info.get("asyncInspection") is not False:
                    raise RuntimeError("wrong indexed/sync capability")
                if int(info.get("inspectionMaxObjects", 0)) != 10000:
                    raise RuntimeError("active inspector bound missing/wrong")
                if runtime.request(origin, "/__mkit_test/stats")[0] == 200:
                    raise RuntimeError("release exposes test-faults")
                required_case = runtime.REQUIRED_CASE if mode == "pass" else "launch.inspection_rejects_advance"
                tap = folder / "wire.tap"
                runtime.invoke([str(runner), "wire", "--base-url", origin, *auth,
                    "--atomic-advance", "--fresh-target", "--milestone", "M4", "--sharding", "d34",
                    "--max-pack-bytes", "1073741824", "--features",
                    "indexed-async,indexed-mode,multi-repo,tickets,timers,http-objects,sync-inspection",
                    "--filter", required_case], ROOT, tap, env, evidence)
                cases = re.findall(r"^(ok|not ok) \d+ - ([^\n]+)", tap.read_text(), re.MULTILINE)
                if cases != [("ok", required_case)]:
                    raise RuntimeError("required release inspection case failed/skipped/missing")
                result["cases"] = [{"name": required_case, "result": "PASS"}]
                if mode == "pass":
                    get_json(receiver_info["origin"] + "/terminal-check", timeout=35)
                receiver_state = get_json(receiver_info["origin"] + "/state")
                (folder / "receiver-transcript.json").write_text(json.dumps(receiver_state, indent=2) + "\n")
                if receiver_state["failures"] or not receiver_state["hooks"]:
                    raise RuntimeError("independent receiver assertions failed or Inspect absent")
                if receiver_state["redirected"]:
                    raise RuntimeError("hook followed a redirect")
                if mode in {"stall", "body"} and receiver_state["closed"] < len(receiver_state["hooks"]):
                    raise RuntimeError("receiver did not observe timed-out hook connection closure")
                if mode == "pass" and not all(hook.get("independent_exact_set")
                                                for hook in receiver_state["hooks"]):
                    raise RuntimeError("complete independently decoded set unproven")
                result["checks"] = ["ordinary optimized release route", "active sync fail-closed inspector",
                    "Ed25519 over exact BLAKE3 body/canonical digest", "hook audience and fresh nonces"]
                if mode == "pass":
                    result["checks"] += ["assigned raw-pack ranges and exact independent Blob set",
                        "seven uniform scanner denial cases", "consumed ticket denies retrieval",
                        "real scheduled verification/extraction and published paired refs"]
                else:
                    result["checks"] += ["synchronous refusal leaves writer/public refs absent",
                                         "redirect not followed" if mode == "redirect" else "fail-closed verdict"]
                result["result"] = "PASS"
        except Exception:
            result["result"] = "FAIL"
            if ready.is_file():
                try:
                    receiver_state = get_json(json.loads(ready.read_text())["origin"] + "/state")
                    (folder / "receiver-transcript.json").write_text(json.dumps(receiver_state, indent=2) + "\n")
                except (OSError, ValueError):
                    pass
            raise
        finally:
            if worker is not None:
                runtime.stop(worker)
            runtime.stop(receiver)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--mode", choices=("all", *MODES), default="all")
    args = parser.parse_args()
    head = runtime.git("rev-parse", "HEAD")
    if head != args.sha or len(head) != 40 or runtime.git("status", "--porcelain"):
        raise RuntimeError("--sha must pin a committed clean candidate")
    if "CARGO_TARGET_DIR" in os.environ:
        raise RuntimeError("CARGO_TARGET_DIR must remain unset")
    scratch = Path(os.environ.get("TMPDIR", ""))
    owned = Path.home() / ".cache/mkit-test-tmp/wp-4-18"
    if not scratch.is_absolute() or not scratch.is_relative_to(owned):
        raise RuntimeError("TMPDIR must be under ~/.cache/mkit-test-tmp/wp-4-18")
    scratch.mkdir(parents=True, exist_ok=True)
    if scratch.resolve() != scratch:
        raise RuntimeError("TMPDIR must not contain symlinks")
    port = os.environ.get("VCS_CONFORMANCE_PORT", "")
    if not port.isdecimal() or not 1024 <= int(port) <= 65535:
        raise RuntimeError("set a private VCS_CONFORMANCE_PORT")
    run = Path(tempfile.mkdtemp(prefix="launch-inspection-", dir=scratch))
    env = dict(os.environ, CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
               WRANGLER_SEND_METRICS="false", WRANGLER_REGISTRY_PATH=str(run / "registry"))
    evidence = {"schema": 1, "candidate_sha": head, "tree_sha": runtime.git("rev-parse", "HEAD^{tree}"),
                "base_sha": runtime.git("merge-base", "HEAD", "origin/feat/mkit-server"),
                "origin_feature_sha": runtime.git("rev-parse", "origin/feat/mkit-server"),
                "directory": str(run), "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "wrangler_version": runtime.WRANGLER, "commands": [], "fixtures": [],
                "result": "RUNNING", "launch_matrix_result": "UNRUN", "limitations": [
                    "Synthetic HTTPS origin mapped to private loopback; no TLS/deployed platform evidence",
                    "One configured inspector; independent two-through-four inspector runtime cases remain UNRUN",
                    "Raw Blob producer, not manifest/chunks, external delta or previous-pack scanner-cache coverage",
                    "No whole-request physical DO/R2 call counter or deployed CPU/memory measurement",
                    "No async/holds/publication Events, takedown, service binding or payment/settlement coverage",
                    "Scanner nonce freshness is verified; no unsupported durable replay-denial claim"]}
    print("Evidence directory:", run, flush=True)
    try:
        runtime.invoke(["node", str(FIXTURE / "receiver.mjs"), "--self-test"], ROOT,
                       run / "receiver-self-test.log", env, evidence)
        runtime.invoke(["cargo", "build", "--locked", "-p", "mkit-server-conformance", "--bin",
                        "mkit-server-conformance"], ROOT / "rust", run / "runner-build.log", env, evidence)
        runner = ROOT / "rust/target/debug/mkit-server-conformance"
        evidence["runner_sha256"] = runtime.digest(runner)
        runtime.invoke(["worker-build", "--release", "--features", "http-objects,signed-http-hooks,pack-ruzstd"],
                       APP, run / "worker-build.log", env, evidence)
        artifact = run / "artifact"
        shutil.copytree(APP / "build", artifact)
        for name in ["index.js", "index_bg.wasm", "worker/shim.mjs"]:
            if not (artifact / name).is_file():
                raise RuntimeError("incomplete release artifact: " + name)
        evidence["artifact"] = {"features": ["http-objects", "signed-http-hooks", "pack-ruzstd"],
            "sha256": {str(path.relative_to(artifact)): runtime.digest(path)
                       for path in artifact.rglob("*") if path.is_file()},
            "wasm_raw_bytes": (artifact / "index_bg.wasm").stat().st_size}
        for mode in MODES if args.mode == "all" else [args.mode]:
            run_mode(mode, int(port), run, artifact, runner, env, evidence)
        if runtime.git("rev-parse", "HEAD") != head or runtime.git("status", "--porcelain"):
            raise RuntimeError("candidate changed; evidence invalidated")
        evidence["result"] = "PASS"
    except Exception as error:
        evidence["result"] = "FAIL"
        evidence["error"] = str(error)
        raise
    finally:
        evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evidence["log_sha256"] = {str(path.relative_to(run)): runtime.digest(path)
            for path in run.rglob("*") if path.is_file() and path.suffix in {".json", ".tap", ".log"}
            and path.name != "evidence.json" and "state" not in path.relative_to(run).parts}
        (run / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("Release R4 component PASS; full matrix remains UNRUN:", run / "evidence.json")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as error:
        print("release inspection probe failed:", error, file=sys.stderr)
        sys.exit(1)
