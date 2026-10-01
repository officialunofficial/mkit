#!/usr/bin/env python3
"""Local B3 counters around an ordinary release Worker; no full-matrix claim."""
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
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "apps/vcs-worker/tests/launch-budget"
spec = importlib.util.spec_from_file_location("release_runtime", ROOT / "scripts/vcs-worker-launch-runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
MARKER = "MKIT_LAUNCH_BUDGET "


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def records(log):
    found = []
    for line in log.read_text(errors="replace").splitlines():
        if MARKER in line:
            text = line.split(MARKER, 1)[1]
            record, _ = json.JSONDecoder().raw_decode(text)
            found.append(record)
    check(found, "no real runtime budget records emitted")
    return found


def assess(found):
    # Every group includes all its overlapping events. Each alarm's individual
    # work is bounded by this conservative total; ALS need not distinguish
    # Rust task polls inside that group. Partial groups cannot establish PASS.
    groups = {record["group"] for record in found}
    final = {record["group"]: record for record in found if record["groupFinal"]}
    check(set(final) == groups, "unfinished invocation group; physical counts incomplete")
    alarms = []
    requests = []
    for record in final.values():
        check(record["complete"] and record["outgoing"] == 0 and record["sqlPending"] == 0,
              "body lifetime or SQL cursor still open at group completion")
        check(not record["handlerError"] and record["errors"] == 0,
              f"observed handler or host operation failed: {record}")
        calls = sum(record[name] for name in ["doFetch", "r2", "hookFetch", "bindingFetch"])
        check(record["outgoingPeak"] <= 6, f"outgoing lifetime peak exceeds six: {record}")
        check(record["timerWindowRowsMax"] <= 64, f"raw timer window exceeds 64: {record}")
        if record["groupAlarms"]:
            check(calls <= 960, f"conservative alarm group exceeds 960 external calls: {record}")
            alarms.append(record)
        if record["groupRequests"]:
            check(calls <= 10000, f"request exceeds 10000 physical calls: {record}")
            requests.append(record)
    check(alarms and any(record["r2"] for record in alarms),
          "no observed real alarm with R2 work; discovery alone cannot pass")
    check(requests and any(record["kind"] == "request" and record["doFetch"] for record in requests),
          "no observed release request with real DO calls")
    check(any(record["timerWindows"] and record["sqlRowsRead"] for record in alarms),
          "no actual indexed timer-window SQL observation")
    return {"alarm_groups": len(alarms), "request_groups": len(requests),
            "max_alarm_external_calls": max(sum(r[n] for n in
                ["doFetch", "r2", "hookFetch", "bindingFetch"]) for r in alarms),
            "max_request_external_calls": max(sum(r[n] for n in
                ["doFetch", "r2", "hookFetch", "bindingFetch"]) for r in requests),
            "outgoing_peak": max(r["outgoingPeak"] for r in final.values()),
            "sql_rows_read": sum(r["sqlRowsRead"] for r in final.values()),
            "sql_rows_written": sum(r["sqlRowsWritten"] for r in final.values()),
            "timer_window_rows_max": max(r["timerWindowRowsMax"] for r in final.values()),
            "exact_rust_overlap_attribution": False,
            "attribution": "fresh request Env; conservative overlapping DO invocation groups"}


def http_read(origin, path, method="GET", headers=None):
    request = urllib.request.Request(origin + path, method=method, headers=headers or {})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        result = opener.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        result = error
    with result:
        return result.status, dict(result.headers), result.read()


def check_read_records(found, producer):
    """Require finished metrics for every HTTP read the bounded replay expects."""
    object_path = f"/{producer['repository']}/-/objects/{producer['extracted_blob']}"
    file_path = f"/{producer['repository']}/-/{producer['head_ref']}/-/extracted.txt"
    expected = [(object_path, "GET", 200, 2), (object_path, "HEAD", 200, 1),
                (object_path, "GET", 206, 1), (file_path, "GET", 200, 1),
                (file_path, "GET", 416, 1)]
    for path, method, status, count in expected:
        observed = sum(record["kind"] == "request" and record["groupFinal"]
                       and record["path"] == path[:180] and record["method"] == method
                       and record["status"] == status for record in found)
        check(observed >= count,
              f"missing completed HTTP body/settlement metrics: {method} {path} {status}")


def fixture(namespace, port, run, artifact, runner, env, evidence):
    folder = run / namespace
    folder.mkdir()
    origin = f"http://127.0.0.1:{port}"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))
    wrapper = folder / "wrapper.mjs"
    wrapper.write_text((FIXTURE / "wrapper.mjs").read_text().replace(
        "__RELEASE_SHIM__", str(artifact / "worker/shim.mjs")))
    auth = ["--auth", "auth-v2", "--audience", runtime.AUDIENCE, "--repository", "default",
            "--signer-seed-hex", runtime.SEED, "--run-id", runtime.RUN_ID]
    variables = {"AUTH_AUDIENCE": runtime.AUDIENCE, "LAUNCH_PROFILE": "uno",
        "WORKERS_PLAN": "paid", "INDEXED_MODE": "true", "ADDRESSING": "multi",
        "SHARDING": "d34", "NAMESPACE_POLICY": namespace, "RETENTION": "permanent",
        "STORAGE_LEASES": "false", "GC_ENABLED": "false",
        "TICKET_KEYS": "launch-ticket " + "11" * 32,
        "HTTP_OBJECTS": "true", "URL_TOKEN_KEYS": "active " + "22" * 32}
    if namespace == "allowlist":
        text = subprocess.check_output([str(runner), "allowlist", *auth], cwd=ROOT, env=env, text=True)
        variables["NAMESPACE_ALLOWLIST"] = ",".join(text.splitlines())
    else:
        variables["UNSAFE_OPEN_NAMESPACES"] = "true"
    classes = [("REFSTORE", "RefStore"), ("NS_COORD", "NsCoordinator"),
               ("REF_SHARD", "RefShard"), ("REPO_INDEX", "RepoIndexShard"),
               ("CONTENT_INDEX", "ContentIndexShard")]
    config = {"name": "mkit-launch-budget", "main": str(wrapper),
        "compatibility_date": "2026-09-09", "compatibility_flags": ["nodejs_als"],
        "build": {"command": "true"}, "vars": variables,
        "r2_buckets": [{"binding": "STORAGE", "bucket_name": "budget-objects"},
                       {"binding": "BACKUPS", "bucket_name": "budget-backups"}],
        "durable_objects": {"bindings": [{"name": binding, "class_name": cls} for binding, cls in classes]},
        "migrations": [{"tag": "v1", "new_sqlite_classes": [cls for _, cls in classes]}]}
    config_path = folder / "wrangler.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    result = {"namespace_policy": namespace, "result": "RUNNING",
              "config_sha256": runtime.digest(config_path), "wrapper_sha256": runtime.digest(wrapper)}
    evidence["fixtures"].append(result)
    command = ["npx", "--yes", "wrangler@" + runtime.WRANGLER, "dev", "--local",
        "--config", str(config_path), "--ip", "127.0.0.1", "--port", str(port),
        "--persist-to", str(folder / "state"), "--show-interactive-dev-session=false"]
    log_path = folder / "wrangler.log"
    evidence["commands"].append({"argv": command, "cwd": str(runtime.APP),
                                 "log": str(log_path.relative_to(run))})
    with log_path.open("w") as output:
        process = subprocess.Popen(command, cwd=runtime.APP, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + 120
            while True:
                check(process.poll() is None, "wrangler exited; see " + str(log_path))
                try:
                    status, body = runtime.request(origin,
                        "/mkit.transport.v1.TransportService/GetServerInfo", b"{}")
                    if status == 200:
                        break
                except (urllib.error.URLError, TimeoutError):
                    pass
                check(time.monotonic() < deadline, "release startup timed out")
                time.sleep(0.25)
            check(json.loads(body).get("indexedMode") is True, "indexed release did not activate")
            check(runtime.request(origin, "/__mkit_test/stats")[0] != 200,
                  "artifact unexpectedly exposes test-faults")
            for filter_ in ["info.", runtime.REQUIRED_CASE]:
                tap = folder / (filter_.replace(".", "-") + ".tap")
                runtime.invoke([str(runner), "wire", "--base-url", origin, *auth,
                    "--atomic-advance", "--fresh-target", "--milestone", "M4", "--sharding", "d34",
                    "--max-pack-bytes", "1073741824", "--features",
                    "indexed-async,indexed-mode,multi-repo,tickets,timers,http-objects",
                    "--filter", filter_], ROOT, tap, env, evidence)
                cases = re.findall(r"^(ok|not ok) \d+ - ([^\n]+)", tap.read_text(), re.MULTILINE)
                expected = ["info.shape_and_policy", "info.ignores_repository_header"] \
                    if filter_ == "info." else [runtime.REQUIRED_CASE]
                check(cases == [("ok", name) for name in expected], "wire case failed/skipped/missing")
                if filter_ == runtime.REQUIRED_CASE:
                    note = dict(re.findall(r"([a-z_]+)=([^\s]+)", tap.read_text()))
                    path = f"/{note['repository']}/-/objects/{note['extracted_blob']}"
                    status, headers, data = http_read(origin, path)
                    check(status == 200 and len(data) == int(note["extracted_blob_bytes"]),
                          "extracted object GET differs")
                    check(headers.get("content-type", headers.get("Content-Type")) == "application/octet-stream",
                          "object response policy differs")
                    status, _, head = http_read(origin, path, "HEAD")
                    check(status == 200 and not head, "object HEAD emitted bytes")
                    status, _, part = http_read(origin, path, headers={"Range": "bytes=3-1026"})
                    check(status == 206 and part == data[3:1027], "object Range differs")
                    result["producer"] = note
                    runtime.extracted_object(folder / "state", note["extracted_blob"], len(data))
            # Allow completed body metrics to reach Wrangler's pipe; do not wait
            # for or erase unrelated future housekeeping alarms.
            time.sleep(1)
            observed = records(log_path)
            check_read_records(observed, result["producer"])
            result["metrics"] = assess(observed)
            (folder / "budget-records.json").write_text(json.dumps(observed, indent=2) + "\n")
            result["result"] = "PASS"
        except Exception:
            result["result"] = "FAIL"
            raise
        finally:
            runtime.stop(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--namespace", choices=["both", "allowlist", "any"], default="both")
    args = parser.parse_args()
    head = runtime.git("rev-parse", "HEAD")
    check(args.sha == head and len(head) == 40, "--sha must name current immutable HEAD")
    check(not runtime.git("status", "--porcelain", "--untracked-files=normal"), "commit candidate first")
    check("CARGO_TARGET_DIR" not in os.environ, "CARGO_TARGET_DIR must be unset")
    scratch = Path(os.environ.get("TMPDIR", ""))
    check(scratch.is_absolute() and scratch.is_relative_to(Path.home() / ".cache/mkit-test-tmp/wp-4-18"),
          "use owned absolute TMPDIR under ~/.cache/mkit-test-tmp/wp-4-18")
    scratch.mkdir(parents=True, exist_ok=True)
    check(scratch.resolve() == scratch, "TMPDIR must not contain symlinks")
    port = os.environ.get("VCS_CONFORMANCE_PORT", "")
    check(port.isdecimal() and 1024 <= int(port) <= 65535, "set owned VCS_CONFORMANCE_PORT")
    run = Path(tempfile.mkdtemp(prefix="launch-budget-", dir=scratch))
    env = dict(os.environ, CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
               WRANGLER_SEND_METRICS="false", WRANGLER_REGISTRY_PATH=str(run / "registry"))
    evidence = {"schema": 1, "candidate_sha": head, "tree_sha": runtime.git("rev-parse", "HEAD^{tree}"),
        "directory": str(run), "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "commands": [], "fixtures": [], "result": "RUNNING", "launch_matrix_result": "UNRUN",
        "limitations": ["Fixture-only nodejs_als flag; ordinary unchanged release handlers",
            "Conservative overlapping DO groups, no exact Rust ALS attribution claim",
            "Physical lifetime observations are local, not cloud resource certification",
            "HTTP-objects build only: no signed hooks, cache snapshots, inspector, preservation or admin",
            "No cold-row seeding, frozen clock, restart or arbitrary maximal fanout claim",
            "No resident-memory theorem from body byte counters"]}
    print("Evidence directory:", run, flush=True)
    try:
        runtime.invoke(["cargo", "build", "--locked", "-p", "mkit-server-conformance", "--bin",
            "mkit-server-conformance"], ROOT / "rust", run / "runner-build.log", env, evidence)
        runner = ROOT / "rust/target/debug/mkit-server-conformance"
        evidence["runner_sha256"] = runtime.digest(runner)
        runtime.invoke(["worker-build", "--release", "--features", "http-objects,pack-ruzstd"],
            runtime.APP, run / "worker-build.log", env, evidence)
        artifact = run / "artifact"
        shutil.copytree(runtime.APP / "build", artifact)
        check(all((artifact / path).is_file() for path in ["worker/shim.mjs", "index.js", "index_bg.wasm"]),
              "release artifact incomplete")
        evidence["artifact_sha256"] = {str(path.relative_to(artifact)): runtime.digest(path)
            for path in artifact.rglob("*") if path.is_file()}
        namespaces = ["allowlist", "any"] if args.namespace == "both" else [args.namespace]
        for namespace in namespaces:
            fixture(namespace, int(port), run, artifact, runner, env, evidence)
        check(runtime.git("rev-parse", "HEAD") == head and
              not runtime.git("status", "--porcelain", "--untracked-files=normal"),
              "candidate changed during run; evidence invalid")
        evidence["result"] = "PASS"
    except Exception as error:
        evidence["result"] = "FAIL"
        evidence["error"] = str(error)
        raise
    finally:
        evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evidence["log_sha256"] = {str(path.relative_to(run)): runtime.digest(path)
            for path in run.rglob("*") if path.is_file() and path.suffix in {".log", ".tap", ".json"}
            and path.name != "evidence.json"}
        (run / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("PASS measured release B3 component; full matrix UNRUN:", run / "evidence.json")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        print("release budget probe failed:", error, file=sys.stderr)
        sys.exit(1)
