#!/usr/bin/env python3
"""Seven signed operations on the ordinary release Worker, local fixtures only."""
import argparse
import base64
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
FIXTURE = ROOT / "apps/vcs-worker/tests/launch-admin/receiver.mjs"
spec = importlib.util.spec_from_file_location("runtime", ROOT / "scripts/vcs-worker-launch-runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def stream_frames(raw):
    frames = []
    while raw:
        check(len(raw) >= 5, "truncated Connect frame")
        flags, size = raw[0], int.from_bytes(raw[1:5], "big")
        check(flags in (0, 2) and size <= len(raw) - 5, "invalid Connect frame")
        frames.append((flags, json.loads(raw[5:5 + size])))
        raw = raw[5 + size:]
    check(frames and frames[-1][0] == 2 and "error" not in frames[-1][1]
          and all(flags == 0 for flags, _ in frames[:-1]),
          "Connect stream did not end successfully")
    return [value for flags, value in frames if flags == 0]


def admin(origin, method, body, env, transcript, role="operator", streamed=False, expected=200):
    result = json.loads(subprocess.check_output(["node", str(FIXTURE), "admin", origin, method,
        json.dumps(body, separators=(",", ":")), role, str(streamed).lower()], env=env, text=True))
    check(result["status"] == expected, f"{method}: {result}")
    check(result["headers"].get("cache-control") == "no-store", f"{method} response was cacheable")
    raw = base64.b64decode(result["body"])
    value = stream_frames(raw) if streamed and expected == 200 else json.loads(raw)
    # Preserved content is never retained in the fixture transcript or logs.
    transcript.append({"method": method, "role": role, "status": expected,
        "nonce": result["nonce"], "request_digest": result["request_digest"],
        "response_bytes": len(raw), "streamed": streamed})
    return value


def get_json(url):
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=10) as response:
        return json.loads(response.read(1048577))


def run_fixture(namespace, port, folder, artifact, runner, env, evidence):
    folder.mkdir()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))
    origin = f"http://127.0.0.1:{port}"
    ready = folder / "receiver-ready.json"
    result = {"namespace_policy": namespace, "result": "RUNNING", "checks": []}
    evidence["fixtures"].append(result)
    with (folder / "receiver.log").open("w") as receiver_log:
        receiver = subprocess.Popen(["node", str(FIXTURE)], env=dict(env, ADMIN_READY_FILE=str(ready)),
            stdout=receiver_log, stderr=subprocess.STDOUT, start_new_session=True)
        worker = None
        transcript = []
        try:
            deadline = time.monotonic() + 15
            while not ready.is_file():
                check(receiver.poll() is None and time.monotonic() < deadline, "purge receiver startup failed")
                time.sleep(.1)
            receiver_origin = json.loads(ready.read_text())["origin"]
            keys = json.loads(subprocess.check_output(["node", str(FIXTURE), "keys"], env=env, text=True))
            wrapper = (ROOT / "apps/vcs-worker/tests/launch-inspection/wrapper.mjs").read_text()
            wrapper = wrapper.replace("__RELEASE_SHIM__", str(artifact / "worker/shim.mjs"))
            wrapper = wrapper.replace("__RECEIVER_ORIGIN__", receiver_origin).replace(
                "https://inspection.launch.invalid", "https://purge.launch.invalid")
            wrapper_path = folder / "wrapper.mjs"
            wrapper_path.write_text(wrapper)
            auth = ["--auth", "auth-v2", "--audience", runtime.AUDIENCE, "--repository", "default",
                    "--signer-seed-hex", runtime.SEED, "--run-id", runtime.RUN_ID]
            variables = {"AUTH_AUDIENCE": runtime.AUDIENCE, "LAUNCH_PROFILE": "uno", "WORKERS_PLAN": "paid",
                "INDEXED_MODE": "true", "ADDRESSING": "multi", "SHARDING": "d34", "NAMESPACE_POLICY": namespace,
                "RETENTION": "permanent", "STORAGE_LEASES": "false", "GC_ENABLED": "false",
                "TICKET_KEYS": "launch-ticket " + "11" * 32, "HTTP_OBJECTS": "true",
                "URL_TOKEN_KEYS": "active " + "22" * 32, "HOOK_ROLES": "cache-purge",
                "HOOK_URL": "https://purge.launch.invalid", "MKIT_HOOK_KEY": "launch-hook " + "55" * 32,
                "ADMIN_KEYS": json.dumps(keys["admin"]), "TAKEDOWN_ENABLED": "true",
                "PRESERVATION_RETENTION_MS": "3600000", "RECEIPT_NOTICE_KEY": "79" * 32,
                "RECEIPT_KEYS": json.dumps(keys["receipt"])}
            if namespace == "any":
                variables["UNSAFE_OPEN_NAMESPACES"] = "true"
            else:
                allowlist = subprocess.check_output([str(runner), "allowlist", *auth], cwd=ROOT, env=env, text=True)
                variables["NAMESPACE_ALLOWLIST"] = ",".join(allowlist.splitlines())
            classes = [("REFSTORE", "RefStore"), ("NS_COORD", "NsCoordinator"), ("REF_SHARD", "RefShard"),
                       ("REPO_INDEX", "RepoIndexShard"), ("CONTENT_INDEX", "ContentIndexShard")]
            config = {"name": "mkit-launch-admin", "main": str(wrapper_path), "compatibility_date": "2026-09-09",
                "build": {"command": "true"}, "vars": variables,
                "r2_buckets": [{"binding": binding, "bucket_name": "admin-" + binding.lower()}
                               for binding in ("STORAGE", "BACKUPS", "PRESERVATION")],
                "durable_objects": {"bindings": [{"name": binding, "class_name": cls} for binding, cls in classes]},
                "migrations": [{"tag": "v1", "new_sqlite_classes": [cls for _, cls in classes]}]}
            config_path = folder / "wrangler.json"
            config_path.write_text(json.dumps(config, indent=2) + "\n")
            result["config_sha256"] = runtime.digest(config_path)
            result["wrapper_sha256"] = runtime.digest(wrapper_path)
            command = ["npx", "--yes", "wrangler@" + runtime.WRANGLER, "dev", "--local", "--config", str(config_path),
                "--ip", "127.0.0.1", "--port", str(port), "--persist-to", str(folder / "state"),
                "--show-interactive-dev-session=false"]
            with (folder / "wrangler.log").open("w") as worker_log:
                worker = subprocess.Popen(command, cwd=ROOT / "apps/vcs-worker", env=env, stdout=worker_log,
                    stderr=subprocess.STDOUT, start_new_session=True)
                result["owned_pids"] = [receiver.pid, worker.pid]
                deadline = time.monotonic() + 120
                while True:
                    check(worker.poll() is None and time.monotonic() < deadline, "release admin startup failed")
                    try:
                        status, body = runtime.request(origin, "/mkit.transport.v1.TransportService/GetServerInfo", b"{}")
                        if status == 200:
                            break
                        (folder / "startup.json").write_bytes(body)
                    except (OSError, TimeoutError):
                        pass
                    time.sleep(.25)
                info = json.loads(body)
                check(info.get("receiptPublicKey") and info.get("indexedMode"), "receipt/indexed discovery absent")
                check(runtime.request(origin, "/__mkit_test/stats")[0] != 200, "release test-fault route exposed")
                tap = folder / "producer.tap"
                runtime.invoke([str(runner), "wire", "--base-url", origin, *auth, "--atomic-advance", "--fresh-target",
                    "--milestone", "M4", "--sharding", "d34", "--max-pack-bytes", "1073741824", "--features",
                    "indexed-async,indexed-mode,multi-repo,tickets,timers,http-objects", "--filter", "launch.admin_fixture"],
                    ROOT, tap, env, evidence)
                check(re.findall(r"^(ok|not ok) \d+ - ([^\n]+)", tap.read_text(), re.MULTILINE) ==
                      [("ok", "launch.admin_fixture")], "release producer failed/skipped")
                note = dict(re.findall(r"([a-z_]+)=([^\s]+)", tap.read_text()))
                object_id = base64.b64encode(bytes.fromhex(note["extracted_blob"])).decode()
                object_path = f"/{note['repository']}/-/objects/{note['extracted_blob']}"
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(origin + object_path, timeout=30) as response:
                    original = response.read(1048577)
                    check(response.status == 200 and len(original) == int(note["extracted_blob_bytes"]),
                          "live fixture object absent or incomplete")
                canonical = b"\x01MKT1\x01" + len(original).to_bytes(4, "little") + original
                canonical_hash = subprocess.check_output(["b3sum", "--no-names"], input=canonical).decode().strip()
                check(canonical_hash == note["extracted_blob"], "independent canonical Blob hash differs")
                taken = admin(origin, "Takedown", {"operationId": "launch-admin-1", "repository": note["repository"],
                    "objectIds": [object_id], "reason": "local conformance", "reasonToken": "manual"}, env, transcript)
                takedown_id = taken["takedownId"]
                check(runtime.request(origin, object_path)[0] == 404, "accepted takedown served public bytes")
                deadline = time.monotonic() + 180
                while True:
                    record = admin(origin, "GetTakedown", {"takedownId": takedown_id}, env, transcript)["takedown"]
                    if record.get("preservationVerified"):
                        break
                    check(time.monotonic() < deadline, "preservation did not verify")
                    time.sleep(1)
                check(not record.get("preservationPurged"), "new preserved copy already purged")
                if namespace == "any":
                    check(record.get("discoveryStatus") != "complete" and not record.get("complete"),
                          "Any falsely reported completed discovery")
                for scope in (None, {}, {"repository": note["repository"]}):
                    page = admin(origin, "ListTakedowns", {"scope": scope, "pageSize": "1"}, env, transcript)
                    check(any(row["takedownId"] == takedown_id for row in page["takedowns"]), "scoped List lost record")
                admin(origin, "ListTakedowns", {"pageSize": "0"}, env, transcript, expected=400)
                admin(origin, "GetTakedown", {"takedownId": takedown_id}, env, transcript, role="auditor", expected=403)
                for enabled in (True, False):
                    admin(origin, "SetLegalHold", {"takedownId": takedown_id, "enabled": enabled,
                        "reason": "local hold", "operatorLabel": "fixture"}, env, transcript)
                    check(admin(origin, "GetTakedown", {"takedownId": takedown_id}, env, transcript)["takedown"]
                          .get("legalHold", False) == enabled, "hold status differs")
                pieces = admin(origin, "ReadPreserved", {"takedownId": takedown_id, "objectId": object_id,
                    "offset": "0"}, env, transcript, streamed=True)
                offset, restored = 0, bytearray()
                for piece in pieces:
                    check(int(piece.get("offset", 0)) == offset, "preserved offsets not ordered")
                    data = base64.b64decode(piece.get("data", ""));restored.extend(data);offset += len(data)
                check(bytes(restored) == canonical and pieces[-1].get("last") and
                      sum(bool(piece.get("last")) for piece in pieces) == 1, "preserved stream differs")
                end = admin(origin, "ReadPreserved", {"takedownId": takedown_id, "objectId": object_id,
                    "offset": str(offset)}, env, transcript, streamed=True)
                check(len(end) == 1 and end[0].get("last") and not end[0].get("data"), "empty terminal offset differs")
                purge = admin(origin, "PurgeCache", {"operationId": "launch-purge-1", "repository": note["repository"],
                    "objectIds": [object_id], "reason": "local manual purge"}, env, transcript)
                deadline = time.monotonic() + 90
                while True:
                    sink = get_json(receiver_origin + "/state")
                    delivered = [item for item in sink["requests"] if item["body"]["purgeId"] == purge["purgeId"]]
                    if delivered:
                        break
                    check(time.monotonic() < deadline, "signed purge sink not reached")
                    time.sleep(1)
                check(not sink["failures"], "independent purge authentication failed")
                check(all(item["body"]["repository"] == note["repository"] and
                          item["body"]["audience"] == runtime.AUDIENCE and
                          item["body"]["objectIds"] == [object_id] and
                          item["body"]["trigger"] == "CACHE_PURGE_TRIGGER_MANUAL" for item in delivered),
                      "manual purge scope/selectors/trigger differs")
                deadline = time.monotonic() + 90
                completion_start = 1
                while True:
                    completion = admin(origin, "ReadAuditLog", {"fromSeq": str(completion_start), "pageSize": 100},
                                       env, transcript, streamed=True)
                    if any(entry["procedure"] == "system:timer/PurgeCacheComplete" and
                           entry.get("targets") == [purge["purgeId"]] for entry in completion[0]["entries"]):
                        break
                    next_completion = int(completion[0]["nextSeq"])
                    check(next_completion > completion_start, "completion audit page failed to progress")
                    completion_start = next_completion
                    check(time.monotonic() < deadline, "manual purge completion audit absent")
                    time.sleep(1)
                entries, start, frozen_head = [], 1, None
                while frozen_head is None or start <= frozen_head:
                    audit = admin(origin, "ReadAuditLog", {"fromSeq": str(start), "pageSize": 100},
                                  env, transcript, streamed=True)
                    check(len(audit) == 1, "audit page frame count differs")
                    page = audit[0]
                    if frozen_head is None:
                        frozen_head = int(page["chainHeadSeq"])
                        check(frozen_head <= 10000, "fixture audit unexpectedly large")
                    entries.extend(entry for entry in page["entries"] if int(entry["seq"]) <= frozen_head)
                    next_seq = int(page["nextSeq"])
                    check(next_seq > start, "audit page failed to make progress")
                    start = next_seq
                check(len(entries) == frozen_head and entries and [int(e["seq"]) for e in entries] == list(range(1, len(entries) + 1)), "audit has gaps")
                methods = {entry["procedure"].rsplit("/", 1)[-1] for entry in entries}
                check({"Takedown", "GetTakedown", "ListTakedowns", "SetLegalHold", "ReadPreserved", "PurgeCache"} <= methods,
                      "audit omitted accepted operations")
                for method in ("Reinstate", "ReleaseHold", "Reinspect"):
                    check(runtime.request(origin, "/mkit.server.admin.v1.AdminService/" + method, b"{}")[0] == 404,
                          "deferred operation exposed")
                result["checks"] = ["seven independently signed release operations", "moderation/audit role separation",
                    "global public denial after acceptance", "verified private preservation stream and exact final offsets",
                    "hold set/clear status", "bounded List null/empty/repository scopes and invalid size",
                    "signed HTTPS purge transport mapping and correlated completion audit", "gapless accepted audit", "deferred catalog absent"]
                result["result"] = "PASS"
        except Exception:
            result["result"] = "FAIL"
            raise
        finally:
            (folder / "admin-transcript.json").write_text(json.dumps(transcript, indent=2) + "\n")
            if worker is not None:
                runtime.stop(worker)
            runtime.stop(receiver)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--namespace", choices=("both", "allowlist", "any"), default="both")
    args = parser.parse_args()
    check(args.sha == runtime.git("rev-parse", "HEAD") and not runtime.git("status", "--porcelain"), "use clean current SHA")
    check("CARGO_TARGET_DIR" not in os.environ, "CARGO_TARGET_DIR must be unset")
    scratch = Path(os.environ.get("TMPDIR", ""))
    check(scratch.is_absolute() and scratch.is_relative_to(Path.home() / ".cache/mkit-test-tmp/wp-4-18")
          and scratch.resolve() == scratch, "use owned nonsymlink TMPDIR")
    scratch.mkdir(parents=True, exist_ok=True)
    port = os.environ.get("VCS_CONFORMANCE_PORT", "")
    check(port.isdecimal() and 1024 <= int(port) <= 65535, "set private VCS_CONFORMANCE_PORT")
    run = Path(tempfile.mkdtemp(prefix="launch-admin-", dir=scratch))
    env = dict(os.environ, CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", WRANGLER_SEND_METRICS="false",
               WRANGLER_REGISTRY_PATH=str(run / "registry"))
    evidence = {"schema": 1, "candidate_sha": args.sha, "tree_sha": runtime.git("rev-parse", "HEAD^{tree}"),
        "directory": str(run), "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "commands": [],
        "fixtures": [], "result": "RUNNING", "launch_matrix_result": "UNRUN", "limitations": [
            "Local synthetic HTTPS hook mapping; no deployment or TLS sink certification",
            "Single live raw Blob producer; no concurrent purge CAS, retention expiry/corrupt copy or failure injection",
            "No whole-dispatch physical counter or isolate CPU/memory certificate",
            "No writer-reuse/snapshot/scanner intersection or durable signing rotation claim"]}
    print("Evidence directory:", run, flush=True)
    try:
        runtime.invoke(["cargo", "build", "--locked", "-p", "mkit-server-conformance", "--bin", "mkit-server-conformance"],
                       ROOT / "rust", run / "runner-build.log", env, evidence)
        runtime.invoke(["worker-build", "--release", "--features", "launch"], ROOT / "apps/vcs-worker", run / "build.log", env, evidence)
        artifact = run / "artifact"
        shutil.copytree(ROOT / "apps/vcs-worker/build", artifact)
        evidence["artifacts"] = {str(p.relative_to(artifact)): runtime.digest(p) for p in artifact.rglob("*") if p.is_file()}
        runner = ROOT / "rust/target/debug/mkit-server-conformance"
        evidence["runner_sha256"] = runtime.digest(runner)
        for namespace in ("allowlist", "any") if args.namespace == "both" else (args.namespace,):
            run_fixture(namespace, int(port), run / namespace, artifact, runner, env, evidence)
        check(runtime.git("rev-parse", "HEAD") == args.sha and not runtime.git("status", "--porcelain"), "candidate changed")
        evidence["result"] = "PASS"
    except Exception as error:
        evidence["result"] = "FAIL"
        evidence["error"] = str(error)
        raise
    finally:
        evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evidence["logs_sha256"] = {str(p.relative_to(run)): runtime.digest(p) for p in run.rglob("*.log")}
        (run / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
