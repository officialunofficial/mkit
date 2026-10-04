#!/usr/bin/env python3
"""Run the generic reference and its separate fault harness on local workerd."""
import importlib.util
import base64
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps/embedded-worker"
FIXTURE = APP / "tests/reference-acceptance"
spec = importlib.util.spec_from_file_location("hooks", ROOT / "scripts/embedded-worker-hooks.py")
hooks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hooks)
runtime, check = hooks.runtime, hooks.check


def wait_for(worker, predicate, message, seconds=120):
    deadline = time.monotonic() + seconds
    while not predicate():
        check(worker.poll() is None and time.monotonic() < deadline, message)
        time.sleep(.2)


def main():
    check("CARGO_TARGET_DIR" not in os.environ, "do not share target directories")
    scratch = Path(os.environ["TMPDIR"]).resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="reference-acceptance-", dir=scratch))
    print(f"Acceptance logs: {run}", flush=True)
    env = dict(os.environ, WRANGLER_SEND_METRICS="false")
    source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    evidence = {"directory": str(run), "source_sha": source_sha, "commands": [], "result": "RUNNING"}
    worker = None
    try:
        runtime.invoke(["cargo", "build", "--locked", "-p", "mkit-server-conformance", "--bin",
                        "mkit-server-conformance"], ROOT / "rust", run / "runner-build.log", env, evidence)
        runtime.invoke(["worker-build", "--release", "--locked"], APP, run / "build.log", env, evidence)
        artifact = APP / "build"
        evidence["wasm_sha256"] = runtime.digest(artifact / "index_bg.wasm")
        runner = ROOT / "rust/target/debug/mkit-server-conformance"
        auth = ["--auth", "auth-v2", "--audience", runtime.AUDIENCE, "--repository", "default",
                "--signer-seed-hex", runtime.SEED, "--run-id", runtime.RUN_ID]
        namespaces = subprocess.check_output([str(runner), "allowlist", *auth], text=True, env=env).splitlines()
        variables = {"AUTH_AUDIENCE": runtime.AUDIENCE, "LAUNCH_PROFILE": "paid-workers",
            "WORKERS_PLAN": "paid", "INDEXED_MODE": "true", "ADDRESSING": "multi", "SHARDING": "d34",
            "NAMESPACE_POLICY": "allowlist", "NAMESPACE_ALLOWLIST": ",".join(namespaces),
            "RETENTION": "permanent", "STORAGE_LEASES": "false", "GC_ENABLED": "false",
            "TICKET_KEYS": "ticket " + "11" * 32, "URL_TOKEN_KEYS": "active " + "22" * 32,
            "HTTP_OBJECTS": "true", "TAKEDOWN_ENABLED": "true", "DEFAULT_REPO_VISIBILITY": "public",
            "PRESERVATION_RETENTION_MS": "3600000", "RECEIPT_NOTICE_KEY": "79" * 32,
            "RECEIVER_OUTAGE": "true"}
        wrapper = run / "wrapper.mjs"
        keys = json.loads(subprocess.check_output(["node", str(ROOT / "apps/vcs-worker/tests/launch-admin/receiver.mjs"), "keys"], env=env))
        variables.update(ADMIN_KEYS=json.dumps(keys["admin"]), RECEIPT_KEYS=json.dumps(keys["receipt"]))
        wrapper.write_text((FIXTURE / "wrapper.mjs").read_text().replace("__REFERENCE_SHIM__", str(artifact / "worker/shim.mjs")))
        classes = [("HOST_EVENTS", "HostEvents"), ("REFSTORE", "RefStore"), ("NS_COORD", "NsCoordinator"), ("REF_SHARD", "RefShard"),
                   ("REPO_INDEX", "RepoIndexShard"), ("CONTENT_INDEX", "ContentIndexShard")]
        config = {"name": "reference-acceptance", "main": str(wrapper), "compatibility_date": "2026-09-09",
            "vars": variables, "durable_objects": {"bindings": [
                {"name": name, "class_name": cls} for name, cls in classes]},
            "r2_buckets": [{"binding": name, "bucket_name": name.lower()} for name in ("STORAGE", "BACKUPS", "PRESERVATION")]}
        config_path = run / "config.json"
        config_path.write_text(json.dumps(config))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        ready = run / "ready.json"
        command = ["node", str(ROOT / "apps/vcs-worker/tests/launch-budget/direct.mjs"),
                   str(config_path), str(artifact), str(port), str(ready)]
        log_path = run / "worker.log"
        with log_path.open("w") as log:
            worker = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            wait_for(worker, ready.is_file, "runtime startup failed")
            status, _, body = hooks.request(origin, "/_embedding/mkit/mkit.transport.v1.TransportService/GetServerInfo",
                method="POST", headers={"Content-Type": "application/json", "Connect-Protocol-Version": "1",
                    "connect-timeout-ms":"1", "grpc-timeout":"1m"}, body=b"{}")
            check(status == 200, "release configuration refused")
            info = json.loads(body)
            check(info.get("indexedMode") and info.get("beginUploadThresholdBytes") == "0", "launch profile absent")
            check(info.get("leases") is False and info.get("namespacePolicy") == "allowlist", "launch discovery differs")
            check(not info.get("asyncInspection") and "inspectionMaxObjects" not in info, "inspection unexpectedly active")
            check(not any(value for key, value in info.items() if "proof" in key.lower()), "Worker advertised proofs")
            status, _, body = hooks.request(origin, "/.well-known/mkit-url-token-keys.json")
            check(status == 200 and json.loads(body), "URL-token key mount absent")
            check(hooks.request(origin, "/__mkit_test/stats")[0] != 200, "release exposes test faults")
            runtime.invoke([str(runner), "wire", "--base-url", origin, *auth, "--atomic-advance", "--fresh-target",
                "--milestone", "M4", "--sharding", "d34", "--max-pack-bytes", "1073741824", "--features",
                "indexed-async,indexed-mode,multi-repo,tickets,timers,http-objects", "--filter", "embedding.reference_fixture"],
                ROOT, run / "producer.tap", env, evidence)
            tap = (run / "producer.tap").read_text()
            cases = re.findall(r"^(ok|not ok) \d+ - ([^\n]+)", tap, re.M)
            check(len(cases) == 1 and cases[0][0] == "ok"
                  and cases[0][1].startswith("embedding.reference_fixture # repository=")
                  and "# SKIP" not in tap, "producer failed, absent or skipped")
            note = dict(re.findall(r"([a-z_]+)=([^\s]+)", tap))
            repository, object_id = note["repository"], note["extracted_blob"]
            unsigned = {"X-Repository": repository}
            def signed(procedure, body="{}", audience=runtime.AUDIENCE):
                return json.loads(subprocess.check_output(["node", str(FIXTURE / "sign.mjs"), runtime.SEED,
                    runtime.RUN_ID, audience, repository, "/mkit.transport.v1.TransportService/" + procedure, body], env=env))
            def read(owner=False, headers=None, query=None, body=b"{}"):
                path = "/_embedding/read/" + ("owner" if owner else "public")
                return hooks.request(origin, path + (query or f"?id={object_id}&metadata=true"),
                    method="POST", headers=headers or unsigned, body=body)
            status, _, data = read()
            check(status == 200, "public reader refused published object")
            preview = json.loads(data)
            check(preview["canonical_lengths"][0] > int(note["extracted_blob_bytes"]), "canonical read missing")
            check(preview["logical_lengths"] == [int(note["extracted_blob_bytes"])], "metadata read differs")
            token = preview["tokens"][0]
            check(token, "reader URL issuance absent")
            path = f"/{repository}/-/objects/{object_id}"
            check(hooks.request(origin, path + "?token=" + token)[0] == 200, "reader token refused")
            status, _, data = hooks.request(origin, "/_embedding/mkit/mkit.transport.v1.TransportService/ReadRef",
                method="POST", headers={**unsigned, "Content-Type":"application/json", "Connect-Protocol-Version":"1"},
                body=json.dumps({"name":note["head_ref"]}).encode())
            check(status == 200, "parent ref read failed")
            parent = base64.b64decode(json.loads(data)["objectId"]).hex()
            status, _, data = read(query="?" + "&".join([f"id={parent}"] * 16))
            check(status == 200 and len(json.loads(data)["canonical_lengths"]) == 16,
                "API-maximum ID batch refused")
            # Duplicate outputs still consume the shared output allowance.
            check(read(True, signed("ListRefs"), query="?" + "&".join([f"id={object_id}"] * 3))[0] == 429,
                "owner output cap not enforced")
            owner_headers = signed("ListRefs")
            check(read(True)[0] == 401, "owner view accepted without envelope")
            check(read(True, owner_headers)[0] == 200, "verified owner reader refused")
            check(read(True, signed("ListRefs", audience="https://embedded.invalid"))[0] == 401,
                "internal dispatch origin changed signed audience")
            check(read(query="?" + "&".join([f"id={object_id}"] * 17))[0] == 400, "oversized ID batch accepted")
            check(read(body=b"x" * 4097)[0] == 413, "oversized body accepted")
            # A host-owned private receiver is reachable only in this test wrapper.
            probe = {"X-Repository": "projection-probe"}
            for event in [
                {"reservation_id":"probe:2", "kind":"storage", "counter":[18446744073709551615, 2]},
                {"reservation_id":"probe:1", "kind":"storage", "counter":[7, 1]},
                {"reservation_id":"probe:2", "kind":"storage", "counter":[9, 3]},
            ]:
                check(hooks.request(origin, "/__reference_test/events", method="POST", headers=probe,
                    body=json.dumps(event).encode())[0] == 200, "receiver probe refused")
            def projection(headers):
                return json.loads(hooks.request(origin, "/__reference_test/events", headers=headers)[2])
            check(projection(probe) == [{"bytes":"18446744073709551615", "version":"00000000000000000002"}],
                "highest version or reservation dedup lost")
            retention_probe = {"X-Repository": "retention-probe"}
            def retention_event(reservation_id, version, counter=True):
                event = {"reservation_id": reservation_id, "kind": "storage" if counter else "committed",
                         "counter": [version, version] if counter else None}
                check(hooks.request(origin, "/__reference_test/events", method="POST", headers=retention_probe,
                    body=json.dumps(event).encode())[0] == 200, "retention probe refused")
            retention_event("retention:old", 1)
            # Counterless outcomes also count toward the receiver's 1,024-record bound.
            for i in range(1023):
                retention_event(f"retention:{i}", 0, counter=False)
            retention_event("retention:old", 3)
            check(int(projection(retention_probe)[0]["version"]) == 1,
                "reservation pruned before the retention cap")
            retention_event("retention:recent", 2)
            retention_event("retention:recent", 3)
            check(int(projection(retention_probe)[0]["version"]) == 2,
                "recent duplicate was accepted after pruning")
            retention_event("retention:old", 4)
            check(int(projection(retention_probe)[0]["version"]) == 4,
                "old reservation was not pruned at the retention bound")
            wait_for(worker, lambda: bool(projection(unsigned)), "RepoStorageChanged not consumed")
            counter = projection(unsigned)[0]
            check(int(counter["bytes"]) >= int(note["pack_bytes"]) and int(counter["version"]) > 0,
                "storage projection not an absolute pack total")
            # Visibility drives real local purge work and proves private/public separation.
            visibility = '{"visibility":"REPO_VISIBILITY_PRIVATE"}'
            status, _, data = hooks.request(origin, "/_embedding/mkit/mkit.transport.v1.TransportService/SetRepoVisibility",
                method="POST", headers={**signed("SetRepoVisibility", visibility), "Content-Type":"application/json",
                    "Connect-Protocol-Version":"1"}, body=visibility.encode())
            check(status == 200, "private visibility refused: " + data.decode())
            check(json.loads(read()[2])["canonical_lengths"] == [None], "public view exposed private object")
            check(json.loads(read(True, signed("ListRefs"))[2])["canonical_lengths"][0] > 0, "owner lost private view")
            wait_for(worker, lambda: "REFERENCE purge delivered" in log_path.read_text(), "custom purge sink not reached")
            reader_metrics = re.findall(r"REFERENCE reader owner=(?:true|false) calls=(\d+) decoded=(\d+) encoded=(\d+) output=(\d+) physical=(\d+)", log_path.read_text())
            check(any(all(int(n) > 0 for n in row) for row in reader_metrics), "session/outer metrics absent")
            evidence["storage_counter"] = counter
            evidence["checks"] = ["routing and deadlines", "in-process hooks", "request session and bounded reads",
                "owner/public separation", "reader tokens", "highest storage version", "reservation dedup",
                "bounded dedup retention: old pruned, recent duplicate rejected", "purge"]
            before = log_path.read_text()
            check("REFERENCE authorize" in before and "REFERENCE admit" in before, "supplied hooks absent")
            pending = set(re.findall(r"REFERENCE outcome retry (\S+)", before))
            check(pending, "no failed committed outcome to retry")
            runtime.stop(worker)
            variables["RECEIVER_OUTAGE"] = "false"
            config_path.write_text(json.dumps(config))
            offset = log_path.stat().st_size
            ready.unlink()
            worker = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            def delivered():
                with log_path.open("rb") as restarted:
                    restarted.seek(offset)
                    after = restarted.read().decode(errors="replace")
                return pending <= set(re.findall(r"REFERENCE outcome committed (\S+)", after))
            wait_for(worker, delivered, "cold alarm did not deliver every persisted outcome")
            note = dict(re.findall(r"([a-z_]+)=([^\s]+)", tap))
            check(note["http"] == "true", "HTTP and URL-token assertions did not run")
            # Reopen with the same genuine owner envelope after the cold restart.
            visibility = '{"visibility":"REPO_VISIBILITY_PUBLIC"}'
            check(hooks.request(origin, "/_embedding/mkit/mkit.transport.v1.TransportService/SetRepoVisibility",
                method="POST", headers={**signed("SetRepoVisibility", visibility), "Content-Type":"application/json",
                    "Connect-Protocol-Version":"1"}, body=visibility.encode())[0] == 200, "reopen refused")
            check(projection(probe)[0]["bytes"] == "18446744073709551615", "projection lost on cold restart")
            retention_event("retention:recent", 5)
            check(int(projection(retention_probe)[0]["version"]) == 4,
                "retained duplicate protection lost on cold restart")
            status, _, data = hooks.request(origin, f"/{note['repository']}/-/objects/{note['extracted_blob']}")
            expected = bytes((i * 17 ^ (i >> 9)) & 255 for i in range(1 << 20))
            check(status == 200 and data == expected, "published read differs after cold retry")
            evidence["retried_reservations"] = sorted(pending)
            check(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == source_sha,
                "reference source changed during acceptance")
            evidence["result"] = "PASS"
    finally:
        if worker is not None:
            runtime.stop(worker)
        if evidence["result"] == "RUNNING":
            evidence["result"] = "FAIL"
        (run / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("PASS reference: hooks, bounded reader sessions, owner/public isolation, tokens, storage projection, dedup retention, purge, cold retry")


if __name__ == "__main__":
    main()
