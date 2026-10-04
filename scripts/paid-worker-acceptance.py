#!/usr/bin/env python3
"""Bounded local release-profile acceptance with supplied hooks and cold outbox retry."""
import importlib.util
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
APP = ROOT / "apps/embedded-worker/tests/embedding-conformance"
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
    run = Path(tempfile.mkdtemp(prefix="paid-acceptance-", dir=scratch))
    print(f"Acceptance logs: {run}", flush=True)
    env = dict(os.environ, WRANGLER_SEND_METRICS="false")
    evidence = {"directory": str(run), "commands": [], "result": "RUNNING"}
    worker = None
    try:
        runtime.invoke(["cargo", "build", "--locked", "-p", "mkit-server-conformance", "--bin",
                        "mkit-server-conformance"], ROOT / "rust", run / "runner-build.log", env, evidence)
        runtime.invoke(["worker-build", "--release", "--locked"], APP, run / "build.log", env, evidence)
        artifact = APP / "build"
        runner = ROOT / "rust/target/debug/mkit-server-conformance"
        auth = ["--auth", "auth-v2", "--audience", runtime.AUDIENCE, "--repository", "default",
                "--signer-seed-hex", runtime.SEED, "--run-id", runtime.RUN_ID]
        namespaces = subprocess.check_output([str(runner), "allowlist", *auth], text=True, env=env).splitlines()
        variables = {"AUTH_AUDIENCE": runtime.AUDIENCE, "LAUNCH_PROFILE": "paid-workers",
            "WORKERS_PLAN": "paid", "INDEXED_MODE": "true", "ADDRESSING": "multi", "SHARDING": "d34",
            "NAMESPACE_POLICY": "allowlist", "NAMESPACE_ALLOWLIST": ",".join(namespaces),
            "RETENTION": "permanent", "STORAGE_LEASES": "false", "GC_ENABLED": "false",
            "TICKET_KEYS": "ticket " + "11" * 32, "URL_TOKEN_KEYS": "active " + "22" * 32,
            "HTTP_OBJECTS": "true", "TAKEDOWN_ENABLED": "false", "DEFAULT_REPO_VISIBILITY": "public",
            "FIXTURE_OUTCOME_FAIL": "true"}
        wrapper = run / "wrapper.mjs"
        wrapper.write_text("import Host from '" + str(artifact / "worker/shim.mjs") + "';\n"
            "export * from '" + str(artifact / "worker/shim.mjs") + "';\n"
            "export default {fetch(req, env, ctx) {return new Host(ctx, env).fetch(req);}};\n")
        classes = [("REFSTORE", "RefStore"), ("NS_COORD", "NsCoordinator"), ("REF_SHARD", "RefShard"),
                   ("REPO_INDEX", "RepoIndexShard"), ("CONTENT_INDEX", "ContentIndexShard")]
        config = {"name": "paid-acceptance", "main": str(wrapper), "compatibility_date": "2026-09-09",
            "vars": variables, "durable_objects": {"bindings": [
                {"name": name, "class_name": cls} for name, cls in classes]},
            "r2_buckets": [{"binding": name, "bucket_name": name.lower()} for name in ("STORAGE", "BACKUPS")]}
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
            status, _, body = hooks.request(origin, "/mkit.transport.v1.TransportService/GetServerInfo",
                method="POST", headers={"Content-Type": "application/json", "Connect-Protocol-Version": "1"}, body=b"{}")
            check(status == 200, "release configuration refused")
            info = json.loads(body)
            check(info.get("indexedMode") and info.get("beginUploadThresholdBytes") == "0", "launch profile absent")
            check(info.get("leases") is False and info.get("namespacePolicy") == "allowlist", "launch discovery differs")
            check(not info.get("asyncInspection") and "inspectionMaxObjects" not in info
                  and not info.get("receiptPublicKey"), "inspection/takedown unexpectedly active")
            check(not any(value for key, value in info.items() if "proof" in key.lower()), "Worker advertised proofs")
            status, _, body = hooks.request(origin, "/.well-known/mkit-url-token-keys.json")
            check(status == 200 and json.loads(body), "URL-token key mount absent")
            check(hooks.request(origin, "/__mkit_test/stats")[0] != 200, "release exposes test faults")
            runtime.invoke([str(runner), "wire", "--base-url", origin, *auth, "--atomic-advance", "--fresh-target",
                "--milestone", "M4", "--sharding", "d34", "--max-pack-bytes", "1073741824", "--features",
                "indexed-async,indexed-mode,multi-repo,tickets,timers,http-objects", "--filter", "embedding.public_fixture"],
                ROOT, run / "producer.tap", env, evidence)
            tap = (run / "producer.tap").read_text()
            cases = re.findall(r"^(ok|not ok) \d+ - ([^\n]+)", tap, re.M)
            check(len(cases) == 1 and cases[0][0] == "ok"
                  and cases[0][1].startswith("embedding.public_fixture # repository=")
                  and "# SKIP" not in tap, "producer failed, absent or skipped")
            before = log_path.read_text()
            check("MKIT_EMBED_STAGE authorize" in before and "MKIT_EMBED_STAGE admit" in before, "supplied hooks absent")
            pending = set(re.findall(r"MKIT_EMBED_OUTCOME_RETRY committed (\S+)", before))
            check(pending, "no failed committed outcome to retry")
            runtime.stop(worker)
            variables["FIXTURE_OUTCOME_FAIL"] = "false"
            config_path.write_text(json.dumps(config))
            offset = log_path.stat().st_size
            ready.unlink()
            worker = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            def delivered():
                with log_path.open("rb") as restarted:
                    restarted.seek(offset)
                    after = restarted.read().decode(errors="replace")
                return pending <= set(re.findall(r"MKIT_EMBED_OUTCOME committed (\S+)", after))
            wait_for(worker, delivered, "cold alarm did not deliver every persisted outcome")
            note = dict(re.findall(r"([a-z_]+)=([^\s]+)", tap))
            check(note["http"] == "true", "HTTP and URL-token assertions did not run")
            status, _, data = hooks.request(origin, f"/{note['repository']}/-/objects/{note['extracted_blob']}")
            expected = bytes((i * 17 ^ (i >> 9)) & 255 for i in range(1 << 20))
            check(status == 200 and data == expected, "published read differs after cold retry")
            evidence["retried_reservations"] = sorted(pending)
            evidence["result"] = "PASS"
    finally:
        if worker is not None:
            runtime.stop(worker)
        if evidence["result"] == "RUNNING":
            evidence["result"] = "FAIL"
        (run / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("PASS paid release: push, published reads, URL token, supplied hooks, cold outcome retry")


if __name__ == "__main__":
    main()
