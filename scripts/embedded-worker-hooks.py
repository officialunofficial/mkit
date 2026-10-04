#!/usr/bin/env python3
"""Exercise supplied paid-read hooks and Authority fencing on local workerd."""
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
import urllib.error
import urllib.request

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps/embedded-worker/tests/embedding-conformance"
spec = importlib.util.spec_from_file_location("runtime", ROOT / "scripts/vcs-worker-launch-runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def check(ok, message):
    if not ok:
        raise RuntimeError(message)


def request(origin, path, method="GET", headers=None, body=None):
    req = urllib.request.Request(origin + path, method=method, headers=headers or {}, data=body)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(req, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, dict(response.headers), response.read(1048577)


def main():
    scratch = Path(os.environ["TMPDIR"])
    check(scratch.resolve() == scratch and scratch.is_relative_to(Path.home() / ".cache/mkit-test-tmp"), "owned nonsymlink TMPDIR required")
    check("CARGO_TARGET_DIR" not in os.environ, "do not share target directories")
    run = Path(tempfile.mkdtemp(prefix="embedded-hooks-", dir=scratch))
    print(f"Evidence directory: {run}", flush=True)
    evidence = {"directory": str(run), "commands": [], "result": "RUNNING", "checks": []}
    env = dict(os.environ, WRANGLER_SEND_METRICS="false")
    runner = ROOT / "rust/target/debug/mkit-server-conformance"
    auth = ["--auth", "auth-v2", "--audience", runtime.AUDIENCE, "--repository", "default",
            "--signer-seed-hex", runtime.SEED, "--run-id", runtime.RUN_ID]
    runtime.invoke(["cargo", "build", "--locked", "-p", "mkit-server-conformance", "--bin", "mkit-server-conformance"], ROOT / "rust", run / "runner-build.log", env, evidence)
    runtime.invoke(["worker-build", "--release"], APP, run / "build.log", env, evidence)
    artifact = APP / "build"
    evidence["wasm_sha256"] = runtime.digest(artifact / "index_bg.wasm")
    namespaces = subprocess.check_output([str(runner), "allowlist", *auth], text=True, env=env).splitlines()
    key = json.loads(subprocess.check_output(["node", str(ROOT / "apps/vcs-worker/tests/launch-admin/receiver.mjs"), "keys"], env=env))["admin"]["keys"][0]["publicKey"]
    variables = {"AUTH_AUDIENCE": runtime.AUDIENCE, "LAUNCH_PROFILE": "paid-workers", "WORKERS_PLAN": "paid",
                 "INDEXED_MODE": "true", "ADDRESSING": "multi", "SHARDING": "d34",
                 "NAMESPACE_POLICY": "allowlist", "NAMESPACE_ALLOWLIST": ",".join(namespaces),
                 "TICKET_KEYS": "ticket " + "11" * 32, "URL_TOKEN_KEYS": "active " + "22" * 32,
                 "HTTP_OBJECTS": "true", "HTTP_ADMIT_READS": "true",
                 "AUTHORITY_FENCE": "true", "AUTHORITY_KEYS": f"operator {key} {','.join(namespaces)}"}
    check(not any(name in variables for name in ("HOOK_ROLES", "HOOK_URL", "ADMISSION_HOOK")), "no external hook transport")
    wrapper = run / "wrapper.mjs"
    wrapper.write_text((ROOT / "apps/vcs-worker/tests/launch-read-hooks/wrapper.mjs").read_text().replace("__RELEASE_MODULE__", str(artifact / "worker/shim.mjs")))
    classes = [("REFSTORE", "RefStore"), ("NS_COORD", "NsCoordinator"), ("REF_SHARD", "RefShard"),
               ("REPO_INDEX", "RepoIndexShard"), ("CONTENT_INDEX", "ContentIndexShard")]
    config = {"name": "embedded-hooks", "main": str(wrapper), "compatibility_date": "2026-09-09", "vars": variables,
              "durable_objects": {"bindings": [{"name": name, "class_name": cls} for name, cls in classes]},
              "r2_buckets": [{"binding": name, "bucket_name": name.lower()} for name in ("STORAGE", "BACKUPS", "PRESERVATION")]}
    config_path = run / "config.json"
    config_path.write_text(json.dumps(config))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    ready = run / "ready.json"
    worker = None
    try:
        with (run / "worker.log").open("w") as log:
            worker = subprocess.Popen(["node", str(ROOT / "apps/vcs-worker/tests/launch-budget/direct.mjs"),
                                       str(config_path), str(artifact), str(port), str(ready)], env=env,
                                      stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + 120
            while not ready.is_file():
                check(worker.poll() is None and time.monotonic() < deadline, "embedded runtime startup failed")
                time.sleep(.1)
            producer = [str(runner), "wire", "--base-url", origin, *auth, "--atomic-advance", "--fresh-target",
                        "--milestone", "M4", "--sharding", "d34", "--max-pack-bytes", "1073741824",
                        "--features", "indexed-async,indexed-mode,multi-repo,tickets,timers", "--filter", "embedding.public_fixture"]
            runtime.invoke(producer, ROOT, run / "producer.tap", env, evidence)
            tap = (run / "producer.tap").read_text()
            check(re.search(r"^ok \d+ - embedding\.public_fixture # repository=", tap, re.M), "producer failed or skipped")
            note = dict(re.findall(r"([a-z_]+)=([^\s]+)", tap))
            path = f"/{note['repository']}/-/objects/{note['extracted_blob']}"
            size = int(note["extracted_blob_bytes"])
            paid = {"Authorization": "Payment embedding-fixture"}
            expected = {}
            for method in ("GET", "HEAD"):
                status, _, _ = request(origin, path, method=method)
                check(status == 402, f"{method} without payment: {status}")
                status, headers, body = request(origin, path, method=method, headers=paid)
                check(status == 200 and len(body) == (size if method == "GET" else 0), f"paid {method} incomplete")
                receipt = next(value for name, value in headers.items() if name.lower() == "payment-receipt")
                expected[receipt] = ("read", size if method == "GET" else 0)
            deadline = time.monotonic() + 30
            while True:
                outcomes = re.findall(r"MKIT_EMBED_OUTCOME (read|aborted) (embedding-read:\d+) (\d+)", (run / "worker.log").read_text())
                recorded = {reservation: (kind, int(count)) for kind, reservation, count in outcomes}
                if all(recorded.get(reservation) == result for reservation, result in expected.items()):
                    break
                check(time.monotonic() < deadline, "paid GET/HEAD settlement missing")
                time.sleep(.1)
            namespace = note["repository"].rsplit("/", 1)[0]
            rpc = "/mkit.transport.v1.TransportService/GetAuthorityGeneration"
            status, _, body = request(origin, rpc, method="POST", body=json.dumps({"namespace": namespace}).encode(), headers={"Content-Type": "application/json", "Connect-Protocol-Version": "1"})
            check(status == 200 and json.loads(body).get("generation", "0") == "0", "custom Authority fence unavailable")
            evidence["checks"] = ["in-process Authority/fence with signed writes", "GET/HEAD payment challenge", "GET/HEAD ReadServed outcomes", "no external hook transport"]
            evidence["result"] = "PASS"
    finally:
        if evidence["result"] == "RUNNING":
            evidence["result"] = "FAIL"
        if worker is not None:
            runtime.stop(worker)
        (run / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("PASS embedded supplied hooks: " + "; ".join(evidence["checks"]))


if __name__ == "__main__":
    main()
