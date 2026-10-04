#!/usr/bin/env python3
"""Deadline regression on pinned local workerd through the Workers harness."""
import argparse
import base64
import importlib.util
import json
import os
import re
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "rust/crates/mkit-server-worker/tests/connect-deadline-probe"
SIGNER = ROOT / "apps/vcs-worker/tests/launch-admin/receiver.mjs"
spec = importlib.util.spec_from_file_location("harness", ROOT / "scripts/embedded-worker-conformance.py")
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)
VARIANTS = [
    {}, {"connect-timeout-ms": "0"}, {"grpc-timeout": "0m"},
    {"connect-timeout-ms": "1", "grpc-timeout": "1m"},
    {"connect-timeout-ms": "malformed"}, {"grpc-timeout": "malformed"},
    {"connect-timeout-ms": "malformed", "grpc-timeout": "malformed"},
]


def request(origin, path, headers, body=b"{}", content_type="application/json"):
    req = urllib.request.Request(origin + path, data=body, headers={
        "content-type": content_type, "connect-protocol-version": "1", **headers})
    try:
        response = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read(), response.headers


def check_audit_stream(raw):
    frames = []
    while raw:
        assert len(raw) >= 5, "truncated admin stream frame"
        flags, size = raw[0], int.from_bytes(raw[1:5], "big")
        assert flags in (0, 2) and size <= len(raw) - 5, "invalid admin stream frame"
        frames.append((flags, json.loads(raw[5:5 + size])))
        raw = raw[5 + size:]
    assert frames and frames[-1][0] == 2 and "error" not in frames[-1][1]
    assert all(flags == 0 for flags, _ in frames[:-1])


def portable_wire(common, prefix, expected, env, work, cases):
    result = subprocess.run([*common, "--filter", prefix], env=env, text=True, capture_output=True, timeout=900)
    (work / (prefix.replace(".", "-") + ".tap")).write_text(result.stdout + result.stderr)
    print(result.stdout, end="", flush=True)
    assert result.returncode == 0, f"portable case {prefix} failed"
    found = re.findall(r"^(ok|not ok) \d+ - ([^\n]+)", result.stdout, re.MULTILINE)
    assert len(found) == expected and "# SKIP" not in result.stdout, f"{prefix}: intended cases absent/skipped"
    assert all(status == "ok" and name.startswith(prefix) for status, name in found)
    cases.extend({"case": name.split(" #", 1)[0], "verdict": status} for status, name in found)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--portable", action="store_true", help="also run portable file and takedown contracts")
    parser.add_argument("--port", type=int, default=8797)
    args = parser.parse_args()
    scratch = Path(os.environ.get("TMPDIR", Path.home() / ".cache/mkit-test-tmp/wasm-deadline"))
    scratch.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="deadline-", dir=scratch))
    env = dict(os.environ, CARGO_PROFILE_DEV_DEBUG="0", TMPDIR=str(scratch),
               WRANGLER_SEND_METRICS="false", WRANGLER_REGISTRY_PATH=str(work / "registry"))
    if env.get("CARGO_TARGET_DIR"):
        raise RuntimeError("CARGO_TARGET_DIR must remain unset")
    source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True):
        raise RuntimeError("commit the candidate first; deadline evidence requires a clean worktree")
    if shutil.which("b3sum", path=env.get("PATH")) is None:
        raise RuntimeError("independent admin signer requires b3sum; install b3sum 1.8.5")
    keys = json.loads(subprocess.check_output(["node", str(SIGNER), "keys"], env=env, text=True))
    if not args.no_build:
        with (work / "build.log").open("w") as log:
            subprocess.run(["worker-build", "--release", "--locked"], cwd=APP, env=env,
                           stdout=log, stderr=log, check=True)
    runner = ROOT / "rust/target/debug/mkit-server-conformance"
    if args.portable and not args.no_build:
        with (work / "runner-build.log").open("w") as log:
            subprocess.run(["cargo", "build", "--locked", "-p", "mkit-server-conformance", "--bin", "mkit-server-conformance"],
                           cwd=ROOT / "rust", env=env, stdout=log, stderr=log, check=True)
    artifacts = harness.artifact_hashes(APP)
    classes = [("REFSTORE", "RefStore"), ("NS_COORD", "NsCoordinator"), ("REF_SHARD", "RefShard"),
               ("REPO_INDEX", "RepoIndexShard"), ("CONTENT_INDEX", "ContentIndexShard")]
    config = {"name": "mkit-connect-deadline-probe", "main": str(APP / "build/worker/shim.mjs"),
              "compatibility_date": "2026-09-09", "build": {"command": "true"},
              "vars": {"AUTH_AUDIENCE": "https://vcs.launch.invalid", "AUTH_REPOSITORY": "default",
                       "WORKERS_PLAN": "paid", "SHARDING": "d34", "LAUNCH_PROFILE": "paid-workers",
                       "ADDRESSING": "multi", "NAMESPACE_POLICY": "any", "UNSAFE_OPEN_NAMESPACES": "true",
                       "INDEXED_MODE": "true", "RETENTION": "permanent", "STORAGE_LEASES": "false", "GC_ENABLED": "false",
                       "TICKET_KEYS": "fixture-ticket " + "11" * 32,
                       "ADMIN_KEYS": json.dumps(keys["admin"]), "TAKEDOWN_ENABLED": "true",
                       "PRESERVATION_RETENTION_MS": "3600000", "RECEIPT_NOTICE_KEY": "79" * 32,
                       "RECEIPT_KEYS": json.dumps(keys["receipt"]), "HOOK_ROLES": "cache-purge",
                       "HOOK_URL": "https://purge.launch.invalid", "MKIT_HOOK_KEY": "fixture-hook " + "55" * 32},
              "r2_buckets": [{"binding": name, "bucket_name": "deadline-" + name.lower()}
                             for name in ["STORAGE", "BACKUPS", "PRESERVATION"]],
              "durable_objects": {"bindings": [{"name": name, "class_name": cls} for name, cls in classes]},
              "migrations": [{"tag": "deadline", "new_sqlite_classes": [cls for _, cls in classes]}]}
    if args.portable:
        config["vars"].update(HTTP_OBJECTS="true", URL_TOKEN_KEYS="active " + "22" * 32, DEFAULT_REPO_VISIBILITY="private")
        wrapper = work / "wrapper.mjs"
        wrapper.write_text((ROOT / "rust/crates/mkit-server-worker/tests/connect-deadline-probe/range-probe.mjs").read_text()
                           .replace("__RELEASE_SHIM__", str(APP / "build/worker/shim.mjs")))
        config["main"] = str(wrapper)
        # Each invocation owns its sensitive resume fixture; never print its token.
        env["TMPDIR"] = str(work)
    config_path = work / "wrangler.json"
    config_path.write_text(json.dumps(config))
    origin = f"http://127.0.0.1:{args.port}"
    # Reuse the harness's independent admin signer; inject only unsigned timeout
    # headers, preserving the exact signed body/path and fresh nonce per request.
    inject = work / "deadline-headers.mjs"
    inject.write_text("const original = globalThis.fetch; globalThis.fetch = (url, init) => original(url, "
                      "{...init, headers: {...init.headers, ...JSON.parse(process.env.DEADLINE_HEADERS)}});\n")
    cases = []
    process = None
    try:
        with (work / "wrangler.log").open("w") as log:
            process = subprocess.Popen(["npx", "--yes", f"wrangler@{harness.WRANGLER}", "dev", "--local",
                "--config", str(config_path), "--ip", "127.0.0.1", "--port", str(args.port),
                "--persist-to", str(work / "state"), "--show-interactive-dev-session=false"],
                cwd=APP, env=env, stdout=log, stderr=log, start_new_session=True)
            harness.wait_ready(origin + "/direct/grpc.health.v1.Health/Check", process)
            for entry in ["direct", "default", "router", "serve", "serve_with", "fetch", "fetch_with", "fetch_with_context"]:
                for headers in VARIANTS:
                    for content_type, body in [("application/json", b"{}"), ("application/grpc+proto", b"\0\0\0\0\0")]:
                        status, raw, response_headers = request(origin, f"/{entry}/grpc.health.v1.Health/Check",
                                                               headers, body, content_type)
                        assert status == 200, (entry, headers, status, raw)
                        if content_type == "application/json":
                            assert json.loads(raw)["status"] == "SERVING", (entry, raw)
                        else:
                            assert raw == b"\0\0\0\0\2\x08\x01", (entry, raw)
                        cases.append({"entry": entry, "headers": headers, "protocol": content_type, "status": status})
                    repository = "default" if entry in ["direct", "default", "router"] else "ed25519-" + "11" * 32 + "/default"
                    status, raw, _ = request(origin, f"/{entry}/mkit.transport.v1.TransportService/UpdateRef",
                                             {**headers, "x-repository": repository},
                                             b'{"name":"refs/heads/main","expectation":"REF_EXPECTATION_MISSING","delete":true}')
                    assert status == 401 and json.loads(raw)["code"] == "unauthenticated", (entry, status, raw)
                    cases.append({"entry": entry, "headers": headers, "protocol": "auth rejection", "status": status})
                print(f"PASS {entry}: all timeout variants, Connect/gRPC health and auth rejection", flush=True)
            for entry in ["admin", "serve", "serve_with", "fetch", "fetch_with", "fetch_with_context"]:
                for headers in VARIANTS:
                    result = json.loads(subprocess.check_output(["node", "--import", str(inject), str(SIGNER),
                        "admin", origin, "ReadAuditLog", '{"fromSeq":"1","pageSize":1}', "auditor", "true"],
                        env=dict(env, ADMIN_PATH_PREFIX="/" + entry, DEADLINE_HEADERS=json.dumps(headers)), text=True))
                    raw = base64.b64decode(result["body"])
                    assert result["status"] == 200, (entry, headers, result)
                    assert result["headers"]["cache-control"] == "no-store"
                    check_audit_stream(raw)
                    cases.append({"entry": entry, "headers": headers, "protocol": "signed admin", "status": 200})
                print(f"PASS {entry}: signed admin with all timeout variants", flush=True)
            if args.portable:
                common = [str(runner), "wire", "--base-url", origin + "/serve", "--auth", "auth-v2",
                    "--audience", "https://vcs.launch.invalid", "--repository", "default", "--signer-seed-hex", "5e" * 32,
                    "--run-id", "portable-contract", "--atomic-advance", "--fresh-target", "--sign-reads", "--milestone", "M5",
                    "--sharding", "d34", "--max-pack-bytes", "1073741824", "--features",
                    "health,indexed-async,indexed-mode,multi-repo,tickets,timers,http-objects,multipart,takedown,admin"]
                for prefix, expected in [("files.", 5), ("health.deadline_headers", 1), ("embedding.multipart_file_readback", 1), ("takedown.contract", 1)]:
                    portable_wire(common, prefix, expected, env, work, cases)
                harness.stop(process)
                process = subprocess.Popen(["npx", "--yes", f"wrangler@{harness.WRANGLER}", "dev", "--local",
                    "--config", str(config_path), "--ip", "127.0.0.1", "--port", str(args.port),
                    "--persist-to", str(work / "state"), "--show-interactive-dev-session=false"],
                    cwd=APP, env=env, stdout=log, stderr=log, start_new_session=True)
                harness.wait_ready(origin + "/direct/grpc.health.v1.Health/Check", process)
                portable_wire(common, "takedown.persisted_denial", 1, env, work, cases)
                observed = (work / "wrangler.log").read_text()
                assert "MKIT_CONFORMANCE_R2_GET" in observed, "range observer did not run"
                assert "MKIT_CONFORMANCE_ZERO_RANGE" not in observed, "zero-length backend range requested"
                print("PASS Worker restart: persisted takedown; zero-length R2 ranges=0", flush=True)
            assert harness.artifact_hashes(APP) == artifacts, "runtime artifacts changed"
            assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == source_sha
            assert not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
            evidence = {"source_sha": source_sha,
                        "wrangler": harness.WRANGLER, "artifacts": artifacts, "cases": cases}
            (work / "evidence.json").write_text(json.dumps(evidence, indent=2))
    finally:
        harness.stop(process)
        print(f"Deadline runtime evidence: {work}", flush=True)


if __name__ == "__main__":
    main()
