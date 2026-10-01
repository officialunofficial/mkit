#!/usr/bin/env python3
"""Local launch evidence; component success never marks the complete matrix PASS."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "docs/plans/mkit-server/launch-cases.json"
WRANGLER = "4.134.0"
LANES = {
    "native": ["cargo", "nextest", "run", "--locked", "--manifest-path", "rust/Cargo.toml",
               "-p", "mkit-server", "-p", "mkit-server-native", "-p", "mkit-server-worker",
               "-p", "mkit-server-conformance", "--all-features", "--test-threads", "1"],
    "baseline": ["bash", "scripts/vcs-worker-conformance.sh", "--multi", "--", "--filter", "info."],
    "hooks": ["bash", "scripts/vcs-worker-conformance.sh", "--hooks", "--", "--filter", "info."],
    "authority": ["bash", "scripts/vcs-worker-authority.sh", "--authority"],
}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def validate():
    matrix = json.loads(CASES.read_text())
    assert matrix["schema"] == 1
    cases = matrix["cases"]
    ids = [case["id"] for case in cases]
    assert len(ids) == len(set(ids)) and len(ids) >= 20
    for case in cases:
        assert set(case) == {"id", "contract", "native", "worker", "phase2"}
        assert all(isinstance(value, str) and value.strip() for value in case.values())
    assert all(any(name.startswith(prefix) for name in ids) for prefix in ("B3.", "B4.", "B5."))
    assert len(matrix["external"]) == 6
    return matrix


def request(url, method="GET", body=None):
    headers = {"content-type": "application/json", "connect-protocol-version": "1"}
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    # Local fixture traffic must never go through a configured external proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=3) as response:
            return response.status, dict(response.headers), response.read(65537)
    except urllib.error.HTTPError as response:
        return response.code, dict(response.headers), response.read(65537)


def release_launch(run, env, evidence):
    """Actual release opt-in, with HTTP tokens; inspection and takedown stay off."""
    invoke(["worker-build", "--release", "--features", "launch"], run / "build.log", env,
           cwd=ROOT / "apps/vcs-worker", evidence=evidence)
    artifact_root = ROOT / "apps/vcs-worker/build"
    evidence["artifact_sha256"] = {
        str(path.relative_to(artifact_root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in artifact_root.rglob("*") if path.is_file()
    }
    required = ("index_bg.wasm", "index.js", "worker/shim.mjs", "package.json")
    if any(name not in evidence["artifact_sha256"] for name in required):
        raise RuntimeError("release build is missing optimized wasm or JavaScript artifacts")
    if not (artifact_root / "index_bg.wasm").read_bytes().startswith(b"\0asm"):
        raise RuntimeError("release build did not emit a valid wasm artifact")
    evidence["build_features"] = ["launch"]
    evidence["compatibility_date"] = "2026-09-09"
    evidence["wrangler_version"] = WRANGLER
    port_text = env.get("VCS_CONFORMANCE_PORT")
    if not port_text or not port_text.isdecimal() or not 1024 <= int(port_text) <= 65535:
        raise RuntimeError("release-launch requires a private VCS_CONFORMANCE_PORT in 1024..65535")
    port = int(port_text)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))
    # These public test seeds are confined to an isolated, empty local state.
    token = "active " + "22" * 32
    command = ["npx", "--yes", "wrangler@" + WRANGLER, "dev", "--local",
               "--config", "wrangler.dev.jsonc", "--ip", "127.0.0.1", "--port", str(port),
               "--persist-to", str(run / "state"), "--show-interactive-dev-session=false"]
    for name, value in {
        "AUTH_AUDIENCE": "https://vcs.launch.invalid", "LAUNCH_PROFILE": "uno",
        "INDEXED_MODE": "true", "WORKERS_PLAN": "paid", "ADDRESSING": "multi",
        "SHARDING": "d34", "NAMESPACE_POLICY": "any", "UNSAFE_OPEN_NAMESPACES": "true",
        "RETENTION": "permanent", "STORAGE_LEASES": "false", "GC_ENABLED": "false",
        "TICKET_KEYS": "launch-ticket " + "11" * 32,
        "HTTP_OBJECTS": "true", "URL_TOKEN_KEYS": token,
    }.items():
        command += ["--var", name + ":" + value]
    origin = "http://127.0.0.1:" + str(port)
    url = origin + "/mkit.transport.v1.TransportService/GetServerInfo"
    with (run / "wrangler.log").open("w") as log:
        process = subprocess.Popen(command, cwd=ROOT / "apps/vcs-worker", env=env,
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        # Do not serialize fake secret values in the reproduction command record.
        evidence["commands"].append({"cwd": "apps/vcs-worker", "command":
                                     "wrangler dev --local with fixed public launch fixture vars",
                                     "pid": process.pid, "log": "wrangler.log"})
        try:
            deadline = time.monotonic() + 120
            while True:
                if process.poll() is not None:
                    raise RuntimeError("wrangler exited; see wrangler.log")
                try:
                    status, _, body = request(url, "POST", b"{}")
                    (run / "discovery.json").write_bytes(body)
                    if status == 200:
                        break
                    if status == 503 and b"requires WP-" in body:
                        raise RuntimeError("release launch still refuses a prerequisite; see discovery.json")
                except (urllib.error.URLError, TimeoutError):
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("release launch did not become ready; see wrangler.log")
                time.sleep(0.25)
            (run / "discovery.json").write_bytes(body)
            info = json.loads(body)
            for name, expected in {"indexedMode": True, "leases": False, "asyncInspection": False,
                                   "namespacePolicy": "any", "beginUploadThresholdBytes": "0"}.items():
                assert info.get(name) == expected, (name, info.get(name))
            assert "inspectionMaxObjects" not in info
            assert not info.get("receiptPublicKey") and not info.get("receiptKeyId")
            # GetServerInfo has no proof field in this protocol. Any future proof
            # capability field must remain false/absent for the launch Worker.
            assert not any(value for key, value in info.items() if "proof" in key.lower())
            key_status, _, keys = request(origin + "/.well-known/mkit-url-token-keys.json")
            assert key_status == 200
            json.loads(keys)
            (run / "url-token-public-keys.json").write_bytes(keys)
            test_status, _, _ = request(origin + "/__mkit_test/stats")
            assert test_status != 200, "release artifact exposes a test-faults route"
            evidence["assertions"] = ["Paid indexed release discovery", "leases/async false",
                                      "threshold zero", "no inspector bound or proof claim",
                                      "HTTP URL-token key mount", "test-faults route absent"]
            evidence["limitations"] = ["No inspection/admin/takedown opted in in this lane",
                                       "Discovery does not prove Worker proof rejection on reachable bytes",
                                       "No wire writes, extraction payload or stream-lifetime proof in this lane"]
        finally:
            # Kill only the process group created by this invocation.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)


def invoke(command, log_path, env, cwd=ROOT, evidence=None):
    if evidence is not None:
        evidence["commands"].append({"cwd": str(cwd.relative_to(ROOT)) or ".",
                                     "argv": command, "log": log_path.name})
    with log_path.open("w") as log:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError("command failed (" + str(result.returncode) + "); see " + str(log_path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lane", choices=["validate", "plan", *LANES, "release-launch", "full"])
    parser.add_argument("--sha", help="required exact immutable HEAD for executable lanes")
    args = parser.parse_args()
    matrix = validate()
    if args.lane == "validate":
        print("Launch skeleton valid:", len(matrix["cases"]), "itemized B3/B4/B5 cases; no PASS implied")
        return 0
    if args.lane == "plan":
        print(json.dumps({"cases": matrix["cases"], "lanes": LANES,
                          "release-launch": "actual release launch+HTTP discovery, isolated wrangler",
                          "full": "BLOCKED: phase 2 per-case release matrix and preservation required"}, indent=2))
        return 0
    if args.lane == "full":
        raise RuntimeError("full launch matrix is pending phase 2: WP-5.6a-2 preservation, publication recheck timer 12 repair #1245, "
                           "and itemized actual release probes; component suite success is insufficient")
    head = git("rev-parse", "HEAD")
    if args.sha != head:
        raise RuntimeError("--sha must equal the full 40-character current HEAD: " + head)
    if git("status", "--porcelain", "--untracked-files=normal"):
        raise RuntimeError("commit the candidate first; exact-SHA evidence refuses a dirty worktree")
    if "CARGO_TARGET_DIR" in os.environ:
        raise RuntimeError("unset CARGO_TARGET_DIR; launch evidence uses this worktree's rust/target")
    scratch = Path(os.environ.get("TMPDIR", ""))
    owned = Path.home() / ".cache/mkit-test-tmp/wp-4-18"
    if not scratch.is_absolute() or not scratch.is_relative_to(owned):
        raise RuntimeError("TMPDIR must be under ~/.cache/mkit-test-tmp/wp-4-18")
    scratch.mkdir(parents=True, exist_ok=True)
    if scratch.resolve() != scratch:
        raise RuntimeError("TMPDIR must not contain symlinks")
    run = Path(tempfile.mkdtemp(prefix="launch-" + args.lane + "-", dir=scratch))
    env = os.environ.copy()
    env.update({"CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
                "WRANGLER_SEND_METRICS": "false", "VCS_CONFORMANCE_KEEP": "1",
                "WRANGLER_REGISTRY_PATH": str(run / "registry")})
    tool_versions = {}
    for command in (["cargo", "--version"], ["rustc", "--version"], ["node", "--version"]):
        try:
            tool_versions[command[0]] = subprocess.check_output(command, cwd=ROOT, env=env,
                                                               stderr=subprocess.STDOUT, text=True).strip()
        except (OSError, subprocess.CalledProcessError):
            tool_versions[command[0]] = "UNAVAILABLE"
    if args.lane in {"baseline", "hooks", "authority"} and not env.get("VCS_CONFORMANCE_PORT"):
        raise RuntimeError("set your owned VCS_CONFORMANCE_PORT before a wrangler lane")
    evidence = {"schema": 1, "candidate_sha": head, "tree_sha": git("rev-parse", "HEAD^{tree}"),
                "base_sha": git("merge-base", "HEAD", "origin/feat/mkit-server"),
                "origin_feature_sha": git("rev-parse", "origin/feat/mkit-server"),
                "matrix_sha256": hashlib.sha256(CASES.read_bytes()).hexdigest(),
                "tool_versions": tool_versions,
                "lane": args.lane, "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "artifact_kind": "native/all-features" if args.lane == "native" else
                                 "test-faults runtime + release binding" if args.lane == "hooks" else "release",
                "commands": [], "result": "RUNNING", "launch_matrix_result": "UNRUN",
                "cases": [{"id": case["id"], "native": "UNRUN", "release_worker": "UNRUN"}
                          for case in matrix["cases"]],
                "external": {gate: "UNRUN" for gate in matrix["external"]}}
    output = run / "evidence.json"
    if args.lane == "hooks":
        evidence["limitations"] = [
            "Wire suite filtered to discovery; this is a component smoke lane",
            "Fetch/Delay signed runtime probes use a test-faults wrapper",
            "Complete opted-in release signed exchanges remain required in phase 2",
        ]
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    print("Evidence directory:", run, flush=True)
    try:
        if args.lane == "release-launch":
            release_launch(run, env, evidence)
        else:
            invoke(LANES[args.lane], run / "suite.log", env, evidence=evidence)
        if git("rev-parse", "HEAD") != head or git("status", "--porcelain", "--untracked-files=normal"):
            raise RuntimeError("candidate changed during the run; evidence invalidated")
        evidence["result"] = "PASS"
    except Exception as error:
        evidence["result"] = "FAIL"
        evidence["error"] = str(error)
        raise
    finally:
        evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evidence["log_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in run.glob("*.log")}
        output.write_text(json.dumps(evidence, indent=2) + "\n")
    print("Component lane PASS; complete launch matrix and external gates remain UNRUN:", output)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, KeyError, ValueError, RuntimeError) as error:
        print("launch evidence refused:", str(error), file=sys.stderr)
        sys.exit(1)
