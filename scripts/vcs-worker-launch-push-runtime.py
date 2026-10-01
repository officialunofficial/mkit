#!/usr/bin/env python3
"""Pin native zstd push -> optimized Paid launch Worker over local HTTPS -> clone."""
import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps/vcs-worker"
WRANGLER = "4.134.0"
RPC = "/mkit.transport.v1.TransportService/GetServerInfo"
FILE_BYTES = 512 * 1024
PACK_CAP = 64 * 1024 * 1024
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def clean_pin(root, sha):
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or git(root, "rev-parse", "HEAD") != sha:
        raise RuntimeError(f"source pin must equal immutable HEAD in {root}")
    if git(root, "status", "--porcelain", "--untracked-files=normal"):
        raise RuntimeError(f"commit all candidate source before running evidence: {root}")
    return {"sha": sha, "tree_sha": git(root, "rev-parse", "HEAD^{tree}")}


def digest(path):
    # Stream native binary, Wasm, and pack hashes without resident copies.
    with path.open("rb") as source:
        checksum = hashlib.sha256()
        for block in iter(lambda: source.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def invoke(command, cwd, log, env, evidence, timeout=900):
    item = {"argv": list(map(str, command)), "cwd": str(cwd),
            "log": str(log.relative_to(evidence["directory"]))}
    evidence["commands"].append(item)
    started = time.monotonic()
    with log.open("w") as output:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=timeout)
        except BaseException:
            stop(process)
            raise
    item["wall_seconds"] = round(time.monotonic() - started, 3)
    item["exit_code"] = process.returncode
    if process.returncode:
        raise RuntimeError(f"command failed ({process.returncode}); see {log}")
    return log.read_text()


def stop(process):
    # This invocation owns only the group started with start_new_session=True.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)


def request(origin, context, path=RPC, body=b"{}"):
    req = urllib.request.Request(origin + path, data=body,
                                 headers={"content-type": "application/json",
                                          "connect-protocol-version": "1"},
                                 method="POST" if body is not None else "GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(req, timeout=5) as response:
            return response.status, response.read(65537)
    except urllib.error.HTTPError as response:
        return response.code, response.read(65537)


def certificates(run, env, evidence):
    tls = run / "tls"
    tls.mkdir(mode=0o700)
    extension = tls / "localhost.ext"
    extension.write_text("basicConstraints=critical,CA:FALSE\n"
                         "keyUsage=critical,digitalSignature,keyEncipherment\n"
                         "extendedKeyUsage=serverAuth\n"
                         "subjectAltName=DNS:localhost,IP:127.0.0.1\n")
    commands = [
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
         "-days", "2", "-subj", "/CN=mkit local push fixture CA",
         "-keyout", str(tls / "ca.key"), "-out", str(tls / "ca.crt"),
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
         "-subj", "/CN=localhost", "-keyout", str(tls / "localhost.key"),
         "-out", str(tls / "localhost.csr")],
        ["openssl", "x509", "-req", "-sha256", "-days", "2", "-set_serial", "2",
         "-in", str(tls / "localhost.csr"), "-CA", str(tls / "ca.crt"),
         "-CAkey", str(tls / "ca.key"), "-extfile", str(extension),
         "-out", str(tls / "localhost.crt")],
        ["openssl", "verify", "-CAfile", str(tls / "ca.crt"),
         "-verify_hostname", "localhost", str(tls / "localhost.crt")],
    ]
    for index, command in enumerate(commands):
        invoke(command, run, run / f"tls-{index}.log", env, evidence, timeout=30)
    (tls / "ca.key").chmod(0o600)
    (tls / "localhost.key").chmod(0o600)
    evidence["tls"] = {"ca_certificate_sha256": digest(tls / "ca.crt"),
                       "leaf_certificate_sha256": digest(tls / "localhost.crt"),
                       "hostname": "localhost", "verification_bypassed": False}
    return tls


def fixture_files(repo):
    payload = repo / "payload"
    payload.mkdir()
    manifest = {}
    # 35 MiB of distinct incompressible data keeps the on-wire pack >33 MiB;
    # 3 MiB of distinct compressible data exercises native zstd entry encoding.
    for index in range(76):
        if index < 70:
            name = f"payload/random-{index:03}.bin"
            data = hashlib.shake_256(f"WP-4.18 native push {index}".encode()).digest(FILE_BYTES)
        else:
            name = f"payload/compressible-{index:03}.txt"
            phrase = f"WP-4.18 zstd-native release-worker file {index}\n".encode()
            data = (phrase * (FILE_BYTES // len(phrase) + 1))[:FILE_BYTES]
        (repo / name).write_bytes(data)
        manifest[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    return manifest


def blob_path(state, blob_id):
    # Pin Miniflare's local R2 schema and backing blobs, never a cloud API.
    if not isinstance(blob_id, str) or not re.fullmatch(r"[0-9a-f]{32,128}", blob_id):
        raise RuntimeError("unexpected pinned Miniflare R2 blob identity")
    matches = [path for path in state.rglob(blob_id) if path.parent.name == "blobs"
               and "r2" in path.parts and path.is_file()]
    if len(matches) != 1:
        raise RuntimeError(f"local R2 blob missing or ambiguous: {blob_id}")
    return matches[0]


def inspect_pack(data):
    if len(data) < 44 or data[:4] != b"MKIT":
        raise RuntimeError("R2 source object is not a canonical MKIT pack")
    version, count = struct.unpack_from("<II", data, 4)
    if version not in (1, 2) or not 1 <= count <= 4096:
        raise RuntimeError("fixture source pack version or entry count is invalid")
    offset = 12
    kinds = {}
    frames = []
    for index in range(count):
        if offset + 5 > len(data) - 32:
            raise RuntimeError("truncated source pack entry")
        kind, length = struct.unpack_from("<BI", data, offset)
        offset += 5
        if kind not in (0, 2, 3, 4) or offset + length > len(data) - 32:
            raise RuntimeError("invalid source pack entry framing")
        kinds[str(kind)] = kinds.get(str(kind), 0) + 1
        if kind in (3, 4):
            prefix = 4 if kind == 3 else 36
            if version != 2 or length < prefix + 4:
                raise RuntimeError("invalid compressed source pack entry")
            declared = struct.unpack_from("<I", data, offset + prefix - 4)[0]
            if not 0 < declared <= 1024 * 1024:
                raise RuntimeError("fixture zstd entry exceeds indexed entry limit")
            if data[offset + prefix:offset + prefix + 4] != ZSTD_MAGIC:
                raise RuntimeError("canonical zstd frame magic missing in source pack")
            frames.append({"entry": index, "kind": kind, "declared_bytes": declared,
                           "frame_offset": offset + prefix, "frame_bytes": length - prefix})
        offset += length
    if offset != len(data) - 32:
        raise RuntimeError("source pack has trailing or missing entry bytes")
    return {"version": version, "entries": count, "entry_kinds": kinds, "zstd_frames": frames}


def source_packs(state):
    packs = []
    auxiliary = []
    for path in sorted(state.rglob("*.sqlite")):
        if "r2" not in path.parts:
            continue
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as database:
            tables = {row[0] for row in database.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if "_mf_objects" not in tables:
                continue
            rows = database.execute(
                "SELECT key, blob_id, size FROM _mf_objects WHERE key LIKE 'packs/%' LIMIT 9"
            ).fetchall()
            if len(rows) > 8:
                raise RuntimeError("fixture unexpectedly produced more than eight source packs")
            for key, identity, length in rows:
                if len(packs) + len(auxiliary) >= 8:
                    raise RuntimeError("fixture unexpectedly produced more than eight source packs")
                if not 5 <= length <= PACK_CAP:
                    raise RuntimeError("fixture source pack exceeds bounded inspection size")
                if identity is None:
                    parts = database.execute(
                        "SELECT blob_id, size FROM _mf_multipart_parts WHERE object_key = ? "
                        "ORDER BY part_number LIMIT 10", (key,)).fetchall()
                    if not parts or len(parts) > 9 or sum(size for _, size in parts) != length:
                        raise RuntimeError("unexpected source pack multipart shape")
                else:
                    parts = [(identity, length)]
                paths = [blob_path(state, identity) for identity, _ in parts]
                if any(path.stat().st_size != size for path, (_, size) in zip(paths, parts)):
                    raise RuntimeError("R2 source blob size differs from metadata")
                data = b"".join(path.read_bytes() for path in paths)
                record = {"key": key, "bytes": length,
                          "sha256": hashlib.sha256(data).hexdigest(),
                          "metadata_database": str(path.relative_to(state)),
                          "local_parts": [str(part.relative_to(state)) for part in paths]}
                # Auxiliary packlist nodes share the packs/ keyspace. They
                # are verified by native clone and must not be parsed as packs.
                if data[:5] == b"MKPL\x01":
                    if length > 4096:
                        raise RuntimeError("initial fixture packlist unexpectedly large")
                    auxiliary.append({**record, "format": "packlist-v1"})
                else:
                    packs.append({**record, **inspect_pack(data)})
    if not packs or not any(pack["zstd_frames"] for pack in packs):
        raise RuntimeError("native push produced no canonical zstd frames in local R2 source")
    if not any(pack["bytes"] > 33 * 1024 * 1024 for pack in packs):
        raise RuntimeError("fixture did not exercise a source pack larger than 33 MiB")
    if not auxiliary:
        raise RuntimeError("native push published no packlist node in local R2")
    return packs, auxiliary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True, help="clean committed Worker candidate SHA")
    parser.add_argument("--cli-worktree", type=Path, required=True,
                        help="independent native CLI worktree containing the CA-file prerequisite")
    parser.add_argument("--cli-sha", required=True, help="exact clean native CLI source SHA")
    args = parser.parse_args()
    cli_root = args.cli_worktree.resolve()
    candidate = clean_pin(ROOT, args.sha)
    cli_source = clean_pin(cli_root, args.cli_sha)
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
        raise RuntimeError("set private VCS_CONFORMANCE_PORT in 1024..65535")
    port = int(port_text)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))
    previous_umask = os.umask(0o077)
    run = Path(tempfile.mkdtemp(prefix="launch-push-", dir=scratch))
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("MKIT_", "TEST_", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"))
           and key.lower() not in {"http_proxy", "https_proxy", "all_proxy"}}
    env.update(CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
               WRANGLER_SEND_METRICS="false", WRANGLER_REGISTRY_PATH=str(run / "registry"))
    evidence = {"schema": 1, "candidate": candidate, "cli_source": cli_source,
                "base_sha": git(ROOT, "merge-base", "HEAD", "origin/feat/mkit-server"),
                "origin_feature_sha": git(ROOT, "rev-parse", "origin/feat/mkit-server"),
                "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "directory": str(run), "wrangler_version": WRANGLER,
                "commands": [], "checks": [], "result": "RUNNING",
                "launch_matrix_result": "UNRUN", "tool_versions": {},
                "limitations": ["Local workerd and R2 emulation, no deployed resource claim",
                                "Single initial push/clone, no delta, overlap, or crash/restart coverage",
                                "No CPU, resident-memory, or physical-call bound measured by this probe",
                                "Public proof, inspection, admin, and takedown paths are not enabled"]}
    print("Evidence directory:", run, flush=True)
    process = None
    try:
        for tool in ["cargo", "rustc", "node", "worker-build", "openssl"]:
            command = [tool, "version"] if tool == "openssl" else [tool, "--version"]
            evidence["tool_versions"][tool] = subprocess.check_output(
                command, cwd=ROOT, env=env, stderr=subprocess.STDOUT, text=True, timeout=10).strip()
        invoke(["cargo", "build", "--locked", "-p", "mkit-cli", "--bin", "mkit"],
               cli_root / "rust", run / "cli-build.log", env, evidence)
        cli = run / "mkit"
        shutil.copy2(cli_root / "rust/target/debug/mkit", cli)
        evidence["cli_binary_sha256"] = digest(cli)
        invoke(["worker-build", "--release", "--features", "launch"], APP,
               run / "worker-build.log", env, evidence)
        artifact = run / "artifact"
        shutil.copytree(APP / "build", artifact)
        required = [artifact / "worker/shim.mjs", artifact / "index.js", artifact / "index_bg.wasm"]
        if not all(path.is_file() for path in required):
            raise RuntimeError("worker-build produced no complete optimized launch artifact")
        wasm = required[-1].read_bytes()
        if not wasm.startswith(b"\0asm"):
            raise RuntimeError("release artifact is not WebAssembly")
        evidence["artifact"] = {"features": ["launch"],
                                "sha256": {str(path.relative_to(artifact)): digest(path)
                                           for path in artifact.rglob("*") if path.is_file()},
                                "wasm_raw_bytes": len(wasm),
                                "wasm_gzip_bytes": len(gzip.compress(wasm, mtime=0))}
        del wasm
        tls = certificates(run, env, evidence)
        origin = f"https://localhost:{port}"
        remote = "mkit+" + origin + "/default"
        classes = [("REFSTORE", "RefStore"), ("NS_COORD", "NsCoordinator"),
                   ("REF_SHARD", "RefShard"), ("REPO_INDEX", "RepoIndexShard"),
                   ("CONTENT_INDEX", "ContentIndexShard")]
        config = {"name": "mkit-launch-push", "main": str(artifact / "worker/shim.mjs"),
                  "compatibility_date": "2026-09-09", "build": {"command": "true"},
                  "vars": {"AUTH_AUDIENCE": origin, "LAUNCH_PROFILE": "uno",
                           "WORKERS_PLAN": "paid", "INDEXED_MODE": "true", "ADDRESSING": "multi",
                           "SHARDING": "d34", "NAMESPACE_POLICY": "any",
                           "UNSAFE_OPEN_NAMESPACES": "true", "RETENTION": "permanent",
                           "STORAGE_LEASES": "false", "GC_ENABLED": "false",
                           "TICKET_KEYS": "launch-push-ticket " + "11" * 32},
                  "r2_buckets": [{"binding": "STORAGE", "bucket_name": "launch-push-objects"},
                                 {"binding": "BACKUPS", "bucket_name": "launch-push-backups"}],
                  "durable_objects": {"bindings": [{"name": binding, "class_name": cls}
                                                     for binding, cls in classes]},
                  "migrations": [{"tag": "v1", "new_sqlite_classes": [cls for _, cls in classes]}]}
        config_path = run / "wrangler.json"
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        evidence["config_sha256"] = digest(config_path)
        state = run / "state"
        command = ["npx", "--yes", "wrangler@" + WRANGLER, "dev", "--local", "--config",
                   str(config_path), "--ip", "127.0.0.1", "--port", str(port),
                   "--persist-to", str(state), "--show-interactive-dev-session=false",
                   "--local-protocol", "https", "--https-key-path", str(tls / "localhost.key"),
                   "--https-cert-path", str(tls / "localhost.crt")]
        evidence["commands"].append({"argv": command, "cwd": str(APP), "log": "wrangler.log"})
        with (run / "wrangler.log").open("w") as log:
            process = subprocess.Popen(command, cwd=APP, env=env, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            context = ssl.create_default_context(cafile=str(tls / "ca.crt"))
            deadline = time.monotonic() + 120
            while True:
                if process.poll() is not None:
                    raise RuntimeError("Wrangler exited; see wrangler.log")
                try:
                    status, body = request(origin, context)
                    if status == 200:
                        break
                    (run / "startup-response.json").write_bytes(body)
                except (urllib.error.URLError, TimeoutError):
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("release Worker HTTPS startup timed out")
                time.sleep(0.25)
            info = json.loads(body)
            (run / "discovery.json").write_bytes(body)
            for key, expected in {"indexedMode": True, "leases": False,
                                  "asyncInspection": False, "namespacePolicy": "any",
                                  "beginUploadThresholdBytes": "0"}.items():
                if info.get(key) != expected:
                    raise RuntimeError(f"launch discovery {key}={info.get(key)!r}, wanted {expected!r}")
            if any(value for key, value in info.items() if "proof" in key.lower()):
                raise RuntimeError("Worker advertised unsupported launch proofs")
            try:
                request(origin, ssl.create_default_context())
            except urllib.error.URLError as error:
                if not isinstance(error.reason, ssl.SSLCertVerificationError):
                    raise RuntimeError("default CA failure was not certificate verification") from error
            else:
                raise RuntimeError("default CA unexpectedly trusted scratch-only certificate")
            if request(origin, context, "/__mkit_test/stats", None)[0] == 200:
                raise RuntimeError("release artifact exposes test-faults stats")
            evidence["checks"] += ["Paid Uno indexed Any discovery", "HTTPS CA and hostname verified",
                                   "default CA rejects scratch-only chain", "test-faults stats absent"]
            home = run / "cli-home"
            xdg = home / ".config"
            xdg.mkdir(parents=True)
            cli_env = dict(env, HOME=str(home), XDG_CONFIG_HOME=str(xdg),
                           MKIT_SSL_CA_FILE=str(tls / "ca.crt"), EDITOR="true", VISUAL="true",
                           GIT_EDITOR="true")
            repo = home / "source"
            repo.mkdir()
            counter = 0

            def mkit(cwd, *arguments):
                nonlocal counter
                counter += 1
                return invoke([str(cli), *arguments], cwd,
                              run / f"cli-{counter:02}-{arguments[0]}.log", cli_env, evidence)

            mkit(repo, "init")
            keys = repo / ".mkit/keys"
            keys.mkdir(mode=0o700, exist_ok=True)
            key = keys / "default.key"
            key.write_bytes(bytes.fromhex("11" * 32))
            key.chmod(0o600)
            # Both source and fresh clone resolve this existing signer from
            # isolated user config. Security-sensitive -c keys are refused.
            mkit(repo, "config", "--global", "signing_key", str(key))
            mkit(repo, "config", "--global", "transport_auth", "envelope")
            mkit(repo, "config", "trusted_remote_endpoint", remote)
            # Match native grant fixtures: bypass only remote-add's loopback URL
            # policy in local fixture config, never TLS or envelope validation.
            with (repo / ".mkit/config").open("a") as output:
                output.write(f"\nremote.origin.url = {remote}\nremote.origin.type = https\n")
            manifest = fixture_files(repo)
            (run / "files.json").write_text(json.dumps(manifest, indent=2) + "\n")
            evidence["fixture"] = {"file_count": len(manifest),
                                   "total_file_bytes": sum(item["bytes"] for item in manifest.values()),
                                   "largest_file_bytes": FILE_BYTES,
                                   "manifest_sha256": digest(run / "files.json")}
            mkit(repo, "add", ".")
            mkit(repo, "commit", "-m", "WP-4.18 native zstd launch round trip")
            expected_head = mkit(repo, "rev-parse", "HEAD").strip()
            if not re.fullmatch(r"[0-9a-f]{64}", expected_head):
                raise RuntimeError("native source commit did not resolve to an object ID")
            push_log = mkit(repo, "push", "origin")
            if "Waiting for server verification" not in push_log or "Server verification complete" not in push_log:
                raise RuntimeError("native push did not report pending verification and terminal completion")
            evidence["checks"].append("real native push observed pending verification then completion")
            cloned = run / "clone"
            mkit(run, "clone", remote, str(cloned))
            actual_head = mkit(cloned, "rev-parse", "HEAD").strip()
            if actual_head != expected_head:
                raise RuntimeError("native clone HEAD differs from signed source commit")
            actual_files = {str(path.relative_to(cloned)) for path in cloned.rglob("*")
                            if path.is_file() and ".mkit" not in path.relative_to(cloned).parts}
            if actual_files != set(manifest):
                raise RuntimeError("cloned worktree file set differs from committed fixture")
            for name, expected in manifest.items():
                path = cloned / name
                if path.stat().st_size != expected["bytes"] or digest(path) != expected["sha256"]:
                    raise RuntimeError(f"native clone content mismatch: {name}")
            evidence["commit_id"] = expected_head
            evidence["checks"] += ["native clone verified signed HEAD", "exact cloned file set and SHA256"]
        stop(process)
        process = None
        evidence["source_packs"], evidence["packlist_blobs"] = source_packs(state)
        evidence["checks"] += ["actual local R2 source pack exceeds 33 MiB",
                               "canonical v2 zstd frame magic at parsed entry boundaries"]
        clean_pin(ROOT, args.sha)
        clean_pin(cli_root, args.cli_sha)
        evidence["result"] = "PASS"
    except Exception as error:
        evidence["result"] = "FAIL"
        evidence["error"] = str(error)
        raise
    finally:
        if process is not None:
            stop(process)
        evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evidence["log_sha256"] = {str(path.relative_to(run)): digest(path)
                                  for path in run.rglob("*")
                                  if path.is_file() and path.suffix in {".log", ".json"}
                                  and path.name != "evidence.json"}
        (run / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        os.umask(previous_umask)
    print("Native push/clone component PASS; full matrix remains UNRUN:", run / "evidence.json")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as error:
        print("native launch push/clone failed:", error, file=sys.stderr)
        sys.exit(1)
