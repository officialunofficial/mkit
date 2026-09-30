#!/usr/bin/env python3
"""Build and probe the HTTP response bridge using owned local workerd servers."""
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIXTURE = Path(__file__).resolve().parent
WORKTREE = FIXTURE.parents[4]
PORT = int(os.environ.get("MKIT_HTTP_PROBE_PORT", "8836"))
DELAY_PORT = int(os.environ.get("MKIT_HTTP_PROBE_DELAY_PORT", "8837"))


def request(path, method="GET", headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        fields = {name.lower(): value for name, value in response.getheaders()}
        return response.status, fields, response.read()
    finally:
        connection.close()


def verify():
    passed = []
    status, _, body = request("/multipart")
    assert status == 200 and json.loads(body) == {"verified": True, "parts": 2}, (status, body)
    passed.append("local R2 multipart verifies before visibility and preserves exact bytes")
    status, headers, body = request("/raw?")
    assert status == 200 and json.loads(body)["query"] == ""
    passed.append("runtime trailing empty query preserved")
    status, headers, body = request("/raw?token=a%2Bb")
    assert json.loads(body)["query"] == "token=a%2Bb"
    passed.append("runtime escaped query preserved")
    status, headers, body = request("/raw/a%2Fb%3F?")
    assert json.loads(body) == {"path": "/raw/a%2Fb%3F", "query": ""}
    passed.append("runtime escaped path preserved")
    status, headers, body = request("/public/object")
    assert (status, body, headers["content-length"]) == (200, b"abcdef", "6")
    passed.append("streamed GET exact Content-Length")
    status, headers, body = request("/public/object", headers={"Range": "bytes=1-3"})
    assert (status, body, headers["content-length"], headers["content-range"]) == (
        206, b"bcd", "3", "bytes 1-3/6"
    )
    passed.append("streamed Range exact Content-Length")
    for expected in [200, 206, 302, 304, 400, 401, 402, 403, 404, 405, 416, 451, 503]:
        status, headers, body = request(f"/public/{expected}", "HEAD")
        assert status == expected and body == b""
        assert headers["content-length"] == ("3" if expected == 206 else "6")
    passed.append("HEAD full success/redirect/304/error status matrix")
    status, headers, body = request("/public/challenge")
    assert headers["www-authenticate"] == "Payment first, Payment second"
    assert headers["cache-control"] == "no-store"
    passed.append("repeated challenge headers retain ordered semantic list")
    for endpoint in ["object", "challenge", "notfound", "notmodified", "keys", "adapter-error"]:
        status, headers, body = request(f"/public/{endpoint}")
        assert headers["access-control-allow-origin"] == "*"
        assert "access-control-allow-credentials" not in headers
    passed.append("wildcard CORS success/error/304/challenge/keys")
    for origin, allowed in [("https://allowed.example", True), ("https://denied.example", False)]:
        status, headers, body = request("/restricted/challenge", headers={"Origin": origin})
        assert ("access-control-allow-origin" in headers) == allowed
        if allowed:
            assert headers["access-control-allow-origin"] == origin
        assert "Origin" in headers["vary"] and "Accept-Encoding" in headers["vary"]
    passed.append("restricted CORS allowed/disallowed origins and merged Vary")
    status, headers, body = request("/public/object", "OPTIONS")
    assert status == 204 and body == b"" and headers["access-control-allow-origin"] == "*"
    passed.append("wildcard preflight 204")
    for origin in ["https://allowed.example", "https://denied.example"]:
        status, headers, body = request("/restricted/object", "OPTIONS", {"Origin": origin})
        assert status == 204 and body == b""
        assert ("access-control-allow-origin" in headers) == (origin == "https://allowed.example")
        assert "Origin" in headers["vary"]
    passed.append("restricted preflight 204 allowed/disallowed origins")
    status, headers, body = request("/public/private")
    assert headers["cache-control"] == "private, max-age=10, immutable"
    passed.append("private response cache policy preserved")
    status, headers, body = request("/public/keys")
    document = json.loads(body)
    assert status == 200 and len(document["keys"]) == 1
    assert headers["cache-control"] == "public, max-age=300"
    assert headers["content-type"] == "application/json"
    passed.append("key document JSON Content-Type/cache/CORS")
    for endpoint, cache in [("adapter-error", "no-store"), ("private-adapter-error", "private, no-store")]:
        for method in ["GET", "HEAD"]:
            status, headers, body = request(f"/public/{endpoint}", method)
            assert status == 503 and headers["cache-control"] == cache
            assert headers["content-length"] == "16"
            assert body == (b"adapter failure!" if method == "GET" else b"")
            assert headers["x-content-type-options"] == "nosniff"
            assert headers["content-security-policy"] == "sandbox; default-src 'none'"
            assert headers["referrer-policy"] == "no-referrer"
            assert headers["access-control-allow-origin"] == "*"
        passed.append(f"outer policy {endpoint} 503 no-store/security/CORS/HEAD")
    started = time.monotonic()
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    try:
        connection.request("GET", "/public/slow")
        response = connection.getresponse()
        first = response.read(1)
        first_time = time.monotonic() - started
        tail = response.read()
        total = time.monotonic() - started
    finally:
        connection.close()
    assert first == b"a" and tail == b"bcdef"
    assert total - first_time > 0.9, (first_time, total)
    passed.append(f"stream first byte before EOF ({first_time:.3f}s first; {total:.3f}s complete)")
    return passed


class DelayHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(1.2)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        pass


def stop_process_group(process):
    # This group was created by this probe. Never signal unrelated workers.
    for stop_signal in [signal.SIGINT, signal.SIGTERM, signal.SIGKILL]:
        try:
            os.killpg(process.pid, stop_signal)
        except ProcessLookupError:
            process.wait(timeout=5)
            return
        try:
            process.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue
    raise RuntimeError(f"Owned probe process group {process.pid} did not stop")


def main():
    if "CARGO_TARGET_DIR" in os.environ:
        raise RuntimeError("Unset CARGO_TARGET_DIR; the probe uses this worktree's rust/target")
    for port in [PORT, DELAY_PORT]:
        if not 1024 <= port <= 65535:
            raise RuntimeError("Probe ports must be in 1024..=65535")
    if PORT == DELAY_PORT:
        raise RuntimeError("Probe and delay ports must differ")
    # Refuse an occupied probe port, without affecting its owner.
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", PORT))
    scratch_root = Path(os.environ.get("TMPDIR", str(Path.home() / ".cache/mkit-test-tmp/wp-4-16")))
    scratch_root.mkdir(parents=True, exist_ok=True)
    if scratch_root.resolve() != scratch_root.absolute():
        raise RuntimeError("TMPDIR must not contain a symlink")
    scratch = scratch_root / f"http-mount-probe-{os.getpid()}"
    scratch.mkdir()
    environment = dict(os.environ, TMPDIR=str(scratch), CARGO_PROFILE_DEV_DEBUG="0",
                       CARGO_PROFILE_TEST_DEBUG="0", WRANGLER_SEND_METRICS="false",
                       WRANGLER_LOG_PATH=str(scratch / "wrangler-debug.log"))
    output = scratch / "build"
    subprocess.run(["worker-build", "--dev", "--no-opt", "--out-dir", str(output),
                    str(FIXTURE), "--locked", "--target-dir", str(WORKTREE / "rust/target")],
                   cwd=WORKTREE, env=environment, check=True)
    delay = ThreadingHTTPServer(("127.0.0.1", DELAY_PORT), DelayHandler)
    thread = threading.Thread(target=delay.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        with (scratch / "wrangler.log").open("w") as log:
            process = subprocess.Popen([
                "npx", "--yes", "wrangler@4.134.0", "dev", str(output / "index.js"),
                "--local", "--ip", "127.0.0.1", "--port", str(PORT),
                "--config", str(FIXTURE / "wrangler.toml"),
                "--persist-to", str(scratch / "state"),
                "--var", f"DELAY_ORIGIN:http://127.0.0.1:{DELAY_PORT}",
            ], cwd=scratch, env=environment, stdout=log, stderr=log, start_new_session=True)
            deadline = time.monotonic() + 45
            while True:
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(f"Local workerd did not start; see {scratch / 'wrangler.log'}")
                try:
                    status, _, _ = request("/raw")
                    if status == 200:
                        break
                except (ConnectionError, OSError, http.client.HTTPException):
                    pass
                time.sleep(0.1)
            passed = verify()
            result = {"passed": len(passed), "checks": passed}
            (scratch / "results.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result, indent=2))
            print(f"Evidence: {scratch}")
    finally:
        try:
            if process is not None:
                stop_process_group(process)
        finally:
            delay.shutdown()
            delay.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()
