"""Signed managed Connect requests against local workerd (no native client)."""
import json
import http.client
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import blake3
from nacl.signing import SigningKey

ORIGIN = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].startswith("http") else "http://localhost:8791"
REPOSITORY = "managed-test"
SERVICE = "/mkit.transport.v1.TransportService/"
OWNER = SigningKey(bytes([7]) * 32)
READER = SigningKey(bytes([8]) * 32)
WRITER = SigningKey(bytes([9]) * 32)
STRANGER = SigningKey(bytes([10]) * 32)
GOLDEN = Path(__file__).resolve().parents[3] / "rust/tests/golden/managed-service"
MANIFEST_DIGEST, MANIFEST_NAME = (GOLDEN / "MANIFEST.txt").read_text().strip().split("  ")
GOLDEN_BYTES = (GOLDEN / MANIFEST_NAME).read_bytes()
assert blake3.blake3(GOLDEN_BYTES).hexdigest() == MANIFEST_DIGEST
VECTORS = json.loads(GOLDEN_BYTES)["vectors"]


def varint(number):
    out = bytearray()
    while number >= 128:
        out.append((number & 127) | 128)
        number >>= 7
    out.append(number)
    return bytes(out)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    if isinstance(value, str):
        value = value.encode()
    return varint((number << 3) | 2) + varint(len(value)) + value


def frame(payload, flag=0):
    return bytes([flag]) + len(payload).to_bytes(4, "big") + payload


def signed_headers(path, message, signer, commitment=None, content_type="application/proto"):
    now = int(time.time() * 1000)
    digest = blake3.blake3(message).hexdigest()
    commitment = commitment or "body:" + digest
    nonce = secrets.token_hex(32)
    canonical = "\n".join(["mkit-write:v2", ORIGIN, REPOSITORY, path, commitment, str(now), str(now + 300_000), nonce])
    signature = signer.sign(blake3.blake3(canonical.encode()).digest()).signature.hex()
    headers = {
        "Content-Type": content_type,
        "X-Envelope-Version": "2", "X-Audience": ORIGIN,
        "X-Repository": REPOSITORY, "X-Content-Commitment": commitment,
        "X-Created-At": str(now), "X-Expires-At": str(now + 300_000),
        "Idempotency-Key": nonce,
        "X-Public-Key": signer.verify_key.encode().hex(), "X-Signature": signature,
    }
    if commitment.startswith("body:"):
        headers["X-Digest"] = digest
    return headers


def send(path, body, headers=None, method="POST"):
    request = urllib.request.Request(ORIGIN + path, data=body, headers=headers or {}, method=method)
    try:
        response = urllib.request.urlopen(request)
    except urllib.error.HTTPError as error:
        response = error
    result = (response.status, response.read(), response.headers)
    assert result[2].get("Cache-Control") == "private, no-store", (path, result)
    return result


def rpc(method, message, signer, *, streaming=False, headers=None, body=None):
    path = SERVICE + method
    wire = body if body is not None else frame(message) if streaming else message
    selected = headers if headers is not None else (
        signed_headers(path, message, signer,
                       content_type="application/connect+proto" if streaming else "application/proto")
        if signer else {"Content-Type": "application/connect+proto" if streaming else "application/proto"}
    )
    return send(path, wire, selected)


def code(status, body, streaming=False):
    if status == 200 and body[:1] == b"\x02":
        return json.loads(body[5:])["error"]["code"]
    if status == 200:
        return "ok"
    return json.loads(body)["code"]


def admin(method, message, signer=OWNER):
    path = "/mkit/host/v1/" + method
    return send(path, message, signed_headers(path, message, signer, content_type="application/json"))


def policy(members, generation):
    return json.dumps({"version": 1, "expected_generation": str(generation), "collaborators": [
        {"public_key": key.verify_key.encode().hex(), "role": role}
        for key, role in sorted(members, key=lambda item: item[0].verify_key.encode())
    ]}, separators=(",", ":")).encode()


def main():
    init = json.dumps({"version": 1, "collaborators": [
        {"public_key": key.verify_key.encode().hex(), "role": role}
        for key, role in sorted([(READER, "reader"), (WRITER, "writer")], key=lambda item: item[0].verify_key.encode())
    ]}, separators=(",", ":")).encode()
    status, payload, _ = admin("InitializePolicy", init)
    assert status in (200, 409), (status, payload)
    if status == 409:
        current = json.loads(admin("GetPolicy", b'{"version":1}')[1])
        reset = policy([(READER, "reader"), (WRITER, "writer")], int(current["generation"]))
        status, payload, _ = admin("ReplacePolicy", reset)
        assert status == 200, (status, payload)
    for internal in ["get", "list", "update", "advance", "object", "authorize"]:
        result = send("/__test/refstore/" + internal, b"{}")
        assert result[0] in (400, 503), (internal, result[:2])
    assert send(SERVICE + "Future", b"{}")[0] == 503
    assert send("/grpc.health.v1.Health/Check", b"{}")[0] == 503
    cases = {
        "ListRefs": field(1, "refs/heads/"),
        "ReadRef": field(1, "refs/heads/main"),
        "PackExists": field(1, bytes(32)),
        "DownloadPack": field(1, bytes(32)),
        "UpdateRef": field(1, "refs/heads/main") + field(2, 2) + field(4, bytes([1]) * 32),
        "AdvanceRefs": field(1, "refs/heads/main") + field(2, 2) + field(4, bytes([2]) * 32)
            + field(5, "refs/mkit/packmap/main") + field(6, 2) + field(8, bytes([3]) * 32),
    }
    read_vector = VECTORS["ReadRef"]
    assert bytes.fromhex(read_vector["message_hex"]) == cases["ReadRef"]
    assert read_vector["digest"] == blake3.blake3(cases["ReadRef"]).hexdigest()
    for method, message in cases.items():
        for label, signer in [("anonymous", None), ("stranger", STRANGER), ("reader", READER), ("writer", WRITER), ("owner", OWNER)]:
            status, payload, _ = rpc(method, message, signer, streaming=method == "DownloadPack")
            allowed = label in ("writer", "owner") or (label == "reader" and method in ("ListRefs", "ReadRef", "PackExists", "DownloadPack"))
            result = code(status, payload, method == "DownloadPack")
            if allowed:
                assert result in ("ok", "not_found", "failed_precondition"), (method, label, status, payload)
            else:
                assert result in ("unauthenticated", "permission_denied"), (method, label, status, payload)
            print(method, label, result)
    pack = b"managed-pack-matrix"
    pack_id = blake3.blake3(pack).digest()
    header = field(1, pack_id) + field(2, len(pack))
    chunk = field(1, pack_id) + field(2, 0) + field(3, pack) + field(4, 1)
    upload = frame(field(1, header)) + frame(field(2, chunk))
    writer_upload_headers = None
    for label, signer in [("anonymous", None), ("stranger", STRANGER), ("reader", READER), ("writer", WRITER), ("owner", OWNER)]:
        path = SERVICE + "UploadPack"
        headers = signed_headers(path, b"", signer, "pack:" + pack_id.hex() + ":" + str(len(pack)), "application/connect+proto") if signer else {"Content-Type": "application/connect+proto"}
        status, payload, _ = send(path, upload, headers)
        result = code(status, payload)
        assert result == ("ok" if label in ("writer", "owner") else "unauthenticated" if label == "anonymous" else "permission_denied"), (label, status, payload)
        if label == "writer":
            writer_upload_headers = headers
        print("UploadPack", label, result)
    assert code(*rpc("PackExists", field(1, pack_id), OWNER)[:2]) == "ok"
    assert code(*rpc("DownloadPack", field(1, pack_id), READER, streaming=True)[:2], streaming=True) == "ok"

    # A signature covers the decoded DownloadPack message, not its 5-byte frame.
    path = SERVICE + "DownloadPack"
    message = field(1, pack_id)
    good = signed_headers(path, message, READER, content_type="application/connect+proto")
    pinned = VECTORS["DownloadPack"]
    assert bytes.fromhex(pinned["message_hex"]) == field(1, bytes(32))
    assert bytes.fromhex(pinned["framed_hex"]) == frame(bytes.fromhex(pinned["message_hex"]))
    assert pinned["digest"] != pinned["framed_digest"]
    assert good["X-Digest"] == blake3.blake3(message).hexdigest()
    assert good["X-Digest"] != blake3.blake3(frame(message)).hexdigest()
    wrong_message = field(1, bytes([5]) * 32)
    assert code(*rpc("DownloadPack", message, READER, streaming=True, headers=good, body=frame(wrong_message))[:2], streaming=True) == "unauthenticated"
    for invalid in [frame(message) + frame(message), frame(message) + b"\x00", frame(message, flag=1)]:
        result = rpc("DownloadPack", message, READER, streaming=True, headers=good, body=invalid)
        assert code(*result[:2], streaming=True) != "ok", (invalid[:8], result)
    compressed = good.copy()
    compressed["Connect-Content-Encoding"] = "gzip"
    assert code(*rpc("DownloadPack", message, READER, streaming=True, headers=compressed)[:2], streaming=True) != "ok"

    current = json.loads(admin("GetPolicy", b'{"version":1}')[1])
    replacement = policy([(READER, "reader")], int(current["generation"]))
    status, payload, _ = admin("ReplacePolicy", replacement)
    assert status == 200, (status, payload)
    assert code(*rpc("ReadRef", field(1, "refs/heads/main"), WRITER)[:2]) == "permission_denied"
    revoked = send(SERVICE + "UploadPack", upload, writer_upload_headers)
    assert code(*revoked[:2]) == "permission_denied", revoked
    assert code(*rpc("ReadRef", field(1, "refs/heads/main"), READER)[:2]) == "ok"
    assert code(*admin("GetPolicy", b'{"version":1}', WRITER)[:2]) == "unauthenticated"

    read_path = SERVICE + "ReadRef"
    read_message = field(1, "refs/heads/main")
    exact_headers = signed_headers(read_path, read_message, READER)
    for changed in ["X-Audience", "X-Repository", "X-Digest"]:
        bad = exact_headers.copy()
        bad[changed] = "wrong"
        assert code(*send(read_path, read_message, bad)[:2]) == "unauthenticated"
    assert code(*send(SERVICE + "ListRefs", read_message, exact_headers)[:2]) == "unauthenticated"
    assert code(*send(read_path, field(1, "refs/heads/other"), exact_headers)[:2]) == "unauthenticated"
    assert code(*send(read_path, read_message, exact_headers, method="GET")[:2]) == "method_not_allowed"
    huge_read = field(1, "a" * (64 * 1024))
    assert code(*rpc("ReadRef", huge_read, READER)[:2]) == "resource_exhausted"

    extra_pack = b"post-last-must-not-publish"
    extra_id = blake3.blake3(extra_pack).digest()
    extra_header = field(1, extra_id) + field(2, len(extra_pack))
    extra_chunk = field(1, extra_id) + field(2, 0) + field(3, extra_pack) + field(4, 1)
    extra_wire = frame(field(1, extra_header)) + frame(field(2, extra_chunk)) + frame(field(2, extra_chunk))
    extra_commitment = "pack:" + extra_id.hex() + ":" + str(len(extra_pack))
    extra_auth = signed_headers(SERVICE + "UploadPack", b"", OWNER, extra_commitment, "application/connect+proto")
    assert code(*send(SERVICE + "UploadPack", extra_wire, extra_auth)[:2]) != "ok"
    exists = rpc("PackExists", field(1, extra_id), OWNER)
    assert exists[0] == 200 and exists[1] == b"\x08\x00", exists

    too_big = signed_headers(SERVICE + "UploadPack", b"", OWNER,
                             "pack:" + extra_id.hex() + ":" + str(4 * 1024 * 1024 + 1),
                             "application/connect+proto")
    assert code(*send(SERVICE + "UploadPack", b"", too_big)[:2]) == "resource_exhausted"
    assert code(*send(SERVICE + "UploadPack", b"x" * (4 * 1024 * 1024 + 64 * 1024 + 1), extra_auth)[:2]) == "resource_exhausted"

    maximum_pack = b"m" * (4 * 1024 * 1024)
    maximum_id = blake3.blake3(maximum_pack).digest()
    maximum_header = field(1, maximum_id) + field(2, len(maximum_pack))
    maximum_wire = bytearray(frame(field(1, maximum_header)))
    for offset in range(0, len(maximum_pack), 800 * 1024):
        data = maximum_pack[offset:offset + 800 * 1024]
        chunk_message = field(1, maximum_id) + field(2, offset) + field(3, data)
        if offset + len(data) == len(maximum_pack):
            chunk_message += field(4, 1)
        maximum_wire.extend(frame(field(2, chunk_message)))
    assert len(maximum_wire) < 4 * 1024 * 1024 + 64 * 1024
    maximum_auth = signed_headers(SERVICE + "UploadPack", b"", OWNER,
                                  "pack:" + maximum_id.hex() + ":" + str(len(maximum_pack)),
                                  "application/connect+proto")
    assert code(*send(SERVICE + "UploadPack", maximum_wire, maximum_auth)[:2]) == "ok"
    downloaded = rpc("DownloadPack", field(1, maximum_id), READER, streaming=True)
    assert code(*downloaded[:2], streaming=True) == "ok", downloaded[:2]

    # The stalled chunked upload holds the same isolate's large-transfer
    # permit while owner administration stays available.
    held = threading.Event()
    resume = threading.Event()
    outcome = []

    def slow_upload():
        conn = http.client.HTTPConnection("localhost", 8791, timeout=30)
        conn.putrequest("POST", SERVICE + "UploadPack")
        for key, value in extra_auth.items():
            conn.putheader(key, value)
        conn.putheader("Transfer-Encoding", "chunked")
        conn.endheaders()
        part = frame(field(1, extra_header))
        conn.send(f"{len(part):x}\r\n".encode() + part + b"\r\n")
        held.set()
        resume.wait(20)
        conn.send(b"0\r\n\r\n")
        response = conn.getresponse()
        outcome.append((response.status, response.read()))
        conn.close()

    thread = threading.Thread(target=slow_upload)
    thread.start()
    assert held.wait(5)
    try:
        for _ in range(20):
            busy = send(SERVICE + "UploadPack", b"", extra_auth)
            if code(*busy[:2]) == "resource_exhausted":
                break
            time.sleep(0.05)
        else:
            raise AssertionError("large transfer permit was not observed busy")
        assert admin("GetPolicy", b'{"version":1}')[0] == 200
    finally:
        resume.set()
        thread.join(30)
    assert outcome and code(*outcome[0]) != "ok", outcome


if __name__ == "__main__":
    main()
