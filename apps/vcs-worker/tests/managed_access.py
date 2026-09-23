"""Actual local workerd + SQLite DO managed authority smoke and negatives.

Run after `worker-build --release --features managed-access` and
`npx wrangler dev -c wrangler.managed.dev.jsonc --port 8791`.
The key is the committed auth-v2 test vector, never a production key.
"""
import json
import http.client
import secrets
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import sys
import time
import urllib.error
import urllib.request

import blake3
from nacl.signing import SigningKey

ORIGIN = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8791"
REPO = "managed-test"
SEED = bytes([7] * 32)
KEY = SigningKey(SEED)
OWNER = KEY.verify_key.encode().hex()
FOREIGN = SigningKey(bytes([8] * 32))
GOLDEN = Path(__file__).resolve().parents[3] / "rust/tests/golden/server-access"

def fixture(name):
    return (GOLDEN / name).read_bytes()

def assert_vector(name, result):
    metadata = json.loads(fixture(name.replace(".json", ".meta.json")))
    assert result[0] == metadata["status"], (name, result)
    assert result[4] == fixture(metadata["response"]), (name, result[4])
    if "generation" in metadata:
        assert result[1]["generation"] == metadata["generation"]


def make_headers(path, body, signer=KEY, nonce=None, content_type="application/json"):
    nonce = nonce or secrets.token_hex(32)
    now = int(time.time() * 1000)
    expiry = now + 300_000
    digest = blake3.blake3(body).hexdigest()
    commitment = "body:" + digest
    canonical = "\n".join(["mkit-write:v2", ORIGIN, REPO, path, commitment, str(now), str(expiry), nonce])
    signature = signer.sign(blake3.blake3(canonical.encode()).digest()).signature.hex()
    return {
        "Content-Type": content_type, "X-Envelope-Version": "2", "X-Audience": ORIGIN,
        "X-Repository": REPO, "X-Content-Commitment": commitment, "X-Digest": digest,
        "X-Created-At": str(now), "X-Expires-At": str(expiry), "Idempotency-Key": nonce,
        "X-Public-Key": signer.verify_key.encode().hex(), "X-Signature": signature,
    }


def send(path, body=b"", *, signer=KEY, nonce=None, method="POST", content_type="application/json", encoding=None, signed_headers=None):
    headers = signed_headers.copy() if signed_headers is not None else make_headers(path, body, signer, nonce, content_type)
    if encoding:
        headers["Content-Encoding"] = encoding
    request = urllib.request.Request(ORIGIN + path, data=body, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(request)
    except urllib.error.HTTPError as error:
        response = error
    payload = response.read()
    try:
        parsed = json.loads(payload)
    except ValueError:
        parsed = payload.decode(errors="replace")
    return response.status, parsed, response.headers, headers, payload


def chunked(path, body):
    headers = make_headers(path, body)
    headers["Transfer-Encoding"] = "chunked"
    connection = http.client.HTTPConnection("localhost", 8791)
    chunks = (body[index:index + 8192] for index in range(0, len(body), 8192))
    connection.request("POST", path, body=chunks, headers=headers, encode_chunked=True)
    response = connection.getresponse()
    result = (response.status, json.loads(response.read()), response.headers, headers)
    connection.close()
    return result


def admin(operation, body, **kwargs):
    return send("/mkit/host/v1/" + operation, body, **kwargs)


def expect(status, got):
    assert got[0] == status, (status, got)
    assert got[2].get("Cache-Control") == "private, no-store", got
    return got[1]


def main():
    expired = json.dumps({"identity": {"audience": ORIGIN, "repository": REPO, "owner": OWNER},
                          "proof": {"scope": "expired-test", "author": OWNER, "fingerprint": "expired-test", "expires_at": 0},
                          "operation": "get", "body": "{\"version\":1}"}).encode()
    if "--verify-existing" in sys.argv:
        policy = expect(200, admin("GetPolicy", b'{"version":1}'))
        assert policy["generation"] == "2" and policy["owner"] == OWNER
        expect(409, admin("InitializePolicy", b'{"version":1,"collaborators":[]}'))
        for route in ["ListRefs", "ReadRef", "PackExists", "DownloadPack", "UpdateRef", "AdvanceRefs", "UploadPack"]:
            assert send("/mkit.transport.v1.TransportService/" + route, b"{}")[0] == 503
        expect(401, send("/__test/refstore/managed-policy", expired))
        print("managed workerd: persisted latch survived restart; data plane closed")
        return
    if "--verify-mismatch" in sys.argv:
        expect(503, admin("GetPolicy", b'{"version":1}', signer=FOREIGN))
        expect(503, admin("InitializePolicy", b'{"version":1,"collaborators":[]}', signer=FOREIGN))
        print("managed workerd: configured identity mismatch fails closed")
        return
    if "--verify-concurrency" in sys.argv:
        init = b'{"version":1,"collaborators":[]}'
        expect(503, admin("GetPolicy", b'{"version":1}'))
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda i: admin("InitializePolicy", init, nonce=(i + 1).to_bytes(32, "big").hex()), range(8)))
        assert len({result[3]["Idempotency-Key"] for result in results}) == 8
        assert sorted(result[0] for result in results) == [200] + [409] * 7, results
        policy = expect(200, admin("GetPolicy", b'{"version":1}'))
        assert policy["generation"] == "1"
        candidates = [json.dumps({"version": 1, "expected_generation": "1", "collaborators":
                    [{"public_key": SigningKey(bytes([i] * 32)).verify_key.encode().hex(), "role": "reader" if i % 2 else "writer"}]}).encode()
                    for i in range(8, 16)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            replacements = list(pool.map(lambda pair: admin("ReplacePolicy", pair[1], nonce=(pair[0] + 101).to_bytes(32, "big").hex()), enumerate(candidates)))
        assert len({result[3]["Idempotency-Key"] for result in replacements}) == 8
        assert sorted(result[0] for result in replacements) == [200] + [409] * 7, replacements
        winner = next(result[1] for result in replacements if result[0] == 200)
        assert expect(200, admin("GetPolicy", b'{"version":1}')) == winner
        assert winner["generation"] == "2" and len(winner["collaborators"]) == 1
        print("managed workerd: concurrent bootstrap and replace each committed once")
        return
    if "--probe-uninitialized" in sys.argv:
        expect(503, admin("GetPolicy", b'{"version":1}'))
        expect(503, admin("ReplacePolicy", b'{"version":1,"expected_generation":"0","collaborators":[]}'))
        print("managed workerd: pre-initialization reads return unavailable")
        return
    if "--verify-unavailable" in sys.argv:
        expect(503, admin("GetPolicy", b'{"version":1}'))
        expect(503, admin("InitializePolicy", b'{"version":1,"collaborators":[]}'))
        assert send("/mkit.transport.v1.TransportService/ReadRef", b"{}")[0] == 503
        print("managed workerd: damaged persisted authority fails closed")
        return
    if "--verify-overflow" in sys.argv:
        maximum = "18446744073709551615"
        policy = expect(200, admin("GetPolicy", b'{"version":1}'))
        assert policy["generation"] == maximum
        replacement = json.dumps({"version": 1, "expected_generation": maximum, "collaborators": []}).encode()
        expect(409, admin("ReplacePolicy", replacement))
        assert expect(200, admin("GetPolicy", b'{"version":1}')) == policy
        print("managed workerd: generation overflow left policy unchanged")
        return
    if "--verify-pending" in sys.argv:
        policy = expect(200, admin("GetPolicy", b'{"version":1}'))
        wire = json.dumps({"identity": {"audience": ORIGIN, "repository": REPO, "owner": OWNER},
                           "proof": {"scope": "pending-test", "author": OWNER, "fingerprint": "pending-test", "expires_at": int(time.time() * 1000) + 300_000},
                           "operation": "replace", "body": json.dumps({"version": 1, "expected_generation": policy["generation"], "collaborators": []})}).encode()
        expect(503, send("/__test/refstore/managed-policy", wire))
        assert expect(200, admin("GetPolicy", b'{"version":1}')) == policy
        print("managed workerd: incomplete replay row fails closed")
        return
    if "--verify-storage-failure" in sys.argv:
        policy = expect(200, admin("GetPolicy", b'{"version":1}'))
        replacement = json.dumps({"version": 1, "expected_generation": policy["generation"], "collaborators": []}).encode()
        expect(503, admin("ReplacePolicy", replacement))
        assert expect(200, admin("GetPolicy", b'{"version":1}')) == policy
        print("managed workerd: policy write failure left visible policy unchanged")
        return
    if "--verify-init-failure" in sys.argv:
        expect(503, admin("InitializePolicy", b'{"version":1,"collaborators":[]}'))
        expect(503, admin("GetPolicy", b'{"version":1}'))
        print("managed workerd: failed bootstrap left authority unavailable")
        return
    if "--verify-chunked" in sys.argv:
        payload = fixture("get.json")
        exact = payload + b" " * (65_536 - len(payload))
        assert len(exact) == 65_536
        policy = expect(200, chunked("/mkit/host/v1/GetPolicy", exact))
        expect(413, chunked("/mkit/host/v1/GetPolicy", exact + b" "))
        expect(503, chunked("/grpc.health.v1.Health/Check", exact + b" "))
        expect(503, send("/grpc.health.v1.Health/Check", b"{}"))
        assert expect(200, admin("GetPolicy", payload)) == policy
        print("managed workerd: lengthless chunked body exact/over cap passed")
        return
    init = fixture("initialize.json")
    expect(401, admin("InitializePolicy", init, signer=FOREIGN))
    assert expect(503, admin("GetPolicy", fixture("get.json"))) == json.loads(fixture("unavailable-response.json"))
    expect(503, admin("ReplacePolicy", b'{"version":1,"expected_generation":"0","collaborators":[]}'))
    expect(405, admin("GetPolicy", b'{"version":1}', method="GET"))
    expect(415, admin("InitializePolicy", init, encoding="gzip"))
    invalid = admin("InitializePolicy", fixture("invalid-duplicate.json"))
    assert_vector("invalid-duplicate.json", invalid)
    for route in ["ListRefs", "ReadRef", "PackExists", "DownloadPack", "UpdateRef", "AdvanceRefs", "UploadPack"]:
        code, _, response_headers, _, _ = send("/mkit.transport.v1.TransportService/" + route, b"{}")
        assert code == 503, (route, code)
        assert response_headers.get("Cache-Control") == "private, no-store"
    for route in ["get", "list", "update", "advance", "object"]:
        code, _, _, _, _ = send("/__test/refstore/" + route, b"{}")
        assert code == 503, (route, code)
    expect(401, send("/__test/refstore/managed-policy", expired))
    original = send("/mkit/host/v1/InitializePolicy", init)
    policy = expect(200, original)
    assert policy["generation"] == "1" and policy["owner"] == OWNER
    assert_vector("initialize.json", original)
    assert expect(200, send("/mkit/host/v1/InitializePolicy", init, signed_headers=original[3])) == policy
    expect(409, send("/mkit/host/v1/InitializePolicy", b'{ "version":1,"collaborators":[]}', nonce=original[3]["Idempotency-Key"]))
    got = admin("GetPolicy", fixture("get.json"))
    assert expect(200, got) == policy
    assert_vector("get.json", got)
    conflict = admin("InitializePolicy", init)
    expect(409, conflict)
    assert conflict[4] == fixture("conflict-response.json")
    replacement = fixture("replace.json")
    replaced = admin("ReplacePolicy", replacement)
    changed = expect(200, replaced)
    assert changed["generation"] == "2"
    assert_vector("replace.json", replaced)
    assert expect(200, send("/mkit/host/v1/ReplacePolicy", replacement, signed_headers=replaced[3])) == changed
    expect(409, admin("ReplacePolicy", replacement))
    assert expect(200, admin("GetPolicy", fixture("get.json"))) == changed
    assert send("/not-a-route", b"{}")[0] == 503
    print("managed workerd: owner bootstrap, durable policy/CAS and seven-route closure passed")


if __name__ == "__main__":
    main()
