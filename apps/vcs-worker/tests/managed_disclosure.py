"""Disposable local workerd C2 test after managed_snapshots.py enrolled a fixture.

Usage: python tests/managed_disclosure.py FIXTURE_DIR
The enrollment and this test must use the same --persist-to state and live worker.
"""
import base64
import json
import struct
import sys
import time
from pathlib import Path

import blake3

sys.argv.insert(1, "http://localhost:8791")
from managed_access import admin, expect, send
from managed_data import OWNER, READER, STRANGER, WRITER, varint

ROUTE = "/mkit/partial/v1/GetWorkspace"
REF = "refs/heads/snapshot-test"
WORKSPACE = bytes([11]) * 32


def credential(base, generation=1, subject=READER, paths=("file0000",), expires_ms=600_000,
               authority_generation=1):
    now = int(time.time() * 1000)
    raw = bytearray(b"MKHG\x01")
    for text in ("http://localhost:8791", "managed-test", REF):
        value = text.encode()
        raw.extend(varint(len(value)) + value)
    raw.extend(WORKSPACE)
    for key in (OWNER, subject, WRITER):
        raw.extend(key.verify_key.encode())
    raw.extend(struct.pack(">QQ", authority_generation, generation))
    raw.extend(bytes.fromhex(base))
    raw.extend(struct.pack(">QQI", now - 1000, now + expires_ms, 64))
    raw.extend(varint(len(paths)))
    for path in paths:
        parts = path.split("/")
        raw.extend(varint(len(parts)))
        for part in parts:
            part = part.encode()
            raw.extend(varint(len(part)) + part)
        raw.append(1)
    digest = blake3.blake3(b"mkit.hosted-workspace-grant.v1\0" + raw).digest()
    raw.extend(OWNER.sign(digest).signature)
    return base64.urlsafe_b64encode(raw).decode().rstrip("="), blake3.blake3(
        b"mkit.hosted-workspace-grant-id.v1\0" + raw).hexdigest()


def post(value, signer=READER, body=None, headers=None):
    body = body if body is not None else json.dumps(value, separators=(",", ":")).encode()
    return send(ROUTE, body, signer=signer, signed_headers=headers)


def main(directory):
    manifest = json.loads((directory / "manifest.json").read_bytes())
    base = manifest["root"]
    generation = 1
    if "--renew" in sys.argv:
        current = expect(200, admin("GetGrant", json.dumps({
            "version": 1, "workspace_id": WORKSPACE.hex(),
        }).encode()))
        generation = int(current["grant_generation"]) + 1
    policy = expect(200, admin("GetPolicy", b'{"version":1}'))
    signed, grant_id = credential(base, generation=generation,
                                  authority_generation=int(policy["generation"]))
    if "--revoke" in sys.argv or "--existing" in sys.argv:
        current = expect(200, admin("GetGrant", json.dumps({
            "version": 1, "workspace_id": WORKSPACE.hex(),
        }).encode()))
        grant_id = current["grant_id"]
        generation = int(current["grant_generation"])
    if "--revoke" not in sys.argv and "--existing" not in sys.argv:
        registered = expect(200, admin("RegisterGrant", json.dumps({
            "version": 1, "expected_grant_generation": str(generation - 1), "grant": signed,
        }, separators=(",", ":")).encode()))
        assert registered["grant_id"] == grant_id
    request = {"version": 1, "workspace_id": WORKSPACE.hex(), "grant_id": grant_id,
               "grant_generation": str(generation), "expected_ref": REF,
               "expected_base": base, "paths": [["file0000"]]}
    if "--revoke" in sys.argv:
        revoked = expect(200, admin("RevokeGrant", json.dumps({
            "version": 1, "workspace_id": WORKSPACE.hex(),
            "expected_grant_generation": str(generation), "grant_id": grant_id,
        }, separators=(",", ":")).encode()))
        assert revoked["status"] == "revoked"
        assert post(request)[0] == 403
        return
    result = post(request)
    assert result[0] == 200, result
    assert result[2]["Content-Type"] == "application/octet-stream"
    assert int(result[2]["Content-Length"]) == len(result[4])
    assert result[4].startswith(b"MKWB")
    assert len(result[4]) <= 4 * 1024 * 1024
    assert post(request, signer=STRANGER)[0] == 403
    assert post({**request, "expected_base": "0" * 64,
                 "grant_generation": "999"}, signer=STRANGER)[0] == 403
    assert post({**request, "paths": [["file0001"]]})[0] == 403
    assert post({**request, "expected_base": "0" * 64})[0] == 409
    assert post({**request, "expected_ref": "refs/heads/other"})[0] == 409
    assert post({**request, "grant_generation": "999"})[0] == 409
    assert post({**request, "paths": [["file0000"], ["file0000"]]})[0] == 400
    assert post(request, body=b'{}')[0] == 400
    original = json.dumps(request, separators=(",", ":")).encode()
    from managed_access import make_headers
    bad = make_headers(ROUTE, original, signer=READER)
    bad["X-Audience"] = "http://127.0.0.1:8791"
    assert post(request, headers=bad)[0] == 401
    bad = make_headers(ROUTE, original, signer=READER)
    bad["X-Digest"] = "0" * 64
    assert post(request, headers=bad)[0] == 401
    if "--hold" in sys.argv:
        print("actual workerd C2 selected bytes", len(result[4]), "grant", grant_id, "base", base)
        return
    revoked = expect(200, admin("RevokeGrant", json.dumps({
        "version": 1, "workspace_id": WORKSPACE.hex(),
        "expected_grant_generation": str(generation), "grant_id": grant_id,
    }, separators=(",", ":")).encode()))
    assert revoked["status"] == "revoked"
    assert post(request)[0] == 403
    print("actual workerd C2 selected bytes", len(result[4]), "grant", grant_id, "base", base)


if __name__ == "__main__":
    main(Path(sys.argv[2]))
