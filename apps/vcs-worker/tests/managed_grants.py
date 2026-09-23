"""Actual local workerd/SQLite owner grant lifecycle; use isolated --persist-to state."""
import base64
import json
import os
import secrets
import sqlite3
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import blake3
from nacl.signing import SigningKey

if len(sys.argv) > 1 and sys.argv[1].startswith("--"):
    sys.argv.insert(1, "http://localhost:8791")

from managed_access import admin, expect, send, make_headers
from managed_data import OWNER, READER, WRITER, STRANGER, field, rpc, code, varint

WORKSPACE = bytes([11]) * 32
BASE = bytes([12]) * 32
REANCHORED = bytes([13]) * 32
REF = "refs/heads/grant-test"


def grant(generation, authority, *, now=None, initial_base=BASE, subject=READER,
          paths=(("selected.txt", 3),), expires_delta=60_000, workspace_id=WORKSPACE):
    now = int(time.time() * 1000) if now is None else now
    body = bytearray(b"MKHG\x01")
    for value in ("http://localhost:8791", "managed-test", REF):
        value = value.encode()
        body.extend(varint(len(value)) + value)
    body.extend(workspace_id)
    for key in (OWNER, subject, WRITER):
        body.extend(key.verify_key.encode())
    body.extend(struct.pack(">QQ", authority, generation))
    body.extend(initial_base)
    body.extend(struct.pack(">QQI", now - 1000, now + expires_delta, 64))
    body.extend(varint(len(paths)))
    for path, mask in paths:
        parts = path.split("/")
        body.extend(varint(len(parts)))
        for part in parts:
            raw = part.encode()
            body.extend(varint(len(raw)) + raw)
        body.append(mask)
    digest = blake3.blake3(b"mkit.hosted-workspace-grant.v1\0" + body).digest()
    body.extend(OWNER.sign(digest).signature)
    return base64.urlsafe_b64encode(body).decode().rstrip("=")


def register(expected, credential, **kwargs):
    body = json.dumps({"version": 1, "expected_grant_generation": str(expected),
                       "grant": credential}, separators=(",", ":")).encode()
    return admin("RegisterGrant", body, **kwargs), body


def revoke(generation, grant_id, **kwargs):
    body = json.dumps({"version": 1, "workspace_id": WORKSPACE.hex(),
                       "expected_grant_generation": str(generation),
                       "grant_id": grant_id}, separators=(",", ":")).encode()
    return admin("RevokeGrant", body, **kwargs), body


def get():
    return admin("GetGrant", json.dumps({"version": 1, "workspace_id": WORKSPACE.hex()}).encode())


def storage_snapshot():
    state = os.environ.get("MKIT_GRANT_TEST_STATE")
    if not state:
        raise RuntimeError("set MKIT_GRANT_TEST_STATE to the isolated Wrangler --persist-to directory")
    files = list(Path(state).glob("v3/do/mkit-vcs-managed-local-test-RefStore/[0-9a-f]*.sqlite"))
    assert len(files) == 1, files
    with sqlite3.connect(files[0]) as db:
        tables = [name for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        return {name: list(db.execute("SELECT * FROM " + name + " ORDER BY 1")) for name in tables}


def state_db():
    state = os.environ["MKIT_GRANT_TEST_STATE"]
    files = list(Path(state).glob("v3/do/mkit-vcs-managed-local-test-RefStore/[0-9a-f]*.sqlite"))
    assert len(files) == 1, files
    return files[0]


def main():
    if not os.environ.get("MKIT_GRANT_TEST_STATE"):
        raise RuntimeError("MKIT_GRANT_TEST_STATE is required for SQLite no-effect evidence")
    if "--patch-overflow-offline" in sys.argv:
        # Run only after stopping Wrangler, in this disposable test database.
        now = int(time.time() * 1000)
        signed = grant(2**64 - 1, 1, now=now)
        raw = base64.urlsafe_b64decode(signed + "==")
        digest = blake3.blake3(b"mkit.hosted-workspace-grant-id.v1\0" + raw).hexdigest()
        with sqlite3.connect(state_db()) as db:
            db.execute("UPDATE host_grant_workspaces SET current_generation=? WHERE workspace_id=?",
                       (str(2**64 - 1), WORKSPACE.hex()))
            db.execute("UPDATE host_grant_incarnations SET grant_generation=?,grant_id=?,envelope=?,not_before=?,expires=? WHERE workspace_id=?",
                       (str(2**64 - 1), digest, signed, str(now - 1000), str(now + 60_000), WORKSPACE.hex()))
        print("offline disposable state patched to valid signed u64::MAX incarnation")
        return
    if "--verify-generation-overflow" in sys.argv:
        row = expect(200, get())
        assert row["grant_generation"] == str(2**64 - 1), row
        before = storage_snapshot()
        expect(409, register(2**64 - 1, grant(1, 1))[0])
        assert storage_snapshot() == before
        print("u64 grant-generation overflow conflicts without SQLite effects")
        return
    if "--seed-overflow" in sys.argv:
        expect(200, admin("InitializePolicy", b'{"version":1,"collaborators":[]}'))
        assert code(*rpc("UpdateRef", field(1, REF) + field(2, 2) + field(4, BASE), OWNER)[:2]) == "ok"
        expect(200, register(0, grant(1, 1))[0])
        print("overflow fixture seeded; stop Wrangler before offline patch")
        return
    if "--verify-expiry-replay" in sys.argv:
        expect(200, admin("InitializePolicy", b'{"version":1,"collaborators":[]}'))
        assert code(*rpc("UpdateRef", field(1, REF) + field(2, 2) + field(4, BASE), OWNER)[:2]) == "ok"
        credential = grant(1, 1, expires_delta=3_000)
        registered, body = register(0, credential)
        first = expect(200, registered)
        time.sleep(3.5)
        assert expect(200, get())["time_valid"] is False
        before = storage_snapshot()
        assert send("/mkit/host/v1/RegisterGrant", body, signed_headers=registered[3])[1] == first
        assert storage_snapshot() == before
        expect(400, register(1, grant(2, 1, expires_delta=-1))[0])
        assert storage_snapshot() == before
        print("exact auth-TTL replay survived credential expiry without SQLite mutation")
        return
    if "--verify-corrupt-schema" in sys.argv:
        before = storage_snapshot()
        expect(503, get())
        expect(503, register(4, grant(5, 2))[0])
        assert storage_snapshot() == before
        print("partial grant schema failed closed without auto-repair")
        return
    if "--verify-capacity" in sys.argv:
        kind = sys.argv[sys.argv.index("--verify-capacity") + 1]
        assert kind in ("workspace", "incarnation", "bytes"), kind
        before = storage_snapshot()
        meta = before["host_grant_meta"][0]
        current = (int(meta[2]), int(meta[3]), int(meta[4]))
        assert current == (1, 4, 1352), current
        observed = expect(200, get())["test_limits"]
        limits = (observed["workspaces"], observed["incarnations"], observed["bytes"])
        expected = {
            "workspace": (1, 5, 1690),
            "incarnation": (2, 4, 1690),
            "bytes": (2, 5, 1352),
        }[kind]
        assert limits == expected, (kind, limits, expected)
        if kind == "workspace":
            credential = grant(1, 2, initial_base=REANCHORED,
                               workspace_id=bytes([21]) * 32)
            expected_generation = 0
        else:
            credential = grant(5, 2, initial_base=REANCHORED)
            expected_generation = 4
        inserted_bytes = len(base64.urlsafe_b64decode(credential + "=="))
        prospective = (current[0] + int(kind == "workspace"), current[1] + 1,
                       current[2] + inserted_bytes)
        assert tuple(value > cap for value, cap in zip(prospective, limits)) == (
            kind == "workspace", kind == "incarnation", kind == "bytes"
        ), (kind, current, prospective, limits)
        candidate = register(expected_generation, credential)[0]
        expect(429, candidate)
        assert storage_snapshot() == before
        assert expect(200, get())["grant_generation"] == "4"
        print("lowered", kind, "registry capacity denied without any SQLite effect")
        return
    if "--verify-storage-fault" in sys.argv:
        before = storage_snapshot()
        row = expect(200, get())
        expect(503, revoke(4, row["grant_id"])[0])
        assert storage_snapshot() == before
        assert expect(200, get())["status"] == "active"
        print("injected SQLite write failure rolled back grant and replay")
        return
    if "--verify-existing" in sys.argv:
        row = expect(200, get())
        assert row["grant_generation"] == "4" and row["status"] == "active", row
        assert row["workspace_head"] == REANCHORED.hex() and row["snapshot_readiness"] == "not_checked"
        print("grant registry survived workerd restart")
        return

    # Create a healthy owner policy and a pre-existing branch head. A grant
    # cannot create its ref or certify any object graph.
    expect(200, admin("InitializePolicy", b'{"version":1,"collaborators":[]}'))
    expect(404, get())
    assert code(*rpc("UpdateRef", field(1, REF) + field(2, 2) + field(4, BASE), OWNER)[:2]) == "ok"
    signed = grant(1, 1)
    before = storage_snapshot()
    bad, _ = register(0, signed, signer=STRANGER)
    expect(401, bad)
    assert storage_snapshot() == before
    expect(415, admin("RegisterGrant", b"{}", encoding="gzip"))
    expect(413, admin("RegisterGrant", b" " * (384 * 1024 + 1)))
    assert storage_snapshot() == before
    registered, body = register(0, signed)
    first = expect(200, registered)
    assert first == {"version": 1, "workspace_id": WORKSPACE.hex(),
                     "grant_id": first["grant_id"], "grant_generation": "1", "status": "active"}
    assert expect(200, get())["grant"] == signed
    assert send("/mkit/host/v1/RegisterGrant", body, signed_headers=registered[3])[1] == first
    assert code(*rpc("ReadRef", field(1, REF), READER)[:2]) == "permission_denied"

    # Distinct new nonces race for the same expected generation. Exactly one
    # renewal commits, with no replay row for the losing CAS.
    next_grant = grant(2, 1)
    with ThreadPoolExecutor(max_workers=4) as pool:
        races = list(pool.map(lambda _: register(1, next_grant)[0], range(4)))
    assert sorted(item[0] for item in races) == [200, 409, 409, 409], races
    current = expect(200, get())
    assert current["grant_generation"] == "2" and current["status"] == "active"
    assert current["grant_id"] != first["grant_id"]

    # Revoke a current incarnation; an exact signed nonce retry returns the
    # recorded outcome without a second write. A changed body with that nonce
    # conflicts, and a new-nonce duplicate revoke conflicts.
    request = json.dumps({"version": 1, "workspace_id": WORKSPACE.hex(),
                          "expected_grant_generation": "2", "grant_id": current["grant_id"]},
                         separators=(",", ":")).encode()
    path = "/mkit/host/v1/RevokeGrant"
    headers = make_headers(path, request)
    first_revoke = send(path, request, signed_headers=headers)
    expect(200, first_revoke)
    assert send(path, request, signed_headers=headers)[1] == first_revoke[1]
    expect(409, revoke(2, current["grant_id"])[0])
    different = request + b" "
    changed = make_headers(path, different, nonce=headers["Idempotency-Key"])
    expect(409, send(path, different, signed_headers=changed))
    assert expect(200, get())["status"] == "revoked"

    # Renewal after revocation preserves the tombstone and identity.
    next_grant = grant(3, 1)
    third = expect(200, register(2, next_grant)[0])
    assert third["grant_generation"] == "3"
    assert expect(200, get())["grant_generation"] == "3"
    assert code(*rpc("UpdateRef", field(1, REF) + field(2, 1) + field(4, REANCHORED), OWNER)[:2]) == "ok"
    before = storage_snapshot()
    expect(409, register(3, grant(4, 1, initial_base=BASE))[0])
    assert storage_snapshot() == before
    fourth = expect(200, register(3, grant(4, 1, initial_base=REANCHORED))[0])
    assert fourth["grant_generation"] == "4"
    reanchored = expect(200, get())
    assert reanchored["workspace_head"] == REANCHORED.hex()
    assert reanchored["snapshot_readiness"] == "not_checked"
    replacement = b'{"version":1,"expected_generation":"1","collaborators":[]}'
    expect(200, admin("ReplacePolicy", replacement))
    stale = expect(200, get())
    assert not stale["authority_generation_matches"]
    assert stale["status"] == "active" and stale["snapshot_readiness"] == "not_checked"
    expect(400, register(4, grant(5, 1, initial_base=REANCHORED))[0])
    expect(400, register(4, grant(5, 2, initial_base=REANCHORED, expires_delta=-1))[0])
    assert send("/mkit/host/v1/RegisterGrant", body, signed_headers=registered[3])[1] == first
    expect(409, register(4, grant(5, 2, initial_base=REANCHORED, subject=STRANGER))[0])
    assert code(*rpc("ReadRef", field(1, REF), READER)[:2]) == "permission_denied"
    print("owner registration, CAS, replay, revocation, renewal, policy invalidation passed")


if __name__ == "__main__":
    main()
