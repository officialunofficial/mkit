"""Test-only R2-pause race against disposable local workerd/SQLite state.

Requires a ready enrollment, active grant, test-faults build and
`wrangler dev --var C2_TEST_PAUSE_MS:1000 --persist-to STATE`.
"""
import json
import os
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

INPUT_ARGS = sys.argv[1:]
sys.argv.insert(1, "http://localhost:8791")
from managed_access import admin, expect, send
from managed_data import OWNER, READER, code, field, rpc
from managed_disclosure import credential

WORKSPACE = "0b" * 32
ROUTE = "/mkit/partial/v1/GetWorkspace"


def db_path(state):
    found = list(Path(state).glob("v3/do/mkit-vcs-managed-local-test-RefStore/[0-9a-f]*.sqlite"))
    assert len(found) == 1, found
    return found[0]


def read_count(database):
    with sqlite3.connect(database) as db:
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE name='c2_test_reads'").fetchone()
        return db.execute("SELECT COUNT(*) FROM c2_test_reads").fetchone()[0] if exists else 0


def main(directory, mode="revoke", enrollment=False):
    state = os.environ["MKIT_C2_TEST_STATE"]
    database = db_path(state)
    fixture = json.loads((Path(directory) / "manifest.json").read_bytes())
    current = expect(200, admin("GetGrant", json.dumps({
        "version": 1, "workspace_id": WORKSPACE,
    }).encode()))
    assert current["status"] == "active"
    request = {"version": 1, "workspace_id": WORKSPACE,
               "grant_id": current["grant_id"],
               "grant_generation": current["grant_generation"],
               "expected_ref": "refs/heads/snapshot-test",
               "expected_base": fixture["root"], "paths": [["file0000"]]}
    body = json.dumps(request, separators=(",", ":")).encode()
    before = read_count(database)
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(send, ROUTE, body, signer=READER)
        deadline = time.monotonic() + 5
        while read_count(database) == before and time.monotonic() < deadline:
            time.sleep(.01)
        assert read_count(database) > before, "disclosure did not enter first range"
        busy = send(ROUTE, body, signer=READER)
        assert busy[0] == 429 and busy[1] == {"code": "resource_exhausted"}, busy
        if enrollment:
            job = expect(200, admin("GetSnapshotJob", json.dumps({
                "version": 1, "job_id": "2" * 64,
            }, separators=(",", ":")).encode()))
            assert job["state"] == "catalog"
            stepped = admin("ContinueSnapshot", json.dumps({
                "version": 1, "job_id": job["job_id"],
                "job_generation": job["job_generation"],
                "expected_revision": job["revision"],
            }, separators=(",", ":")).encode())
            assert stepped[0] == 429 and stepped[1] == {"code": "resource_exhausted"}, stepped
            assert expect(200, admin("GetSnapshotJob", json.dumps({
                "version": 1, "job_id": "2" * 64,
            }, separators=(",", ":")).encode()))["revision"] == job["revision"]
        with sqlite3.connect(database) as db:
            assert db.execute("SELECT COUNT(*) FROM host_snapshot_leases").fetchone()[0] == 1
        started = time.monotonic()
        if mode == "revoke":
            changed = expect(200, admin("RevokeGrant", json.dumps({
                "version": 1, "workspace_id": WORKSPACE,
                "expected_grant_generation": current["grant_generation"],
                "grant_id": current["grant_id"],
            }, separators=(",", ":")).encode()))
            assert changed["status"] == "revoked"
        elif mode == "renew":
            next_generation = int(current["grant_generation"]) + 1
            policy = expect(200, admin("GetPolicy", b'{"version":1}'))
            signed, _ = credential(fixture["root"], generation=next_generation,
                                    authority_generation=int(policy["generation"]))
            expect(200, admin("RegisterGrant", json.dumps({
                "version": 1, "expected_grant_generation": current["grant_generation"],
                "grant": signed,
            }, separators=(",", ":")).encode()))
        elif mode == "policy":
            policy = expect(200, admin("GetPolicy", b'{"version":1}'))
            expect(200, admin("ReplacePolicy", json.dumps({
                "version": 1, "expected_generation": policy["generation"],
                "collaborators": [],
            }, separators=(",", ":")).encode()))
        elif mode in ("head", "packmap"):
            name = ("refs/heads/snapshot-test" if mode == "head"
                    else "refs/mkit/packmap/snapshot-test")
            update = field(1, name) + field(2, 1) + field(4, bytes([27]) * 32)
            assert code(*rpc("UpdateRef", update, OWNER)[:2]) == "ok"
        else:
            raise AssertionError(mode)
        latency = time.monotonic() - started
        assert latency < .8, f"owner admin blocked behind R2 pause: {latency:.3f}s"
        response = future.result(timeout=8)
    assert response[0] == 409 and response[1] == {"code": "conflict"}, response
    assert not response[4].startswith(b"MKWB")
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT COUNT(*) FROM host_snapshot_leases").fetchone()[0] == 0
    print("actual workerd paused disclosure fenced by", mode, "owner latency", round(latency, 3),
          "read rows", read_count(database) - before)


if __name__ == "__main__":
    main(INPUT_ARGS[0], INPUT_ARGS[1] if len(INPUT_ARGS) > 1 else "revoke",
         "--enrollment" in INPUT_ARGS)
