"""Enroll a generated C2 resource fixture and exercise its bounded read.

Run against a fresh disposable managed Wrangler state/test-faults build.
`disclosure_resource_fixture` emits the compatible manifest and raw-v1 packs.
"""
import json
import os
import sqlite3
import sys
from pathlib import Path

import blake3

FIXTURE = Path(sys.argv[1])
RESUME = "--resume" in sys.argv
READ_ONLY = "--read-only" in sys.argv
sys.argv.insert(1, "http://localhost:8791")
from managed_access import admin, expect
from managed_data import OWNER, code, field, rpc
from managed_snapshots import upload_pack
from managed_disclosure import WORKSPACE, REF, credential, post


def main():
    fixture = json.loads((FIXTURE / "manifest.json").read_bytes())
    if RESUME or READ_ONLY:
        state = expect(200, admin("GetSnapshotJob", b'{"version":1,"job_id":"1111111111111111111111111111111111111111111111111111111111111111"}'))
    else:
        expect(200, admin("InitializePolicy", b'{"version":1,"collaborators":[]}'))
        for pack in sorted(FIXTURE.glob("*.pack")):
            payload = pack.read_bytes()
            assert len(payload) <= 4 * 1024 * 1024
            assert blake3.blake3(payload).hexdigest() == pack.stem
            upload_pack(pack.stem, payload)
        update = (field(1, REF) + field(2, 2) + field(4, bytes.fromhex(fixture["root"]))
                  + field(5, "refs/mkit/packmap/snapshot-test") + field(6, 2)
                  + field(8, bytes.fromhex(fixture["tip"])))
        assert code(*rpc("AdvanceRefs", update, OWNER)[:2]) == "ok"
        begin = {"version": 1, "job_id": "1" * 64, "ref": REF,
                 "expected_head": fixture["root"], "expected_packmap": fixture["tip"],
                 "selected_pack_keys": fixture["selected"]}
        state = expect(200, admin("BeginSnapshot", json.dumps(begin, separators=(",", ":")).encode()))
    if state["state"] != "ready":
        for attempt in range(8192):
            step = {"version": 1, "job_id": state["job_id"],
                    "job_generation": state["job_generation"],
                    "expected_revision": state["revision"]}
            state = expect(200, admin("ContinueSnapshot", json.dumps(step, separators=(",", ":")).encode()))
            if state["state"] == "ready":
                break
            if attempt % 128 == 0:
                print("enrollment", fixture["mode"], attempt, state["state"], flush=True)
        else:
            raise AssertionError("resource fixture enrollment exhausted attempts")
    assert int(state["progress"]["reached_bytes"]) == fixture["unique_canonical_bytes"], state
    paths = fixture["selected_paths"]
    if READ_ONLY:
        current = expect(200, admin("GetGrant", json.dumps({
            "version": 1, "workspace_id": WORKSPACE.hex(),
        }).encode()))
        if current["time_valid"]:
            grant_id = current["grant_id"]
            grant_generation = current["grant_generation"]
        else:
            policy = expect(200, admin("GetPolicy", b'{"version":1}'))
            grant_generation = str(int(current["grant_generation"]) + 1)
            signed, grant_id = credential(
                fixture["root"], generation=int(grant_generation),
                authority_generation=int(policy["generation"]),
                paths=tuple("/".join(path) for path in paths),
            )
            expect(200, admin("RegisterGrant", json.dumps({
                "version": 1,
                "expected_grant_generation": current["grant_generation"],
                "grant": signed,
            }, separators=(",", ":")).encode()))
    else:
        signed, grant_id = credential(fixture["root"], paths=tuple("/".join(p) for p in paths))
        expect(200, admin("RegisterGrant", json.dumps({
            "version": 1, "expected_grant_generation": "0", "grant": signed,
        }, separators=(",", ":")).encode()))
        grant_generation = "1"
    request = {"version": 1, "workspace_id": WORKSPACE.hex(), "grant_id": grant_id,
               "grant_generation": grant_generation, "expected_ref": REF,
               "expected_base": fixture["root"], "paths": paths}
    state_path = Path(os.environ["MKIT_C2_TEST_STATE"])
    dbs = list(state_path.glob("v3/do/mkit-vcs-managed-local-test-RefStore/[0-9a-f]*.sqlite"))
    assert len(dbs) == 1
    with sqlite3.connect(dbs[0]) as db:
        before = db.execute("SELECT COUNT(*) FROM c2_test_reads").fetchone()[0] if db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='c2_test_reads'").fetchone() else 0
    result = post(request)
    assert result[0] == fixture["expected_status"], result
    if result[0] == 200:
        assert result[4].startswith(b"MKWB")
        assert len(result[4]) <= 4 * 1024 * 1024
    else:
        assert result[1] == {"code": fixture["expected_code"]}
        assert not result[4].startswith(b"MKWB")
    with sqlite3.connect(dbs[0]) as db:
        reads = [row[0] for row in db.execute(
            "SELECT object_id FROM c2_test_reads WHERE seq>? ORDER BY seq", (before,))]
    if result[0] == 200:
        assert len(reads) == len(fixture["required_read_ids"]), reads
        assert set(reads) == set(fixture["required_read_ids"]), reads
    else:
        assert set(reads).issubset(set(fixture["required_read_ids"])), reads
        if fixture["mode"] == "wide_over":
            tree = next(obj["id"] for obj in fixture["objects"] if obj["type"] == "Tree")
            assert tree not in reads, "known oversized witness fetched before refusal"
            assert reads == [fixture["root"]], reads
        if fixture["mode"] == "nested_witness_over":
            trees = [obj for obj in fixture["objects"] if obj["type"] == "Tree"]
            assert len(trees) == 2
            parent = min(trees, key=lambda obj: obj["canonical_bytes"])["id"]
            child = max(trees, key=lambda obj: obj["canonical_bytes"])["id"]
            assert reads == [fixture["root"], parent], reads
            assert child not in reads, "aggregate overflowing witness fetched before refusal"
    print("actual workerd resource", fixture["mode"], "status", result[0],
          "MKWB bytes", len(result[4]) if result[0] == 200 else 0,
          "R2 ranges", len(reads), "enrollment attempts", state["progress"]["attempts"])


if __name__ == "__main__":
    main()
