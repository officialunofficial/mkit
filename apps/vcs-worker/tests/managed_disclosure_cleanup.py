"""Disposable local-state test of read-after-ready-summary cleanup.

Run `--age STATE` only with Wrangler stopped; it ages one test job while
recomputing its private row checksum. Restart Wrangler on STATE, then run
`--cleanup STATE FIXTURE` to invoke the real owner cleanup route and read C2.
No production store is a valid target for this fault setup.
"""
import json
import sqlite3
import sys
from pathlib import Path

import blake3


JOB_ID = "1" * 64


def database(state):
    dbs = list(Path(state).glob("v3/do/mkit-vcs-managed-local-test-RefStore/[0-9a-f]*.sqlite"))
    assert len(dbs) == 1, dbs
    return dbs[0]


def age(state):
    assert "/tmp/mkit-c2-" in str(Path(state).resolve()), "only the disposable C2 fixture"
    with sqlite3.connect(database(state)) as db:
        row = db.execute("SELECT state,document FROM host_snapshot_jobs WHERE job_id=?",
                         (JOB_ID,)).fetchone()
        assert row and row[0] == "ready", row
        document = json.loads(row[1])
        document["terminal_deadline"] = 1
        encoded = json.dumps(document, separators=(",", ":"))
        checksum = blake3.blake3(b"mkit.host.snapshot.job.v1\0" + encoded.encode()).hexdigest()
        db.execute("UPDATE host_snapshot_jobs SET terminal_deadline=1,document=?,checksum=? WHERE job_id=?",
                   (encoded, checksum, JOB_ID))
    print("aged disposable ready summary; restart Wrangler before cleanup")


def cleanup(state, fixture_dir):
    from managed_disclosure import WORKSPACE, REF, admin, credential, expect, post
    fixture = json.loads((Path(fixture_dir) / "manifest.json").read_bytes())
    revision = "0"
    total = 0
    for _ in range(256):
        reply = expect(200, admin("CleanupSnapshots", json.dumps({
            "version": 1, "expected_cleanup_revision": revision, "max_rows": 64,
        }, separators=(",", ":")).encode()))
        revision = reply["cleanup_revision"]
        total += int(reply["affected_rows"])
        if not reply["has_more"]:
            break
    else:
        raise AssertionError("cleanup did not terminate")
    with sqlite3.connect(database(state)) as db:
        assert db.execute("SELECT COUNT(*) FROM host_snapshot_jobs WHERE job_id=?", (JOB_ID,)).fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM host_snapshot_seen WHERE job_id=?", (JOB_ID,)).fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM host_snapshot_catalog WHERE job_id=?", (JOB_ID,)).fetchone()[0] > 0
        assert db.execute("SELECT COUNT(*) FROM host_snapshot_indexes WHERE job_id=?", (JOB_ID,)).fetchone()[0] == 1
    current = expect(200, admin("GetGrant", json.dumps({
        "version": 1, "workspace_id": WORKSPACE.hex(),
    }).encode()))
    generation = int(current["grant_generation"]) + 1
    signed, grant_id = credential(fixture["root"], generation=generation)
    expect(200, admin("RegisterGrant", json.dumps({
        "version": 1, "expected_grant_generation": str(generation - 1), "grant": signed,
    }, separators=(",", ":")).encode()))
    request = {"version": 1, "workspace_id": WORKSPACE.hex(), "grant_id": grant_id,
               "grant_generation": str(generation), "expected_ref": REF,
               "expected_base": fixture["root"], "paths": [["file0000"]]}
    result = post(request)
    assert result[0] == 200 and result[4].startswith(b"MKWB"), result
    print("real owner cleanup removed ready job/seen, preserved catalog/index; C2 returned",
          len(result[4]), "bytes after", total, "cleanup rows")


if __name__ == "__main__":
    if sys.argv[1] == "--age":
        age(sys.argv[2])
    else:
        cleanup(sys.argv[2], sys.argv[3])
