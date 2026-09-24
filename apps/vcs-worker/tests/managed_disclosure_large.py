"""Actual workerd selected read from a >128 MiB distinct-reachable Snapshot.

Run after managed_snapshots.py --large in the same disposable Wrangler state,
with MKIT_C2_TEST_STATE pointing at that state and a test-faults worker build.
"""
import json
import os
import sqlite3
import sys
from pathlib import Path

from managed_disclosure import WORKSPACE, REF, admin, credential, expect, post


def main(directory):
    fixture = json.loads((directory / "manifest.json").read_bytes())
    assert fixture["unique_canonical_bytes"] > 128 * 1024 * 1024
    signed, grant_id = credential(fixture["root"], paths=("selected.txt",))
    registered = expect(200, admin("RegisterGrant", json.dumps({
        "version": 1, "expected_grant_generation": "0", "grant": signed,
    }, separators=(",", ":")).encode()))
    assert registered["grant_id"] == grant_id
    dbs = list(Path(os.environ["MKIT_C2_TEST_STATE"]).glob(
        "v3/do/mkit-vcs-managed-local-test-RefStore/[0-9a-f]*.sqlite"))
    assert len(dbs) == 1, dbs
    with sqlite3.connect(dbs[0]) as db:
        before = db.execute("SELECT COUNT(*) FROM c2_test_reads").fetchone()[0] if db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='c2_test_reads'").fetchone() else 0
    request = {"version": 1, "workspace_id": WORKSPACE.hex(), "grant_id": grant_id,
               "grant_generation": "1", "expected_ref": REF,
               "expected_base": fixture["root"], "paths": [["selected.txt"]]}
    result = post(request)
    assert result[0] == 200 and result[4].startswith(b"MKWB"), result
    assert len(result[4]) <= 4 * 1024 * 1024
    assert post({**request, "paths": [["file0000"]]})[0] == 403
    with sqlite3.connect(dbs[0]) as db:
        reads = db.execute(
            "SELECT object_id,pack_key FROM c2_test_reads WHERE seq>? ORDER BY seq",
            (before,)).fetchall()
    assert len(reads) == 3, reads  # root commit, one Tree, selected Blob
    hidden_pack_keys = {path.stem for path in directory.glob("*.pack")
                        if path.stat().st_size > 1024 * 1024}
    assert all(pack_key not in hidden_pack_keys for _, pack_key in reads), reads
    print("actual workerd >128 MiB base selected disclosure", len(result[4]),
          "R2 ranges", len(reads), "all from the small root pack")


if __name__ == "__main__":
    main(Path(sys.argv[-1]))
