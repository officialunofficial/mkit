"""Disposable workerd read-lease exact/one-over capacity fixture.

Stop Wrangler before `--seed STATE 15|16`; it inserts expired but physical
private lease rows under the current certified index. Restart on the same
state and run `--probe STATE FIXTURE 200|429`. Never use a real repository.
"""
import json
import sqlite3
import sys
from pathlib import Path


def database(state):
    assert "/tmp/mkit-c2-" in str(Path(state).resolve()), "only disposable C2 fixture"
    dbs = list(Path(state).glob("v3/do/mkit-vcs-managed-local-test-RefStore/[0-9a-f]*.sqlite"))
    assert len(dbs) == 1, dbs
    return dbs[0]


def seed(state, total, global_rows=False):
    assert total in ((63, 64) if global_rows else (15, 16))
    with sqlite3.connect(database(state)) as db:
        row = db.execute("SELECT job_id,generation FROM host_snapshot_indexes WHERE retired=0").fetchone()
        assert row
        if global_rows:
            # A physical bookkeeping fixture, not an invented ready cert.
            row = ("f" * 64, "1")
        existing = db.execute("SELECT COUNT(*) FROM host_snapshot_leases").fetchone()[0]
        assert existing <= total
        for n in range(existing, total):
            db.execute("INSERT INTO host_snapshot_leases(lease_id,job_id,generation,deadline) VALUES(?,?,?,1)",
                       (format(n + 1, "064x"), row[0], row[1]))
    print("seeded", total, "expired", "global" if global_rows else "per-cert",
          "physical lease rows in disposable SQLite")


def probe(state, directory, expected):
    from managed_disclosure import WORKSPACE, REF, admin, expect, post
    fixture = json.loads((Path(directory) / "manifest.json").read_bytes())
    current = expect(200, admin("GetGrant", json.dumps({
        "version": 1, "workspace_id": WORKSPACE.hex(),
    }).encode()))
    request = {"version": 1, "workspace_id": WORKSPACE.hex(),
               "grant_id": current["grant_id"],
               "grant_generation": current["grant_generation"],
               "expected_ref": REF, "expected_base": fixture["root"],
               "paths": fixture["selected_paths"]}
    with sqlite3.connect(database(state)) as db:
        before = db.execute("SELECT COUNT(*) FROM host_snapshot_leases").fetchone()[0]
    result = post(request)
    assert result[0] == expected, result
    if expected == 200:
        assert result[4].startswith(b"MKWB")
    else:
        assert result[1] == {"code": "resource_exhausted"}
    with sqlite3.connect(database(state)) as db:
        assert db.execute("SELECT COUNT(*) FROM host_snapshot_leases").fetchone()[0] == before
    print("physical leases", before, "C2 status", expected, "no retained new lease")


def cleanup(state):
    from managed_disclosure import admin, expect
    with sqlite3.connect(database(state)) as db:
        meta = json.loads(db.execute("SELECT document FROM host_snapshot_meta WHERE slot=1").fetchone()[0])
    result = expect(200, admin("CleanupSnapshots", json.dumps({
        "version": 1, "expected_cleanup_revision": meta["cleanup_revision"],
        "max_rows": 64,
    }, separators=(",", ":")).encode()))
    assert int(result["affected_rows"]) >= 16, result
    with sqlite3.connect(database(state)) as db:
        assert db.execute("SELECT COUNT(*) FROM host_snapshot_leases").fetchone()[0] == 0
    print("owner cleanup recovered", result["affected_rows"], "expired physical leases")


def fault(state, kind):
    """Apply one fail-closed lease precondition fault while Wrangler is stopped."""
    with sqlite3.connect(database(state)) as db:
        if kind == "missing-cert":
            assert db.execute("SELECT COUNT(*) FROM host_snapshot_certificates").fetchone()[0] == 1
            db.execute("DELETE FROM host_snapshot_certificates")
        elif kind == "corrupt-schema":
            db.execute("DROP TABLE host_snapshot_indexes")
        else:
            raise AssertionError(kind)
    print("seeded disposable lease fault", kind)


def probe_fault(state, directory, expected, expected_code):
    from managed_disclosure import WORKSPACE, REF, admin, expect, post, credential
    fixture = json.loads((Path(directory) / "manifest.json").read_bytes())
    current = expect(200, admin("GetGrant", json.dumps({
        "version": 1, "workspace_id": WORKSPACE.hex(),
    }).encode()))
    if not current["time_valid"]:
        policy = expect(200, admin("GetPolicy", b'{"version":1}'))
        generation = int(current["grant_generation"]) + 1
        signed, grant_id = credential(
            fixture["root"], generation=generation,
            authority_generation=int(policy["generation"]),
            paths=tuple("/".join(path) for path in fixture["selected_paths"]),
        )
        expect(200, admin("RegisterGrant", json.dumps({
            "version": 1, "expected_grant_generation": current["grant_generation"],
            "grant": signed,
        }, separators=(",", ":")).encode()))
        current = {"grant_id": grant_id, "grant_generation": str(generation)}
    request = {"version": 1, "workspace_id": WORKSPACE.hex(),
               "grant_id": current["grant_id"],
               "grant_generation": current["grant_generation"],
               "expected_ref": REF, "expected_base": fixture["root"],
               "paths": fixture["selected_paths"]}
    with sqlite3.connect(database(state)) as db:
        before = db.execute("SELECT COUNT(*) FROM host_snapshot_leases").fetchone()[0]
    result = post(request)
    assert result[0] == expected and result[1] == {"code": expected_code}, result
    assert not result[4].startswith(b"MKWB")
    with sqlite3.connect(database(state)) as db:
        assert db.execute("SELECT COUNT(*) FROM host_snapshot_leases").fetchone()[0] == before
    print("lease fault", expected_code, "C2 status", expected, "no new lease")


if __name__ == "__main__":
    if sys.argv[1] == "--seed":
        seed(sys.argv[2], int(sys.argv[3]))
    elif sys.argv[1] == "--seed-global":
        seed(sys.argv[2], int(sys.argv[3]), global_rows=True)
    elif sys.argv[1] == "--cleanup":
        cleanup(sys.argv[2])
    elif sys.argv[1] == "--fault":
        fault(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "--probe-fault":
        probe_fault(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])
    else:
        probe(sys.argv[2], sys.argv[3], int(sys.argv[4]))
