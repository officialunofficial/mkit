"""Prepare/verify a stopped local workerd SQLite fixture, never a deployed DB.

Usage: python3 tests/auth_storage_fixture.py prepare|verify <persist-dir>/v3/do/mkit-vcs-worker-RefStore/<id>.sqlite
Restart workerd and run auth_v2.mjs --fault --corrupt-ref between the two steps.

The RefStore object runs mkit-server's SqlKvStore: one `kv(part, key, value)`
table. The fixture stores an undecodable value under the ref
`refs/heads/__corrupt` of repository `default` in the deployment-default
namespace partition; the Worker must neither serve it as valid nor overwrite
it. (Replay-record and quota-window pruning, which the pre-port fixture also
seeded, is covered by the wire suite's `growth.replay_and_quota_pruned` case:
scripts/vcs-worker-conformance.sh --test-faults.)
"""
import sqlite3
import sys

PART = b"nroot\x00"  # Partition::Namespace(deployment default)
KEY = b"r\x00default\x00refs/heads/__corrupt"  # keys::ref_key
CORRUPT = b"not-a-hash"

mode, database = sys.argv[1:]
with sqlite3.connect(database) as connection:
    if mode == "prepare":
        connection.execute("INSERT OR REPLACE INTO kv(part,key,value) VALUES (?,?,?)", (PART, KEY, CORRUPT))
    elif mode == "verify":
        row = connection.execute("SELECT value FROM kv WHERE part=? AND key=?", (PART, KEY)).fetchone()
        assert row == (CORRUPT,), row
        print("corrupt ref preserved: not served as valid, not overwritten")
    else:
        raise ValueError("expected prepare or verify")
