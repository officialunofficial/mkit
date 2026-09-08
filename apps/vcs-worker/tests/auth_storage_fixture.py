"""Prepare/verify a stopped local workerd SQLite fixture, never a deployed DB.

Usage: python3 tests/auth_storage_fixture.py prepare|verify /tmp/.../RefStore/<id>.sqlite
Restart workerd and run auth_v2.mjs --fault --corrupt-ref between the two steps.
"""
import sqlite3
import sys

mode, database = sys.argv[1:]
with sqlite3.connect(database) as connection:
    if mode == "prepare":
        connection.execute("INSERT OR REPLACE INTO refs(path,value) VALUES (?,?)", ("refs/heads/__corrupt", "not-a-hash"))
        connection.execute("INSERT OR REPLACE INTO write_quota(author,window_start,ops,bytes) VALUES (?,0,1,1)", ("__stale_auth_test",))
        connection.execute("INSERT OR REPLACE INTO authenticated_operations(scope,fingerprint,expires,reply) VALUES (?,?,1,NULL)", ("__expired_auth_test", "invalid-expired-fingerprint"))
    elif mode == "verify":
        assert connection.execute("SELECT value FROM refs WHERE path=?", ("refs/heads/__corrupt",)).fetchone() == ("not-a-hash",)
        assert connection.execute("SELECT COUNT(*) FROM write_quota WHERE author=?", ("__stale_auth_test",)).fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM authenticated_operations WHERE scope=?", ("__expired_auth_test",)).fetchone() == (0,)
        assert any(row[1] == "authenticated_operations_expires" for row in connection.execute("PRAGMA index_list(authenticated_operations)"))
        print("corrupt ref preserved; stale quota and expired nonce pruned; expiry index present")
    else:
        raise ValueError("expected prepare or verify")
