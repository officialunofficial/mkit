"""Seed isolated test SQLite offline, then verify managed ListRefs bounds in workerd.

Usage: stop Wrangler; python3 tests/managed_listing.py --seed <persist-to>;
restart Wrangler on that same state; python3 tests/managed_listing.py --verify.
"""
import sqlite3
import gzip
import sys
from pathlib import Path

import managed_data as m


def seed(root):
    database = next(path for path in Path(root).glob("v3/do/mkit-vcs-managed-local-test-RefStore/*.sqlite") if path.name != "metadata.sqlite")
    rows = []
    for index in range(256):
        rows.append((f"refs/heads/count-exact/{index:03d}", "11" * 32))
    for index in range(257):
        rows.append((f"refs/heads/count-over/{index:03d}", "22" * 32))
    for index in range(100):
        rows.append((f"refs/heads/bytes-over/{index:03d}-" + "x" * 700, "33" * 32))
    with sqlite3.connect(database) as db:
        db.executemany("INSERT OR REPLACE INTO refs(path,value) VALUES (?,?)", rows)
    print("seeded", len(rows), "test refs")


def verify():
    for prefix, expected in [
        ("refs/heads/count-exact/", "ok"),
        ("refs/heads/count-over/", "resource_exhausted"),
        ("refs/heads/bytes-over/", "resource_exhausted"),
    ]:
        response = m.rpc("ListRefs", m.field(1, prefix), m.OWNER)
        actual = m.code(*response[:2])
        assert actual == expected, (prefix, response[:2])
        if expected == "ok":
            body = response[1]
            for _ in range(3):
                if not body.startswith(b"\x1f\x8b"):
                    break
                body = gzip.decompress(body)
            assert len(body) > 256 * 32
        print(prefix, actual)
    long_prefix = "refs/heads/" + "z" * 1025
    result = m.rpc("ListRefs", m.field(1, long_prefix), m.OWNER)
    assert m.code(*result[:2]) == "resource_exhausted", result[:2]


if __name__ == "__main__":
    if sys.argv[1] == "--seed":
        seed(sys.argv[2])
    elif sys.argv[1] == "--verify":
        verify()
    else:
        raise SystemExit("expected --seed <state> or --verify")
