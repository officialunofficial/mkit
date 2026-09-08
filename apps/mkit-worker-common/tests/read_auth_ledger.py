"""Read a local workerd ledger without changing its database or journal mode."""
import json
from pathlib import Path
import sqlite3
import sys

storage, author = sys.argv[1:]
matches = []
for database in Path(storage).rglob("*.sqlite"):
    with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"write_quota", "authenticated_operations"} <= tables:
            continue
        quota = connection.execute("SELECT ops, bytes FROM write_quota WHERE author=?", (author,)).fetchone()
        if quota is None:
            continue
        matches.append({
            "database": str(database),
            "operations": connection.execute("SELECT COUNT(*) FROM authenticated_operations").fetchone()[0],
            "quotaOps": quota[0],
            "quotaBytes": quota[1],
            "lastReaction": (connection.execute("SELECT last_ms FROM react_rate WHERE author=?", (author,)).fetchone() or (None,))[0] if "react_rate" in tables else None,
            "messages": connection.execute("SELECT COUNT(*) FROM messages WHERE author=?", (author,)).fetchone()[0] if "messages" in tables else 0,
            "reactions": connection.execute("SELECT COUNT(*) FROM reactions WHERE author=?", (author,)).fetchone()[0] if "reactions" in tables else 0,
        })
assert len(matches) == 1, f"expected one local ledger for author, found {len(matches)}"
print(json.dumps(matches[0]))
