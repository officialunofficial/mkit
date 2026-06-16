#!/usr/bin/env bash
# Local end-to-end check of the D1 contract: build the seed, load schema + seed
# into a throwaway SQLite DB, and run the exact queries the Worker issues. This
# exercises the FTS5 trigram/word tokenizers and bm25 ranking without Cloudflare.
# Requires `sqlite3` built with FTS5 (standard on macOS and most Linux).
set -euo pipefail

cd "$(dirname "$0")/.."
DB="$(mktemp -t mkit-mcp-itest.XXXXXX.db)"
trap 'rm -f "$DB"' EXIT

node scripts/build-index.mjs >/dev/null
sqlite3 "$DB" < migrations/0001_init.sql
sqlite3 "$DB" < dist/seed.sql

echo "counts (files|crates|commands|version):"
sqlite3 "$DB" "SELECT (SELECT count(*) FROM files), (SELECT count(*) FROM crates), (SELECT count(*) FROM commands), (SELECT version FROM versions);"

echo "search_code word 'dsse*' over .rs (bm25 top 3):"
sqlite3 "$DB" "SELECT f.path FROM files_fts_word JOIN files f ON files_fts_word.rowid=f.id WHERE files_fts_word MATCH 'dsse*' AND f.path LIKE '%.rs' ORDER BY bm25(files_fts_word) LIMIT 3;"

echo "get_command 'attest' summary:"
sqlite3 "$DB" "SELECT substr(summary,1,60) FROM commands WHERE name='attest';"

echo "OK"
