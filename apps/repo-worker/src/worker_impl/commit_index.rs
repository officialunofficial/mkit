// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Commit-log index — the denormalized `commits` table colocated in the RefStore
// DO's SQLite. One row per commit/remix (keyed by hash, with the first `parent`
// for the chain walk plus the fields the lobby renders), so `ListCommits` is
// served from this table instead of a per-read R2 walk. Populated on each ref
// update (dual-write) and backfilled from R2 on demand.
//
// This is pure data-access over the DO's SQL handle: the RefStore owns ref
// resolution and the HTTP envelope and calls these functions with a head + a
// `&SqlStorage`.

use std::collections::HashSet;

use worker::{Result, SqlStorage};

use super::wire::{CommitMetaWire, CommitRowWire, ListCommitsResp};

/// Idempotently create the `commits` index. `CREATE TABLE IF NOT EXISTS` is
/// cheap to repeat, so this runs at the top of each commit-index op (a transient
/// DDL failure surfaces as a clean error instead of panicking the isolate).
pub(super) fn ensure_table(sql: &SqlStorage) -> Result<()> {
    sql.exec(
        "CREATE TABLE IF NOT EXISTS commits (\
           hash TEXT PRIMARY KEY, \
           ref TEXT NOT NULL, \
           parent TEXT NOT NULL, \
           signer TEXT NOT NULL, \
           message TEXT NOT NULL, \
           timestamp INTEGER NOT NULL, \
           kind TEXT NOT NULL, \
           sources TEXT NOT NULL);",
        None,
    )?;
    Ok(())
}

/// Insert one row. Idempotent (`OR IGNORE`) — the object is immutable, so a
/// re-push or backfill of the same hash is a no-op.
#[allow(clippy::too_many_arguments)]
fn insert(
    sql: &SqlStorage,
    hash: &str,
    ref_name: &str,
    parent: &str,
    signer: &str,
    message: &str,
    timestamp: i64,
    kind: &str,
    sources: &str,
) -> Result<()> {
    sql.exec(
        "INSERT OR IGNORE INTO commits \
           (hash, ref, parent, signer, message, timestamp, kind, sources) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
        vec![
            hash.into(),
            ref_name.into(),
            parent.into(),
            signer.into(),
            message.into(),
            timestamp.into(),
            kind.into(),
            sources.into(),
        ],
    )?;
    Ok(())
}

/// Record a commit from the on-write metadata (the `UpdateRef` dual-write).
pub(super) fn record(
    sql: &SqlStorage,
    hash: &str,
    ref_name: &str,
    m: &CommitMetaWire,
) -> Result<()> {
    insert(
        sql,
        hash,
        ref_name,
        &m.parent,
        &m.signer,
        &m.message,
        m.timestamp,
        &m.kind,
        &m.sources,
    )
}

/// Backfill rows the worker decoded from R2 (pre-index history). Returns how
/// many inserts succeeded.
pub(super) fn record_batch(sql: &SqlStorage, ref_name: &str, commits: &[CommitRowWire]) -> u32 {
    let mut recorded = 0u32;
    for c in commits {
        if insert(
            sql,
            &c.hash,
            ref_name,
            &c.parent,
            &c.signer,
            &c.message,
            c.timestamp,
            &c.kind,
            &c.sources,
        )
        .is_ok()
        {
            recorded += 1;
        }
    }
    recorded
}

/// Walk the index from `head` by first-parent, returning a bounded page entirely
/// from colocated SQLite — no R2. `complete=false` if it reaches a hash that
/// isn't indexed yet (pre-index history), so the caller can finish + backfill.
pub(super) fn walk(sql: &SqlStorage, head: String, cap: usize) -> ListCommitsResp {
    #[derive(serde::Deserialize)]
    struct Row {
        hash: String,
        parent: String,
        signer: String,
        message: String,
        timestamp: i64,
        kind: String,
        sources: String,
    }
    let mut commits: Vec<CommitRowWire> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut current = head;
    let mut next_cursor = String::new();
    let mut complete = true;
    loop {
        if commits.len() >= cap {
            next_cursor = current;
            break;
        }
        if !seen.insert(current.clone()) {
            break; // cycle guard
        }
        let found: Vec<Row> = sql
            .exec(
                "SELECT hash, parent, signer, message, timestamp, kind, sources \
                 FROM commits WHERE hash = ? LIMIT 1;",
                vec![current.clone().into()],
            )
            .and_then(|r| r.to_array())
            .unwrap_or_default();
        let Some(row) = found.into_iter().next() else {
            complete = false; // not indexed → caller completes from R2
            break;
        };
        let parent = row.parent.clone();
        commits.push(CommitRowWire {
            hash: row.hash,
            parent: row.parent,
            signer: row.signer,
            message: row.message,
            timestamp: row.timestamp,
            kind: row.kind,
            sources: row.sources,
        });
        if parent.is_empty() {
            break; // root
        }
        current = parent;
    }
    ListCommitsResp { commits, next_cursor, complete }
}
