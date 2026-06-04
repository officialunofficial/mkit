//! Recovery log — durable record of commits superseded by
//! history-rewriting operations (`commit --amend`, `reset`, `rebase`),
//! so they (a) remain GC roots within a retention window and (b) can be
//! surfaced and restored. This is Part 2 of #260, the recovery half of
//! the gc model (Part 1 added the reachability root set in
//! [`super::gc`]).
//!
//! Why this exists: the per-branch history journal stores only opaque
//! MMR digests, so a superseded tip is otherwise unrecoverable the moment
//! it leaves the ref set — and `mkit gc` (#233) would reclaim it. Each
//! rewrite appends the old tip here; gc treats every logged hash as a
//! root (clock-free), and [`expire`] drops entries older than the
//! retention policy so they stop pinning objects.
//!
//! On-disk: `.mkit/recovery-log`, append-only, one tab-delimited record
//! per line — `<unix_ts>\t<op>\t<64-hex superseded>\t<branch>`. The
//! branch is last because ref names cannot contain tabs or spaces; `op`
//! is a short internal token. Parsing is **strict** (fail closed) so a
//! corrupt log makes gc abort rather than under-count roots.
//!
//! NOTE: the *producers* (recording at the amend/reset/rebase rewrite
//! sites) are Part 2b — this module is the format, store, retention
//! policy, and gc-root integration.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::Path;

use crate::atomic::write_atomic;
use crate::hash::{self, Hash};

/// File name under `.mkit/` for the append-only recovery log.
pub const RECOVERY_LOG: &str = "recovery-log";

/// Default retention: keep entries from the last 90 days, and always the
/// most recent 50 regardless of age, so a recent mistake is recoverable
/// even on a long-idle repo.
pub const DEFAULT_GRACE_SECS: u64 = 90 * 24 * 60 * 60;
/// Default floor on retained entries regardless of age.
pub const DEFAULT_KEEP_LAST: usize = 50;

/// Errors from the recovery log.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("malformed object id in recovery log: {0}")]
    BadHash(#[from] hash::FromHexError),
    #[error("malformed recovery-log line: {0}")]
    Malformed(String),
    #[error("recovery-log field {0} may not contain a tab or newline")]
    InvalidField(&'static str),
}

type Result<T> = std::result::Result<T, RecoveryError>;

/// One superseded-commit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryEntry {
    /// Unix seconds when the rewrite happened.
    pub timestamp: u64,
    /// Short operation token, e.g. `amend`, `reset`, `rebase`.
    pub op: String,
    /// The commit that was superseded (and would otherwise dangle).
    pub superseded: Hash,
    /// Branch the rewrite moved (empty for a detached HEAD).
    pub branch: String,
}

/// Retention policy for [`expire`]. An entry is kept if it is newer than
/// `grace_secs` **or** among the most recent `keep_last`.
#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicy {
    pub grace_secs: u64,
    pub keep_last: usize,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            grace_secs: DEFAULT_GRACE_SECS,
            keep_last: DEFAULT_KEEP_LAST,
        }
    }
}

/// Append `entry` to the recovery log, creating it if absent. The
/// zero-hash is rejected (nothing to recover).
///
/// # Errors
/// [`RecoveryError::InvalidField`] if `op`/`branch` contain a tab or
/// newline; [`RecoveryError::Io`] on filesystem failure.
pub fn record(mkit_dir: &Path, entry: &RecoveryEntry) -> Result<()> {
    if entry.op.contains(['\t', '\n']) {
        return Err(RecoveryError::InvalidField("op"));
    }
    if entry.branch.contains(['\t', '\n']) {
        return Err(RecoveryError::InvalidField("branch"));
    }
    if entry.superseded == hash::ZERO {
        return Ok(());
    }
    fs::create_dir_all(mkit_dir)?;
    let line = format!(
        "{}\t{}\t{}\t{}\n",
        entry.timestamp,
        entry.op,
        hash::to_hex(&entry.superseded),
        entry.branch,
    );
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(mkit_dir.join(RECOVERY_LOG))?;
    f.write_all(line.as_bytes())?;
    Ok(())
}

/// Read every recovery-log entry, oldest first. Absent log ⇒ empty.
///
/// # Errors
/// Strict: any unparseable line or bad hash errors (fail closed for gc).
pub fn read_all(mkit_dir: &Path) -> Result<Vec<RecoveryEntry>> {
    let raw = match fs::read_to_string(mkit_dir.join(RECOVERY_LOG)) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    raw.lines()
        .filter(|l| !l.is_empty())
        .map(parse_line)
        .collect()
}

/// The set of superseded-commit hashes currently in the log — gc roots,
/// clock-free. Call [`expire`] first to drop entries past the retention
/// policy before treating these as live.
///
/// # Errors
/// Propagates [`RecoveryError`] from a strict [`read_all`].
pub fn roots(mkit_dir: &Path) -> Result<BTreeSet<Hash>> {
    Ok(read_all(mkit_dir)?
        .into_iter()
        .map(|e| e.superseded)
        .filter(|h| *h != hash::ZERO)
        .collect())
}

/// Drop entries that are both older than `policy.grace_secs` (relative to
/// `now`, unix seconds) and not among the most recent `policy.keep_last`.
/// Rewrites the log atomically. Returns the number of entries pruned.
///
/// # Errors
/// [`RecoveryError`] on a strict read or filesystem failure.
pub fn expire(mkit_dir: &Path, now: u64, policy: &RetentionPolicy) -> Result<usize> {
    let all = read_all(mkit_dir)?;
    let total = all.len();
    if total == 0 {
        return Ok(0);
    }
    // Indices counted from the end are within `keep_last`.
    let keep_floor = total.saturating_sub(policy.keep_last);
    let kept: Vec<RecoveryEntry> = all
        .into_iter()
        .enumerate()
        .filter(|(i, e)| {
            let fresh = now.saturating_sub(e.timestamp) <= policy.grace_secs;
            fresh || *i >= keep_floor
        })
        .map(|(_, e)| e)
        .collect();
    let pruned = total - kept.len();
    if pruned == 0 {
        return Ok(0);
    }
    let mut buf = String::new();
    for e in &kept {
        let _ = writeln!(
            buf,
            "{}\t{}\t{}\t{}",
            e.timestamp,
            e.op,
            hash::to_hex(&e.superseded),
            e.branch
        );
    }
    write_atomic(&mkit_dir.join(RECOVERY_LOG), buf.as_bytes(), true)?;
    Ok(pruned)
}

fn parse_line(line: &str) -> Result<RecoveryEntry> {
    let mut it = line.splitn(4, '\t');
    let ts = it.next().ok_or_else(|| malformed(line))?;
    let op = it.next().ok_or_else(|| malformed(line))?;
    let hex = it.next().ok_or_else(|| malformed(line))?;
    let branch = it.next().ok_or_else(|| malformed(line))?;
    let timestamp = ts.parse::<u64>().map_err(|_| malformed(line))?;
    let superseded = hash::from_hex(hex)?;
    Ok(RecoveryEntry {
        timestamp,
        op: op.to_owned(),
        superseded,
        branch: branch.to_owned(),
    })
}

fn malformed(line: &str) -> RecoveryError {
    RecoveryError::Malformed(line.to_owned())
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn md() -> (TempDir, std::path::PathBuf) {
        let d = TempDir::new().unwrap();
        let md = d.path().join(crate::MKIT_DIR);
        fs::create_dir_all(&md).unwrap();
        (d, md)
    }

    fn h(byte: u8) -> Hash {
        [byte; 32]
    }

    fn entry(ts: u64, byte: u8) -> RecoveryEntry {
        RecoveryEntry {
            timestamp: ts,
            op: "amend".into(),
            superseded: h(byte),
            branch: "main".into(),
        }
    }

    #[test]
    fn record_then_read_roundtrips_in_order() {
        let (_d, md) = md();
        record(&md, &entry(100, 1)).unwrap();
        record(&md, &entry(200, 2)).unwrap();
        let all = read_all(&md).unwrap();
        assert_eq!(all, vec![entry(100, 1), entry(200, 2)]);
        assert_eq!(roots(&md).unwrap(), BTreeSet::from([h(1), h(2)]));
    }

    #[test]
    fn absent_log_is_empty_not_error() {
        let (_d, md) = md();
        assert!(read_all(&md).unwrap().is_empty());
        assert!(roots(&md).unwrap().is_empty());
    }

    #[test]
    fn record_rejects_tab_in_fields_and_skips_zero_hash() {
        let (_d, md) = md();
        let mut e = entry(1, 1);
        e.branch = "a\tb".into();
        assert!(matches!(
            record(&md, &e),
            Err(RecoveryError::InvalidField("branch"))
        ));
        // Zero hash is a no-op (nothing to recover), not an error.
        record(&md, &entry(1, 0)).unwrap();
        assert!(roots(&md).unwrap().is_empty());
    }

    #[test]
    fn read_fails_closed_on_corrupt_line() {
        let (_d, md) = md();
        fs::write(md.join(RECOVERY_LOG), "not-a-valid-line\n").unwrap();
        assert!(read_all(&md).is_err(), "corrupt log must fail closed");
    }

    #[test]
    fn expire_drops_old_entries_outside_keep_last() {
        let (_d, md) = md();
        // 3 entries; now=1000, grace=200 → fresh means ts>=800, so
        // ts=850/900 are fresh and ts=10 is old. keep_last=1 would also
        // retain the newest, but the old ts=10 entry is neither fresh nor
        // in the last-1, so it is pruned.
        record(&md, &entry(10, 1)).unwrap();
        record(&md, &entry(850, 2)).unwrap();
        record(&md, &entry(900, 3)).unwrap();
        let pruned = expire(
            &md,
            1000,
            &RetentionPolicy {
                grace_secs: 200,
                keep_last: 1,
            },
        )
        .unwrap();
        assert_eq!(pruned, 1, "the ts=10 entry is old and not in last-1");
        assert_eq!(roots(&md).unwrap(), BTreeSet::from([h(2), h(3)]));
    }

    #[test]
    fn expire_keep_last_retains_old_recent_entries() {
        let (_d, md) = md();
        record(&md, &entry(1, 1)).unwrap();
        record(&md, &entry(2, 2)).unwrap();
        // Everything is "old" vs now, but keep_last=5 retains all.
        let pruned = expire(
            &md,
            1_000_000,
            &RetentionPolicy {
                grace_secs: 0,
                keep_last: 5,
            },
        )
        .unwrap();
        assert_eq!(pruned, 0);
        assert_eq!(roots(&md).unwrap(), BTreeSet::from([h(1), h(2)]));
    }
}
