//! The storage cap of a [`super::SqlKvStore`]: a hard size limit the engine
//! enforces, and a soft limit below it where batches that add data stop.
//!
//! **Why a reserve.** Deleting from a `WITHOUT ROWID` b-tree can *grow* it:
//! removing a cell from an interior page promotes a replacement divider,
//! which may be longer (keys run from 1 to
//! [`MAX_KEY_BYTES`](crate::store::MAX_KEY_BYTES) bytes) and split the page
//! and its ancestors. A store filled to its engine limit
//! (`SQLite` `max_page_count`, a Durable Object's 10 GB) can therefore
//! fail a delete with `SQLITE_FULL`, which breaks normative rule 7 (a
//! delete-only batch never returns `Full`, so pruning always runs). The
//! store keeps a reserve free: a batch with a put returns
//! [`StoreError::Full`](crate::StoreError::Full) once the bytes in use
//! reach `cap - reserve`, and delete-only batches are never refused.
//!
//! **The reserve formula.** One batch holds at most [`MAX_BATCH_OPS`]
//! operations. Each can split one page on every level of its path plus a
//! new root: `depth + 1` pages. `SQLite` keeps at least four cells on an
//! interior page (a longer cell overflows), so a depth of
//! [`RESERVE_TREE_DEPTH`] = 20 covers `4^20` pages, beyond any database.
//! A batch also writes at most [`MAX_BATCH_BYTES`] of payload; doubling it
//! covers overflow-page and cell overhead. So one batch grows the database
//! by at most [`batch_growth_bytes`]`(page) = (MAX_BATCH_OPS × 21 + 2 ×
//! MAX_BATCH_BYTES / page) × page`, 10.2 MiB at 4 KiB pages. The reserve
//! must hold two such batches: a put batch that starts just below the soft
//! limit, then a delete-only batch. [`reserve_floor`] is that, 20.4 MiB at
//! 4 KiB pages. The default reserve is the larger of that floor and 1/64
//! of the cap (160 MiB of a Durable Object's 10 GB), which also absorbs a
//! long run of prune batches and journal overhead the model ignores.
//! Pages freed by deletes go to the free list, and later splits reuse them
//! first, so pruning mostly consumes no new pages.

use crate::store::{MAX_BATCH_BYTES, MAX_BATCH_OPS};

/// The page size the default reserve assumes: `SQLite`'s default and a
/// Durable Object's. A database with larger pages sets its reserve with
/// [`Capacity::with_reserve`] and [`reserve_floor`].
pub const DEFAULT_PAGE_SIZE: u64 = 4096;

/// The b-tree depth the reserve plans for.
pub const RESERVE_TREE_DEPTH: u64 = 20;

/// The most one batch can grow a database with `page_size`-byte pages (see
/// the module docs).
#[must_use]
pub const fn batch_growth_bytes(page_size: u64) -> u64 {
    let split_pages = MAX_BATCH_OPS as u64 * (RESERVE_TREE_DEPTH + 1);
    let payload_pages = 2 * MAX_BATCH_BYTES as u64 / page_size;
    (split_pages + payload_pages) * page_size
}

/// The smallest safe reserve: two batches' growth (a put batch that starts
/// just below the soft limit, then a delete-only batch).
#[must_use]
pub const fn reserve_floor(page_size: u64) -> u64 {
    2 * batch_growth_bytes(page_size)
}

/// A store's size cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacity {
    cap_bytes: u64,
    reserve_bytes: u64,
}

impl Capacity {
    /// A hard cap of `cap_bytes` (the engine limit: natively applied as
    /// `max_page_count`, on a Durable Object its fixed 10 GB) with the
    /// default reserve, `max(reserve_floor(4096), cap_bytes / 64)`.
    #[must_use]
    pub const fn new(cap_bytes: u64) -> Self {
        let floor = reserve_floor(DEFAULT_PAGE_SIZE);
        let fraction = cap_bytes / 64;
        Self {
            cap_bytes,
            reserve_bytes: if fraction > floor { fraction } else { floor },
        }
    }

    /// Keep `reserve_bytes` free instead of the default. Below
    /// [`reserve_floor`] a delete may fail at the engine limit.
    #[must_use]
    pub const fn with_reserve(mut self, reserve_bytes: u64) -> Self {
        self.reserve_bytes = reserve_bytes;
        self
    }

    /// The hard cap.
    #[must_use]
    pub const fn cap_bytes(&self) -> u64 {
        self.cap_bytes
    }

    /// The reserve kept free below the hard cap.
    #[must_use]
    pub const fn reserve_bytes(&self) -> u64 {
        self.reserve_bytes
    }

    /// Where batches with a put start returning `Full`: `cap - reserve`.
    #[must_use]
    pub const fn soft_limit(&self) -> u64 {
        self.cap_bytes.saturating_sub(self.reserve_bytes)
    }
}
