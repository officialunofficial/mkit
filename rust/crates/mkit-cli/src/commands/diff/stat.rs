//! `diff --stat` rendering: git-compatible per-file rows, the `N files
//! changed` summary, and the +/- graph, sized to the terminal.
//!
//! One [`LoadedBlob`] load per diff side supplies the text-vs-binary sniff,
//! byte sizes, and line counts (#624); rendering reads display-only, without
//! per-read hash verification (#625). Extracted from `commands/diff.rs`
//! (#633) after two consecutive PRs grew this cluster in place.

use std::io::Write;

use mkit_core::hash::Hash;
use mkit_core::ops::{BINARY_SNIFF_LEN, DiffEntry, DiffKind, diff_line_counts, is_binary};
use mkit_core::store::{DisplaySource, ObjectSource};
use mkit_core::worktree::LoadedBlob;

/// One row of `--stat` output: a display name plus its change shape.
struct StatRow {
    /// Display name — C-style quoted (git `core.quotePath`) when needed.
    name: String,
    change: StatChange,
}

enum StatChange {
    /// Text change: added / deleted line counts.
    Text { added: usize, deleted: usize },
    /// Binary change: old / new byte sizes (rendered as `Bin … bytes`).
    /// `u64` (not `usize`) because a chunked blob's size comes straight
    /// from its manifest's `total_size`, with no reassembled `Vec` to take
    /// a `usize` length from.
    Binary { old_len: u64, new_len: u64 },
}

/// Classify one changed entry's shape for `--stat`: text (line counts) or
/// binary (byte sizes).
///
/// Each side's top-level object is loaded exactly once (as a
/// [`LoadedBlob`]); the sniff prefix, the binary byte sizes, and the text
/// content all derive from that single load. The sniff reads a bounded
/// prefix — never a full reassembly of a chunked blob — and classifies
/// text vs binary exactly as `diff_line_counts` would (same
/// NUL-in-first-8000 heuristic; a prefix classifies identically to the
/// full blob, since the heuristic never looks further anyway). A binary
/// entry's sizes come from blob metadata (a chunked blob's manifest
/// `total_size`, or an inline blob's length) with no further read at all;
/// full content is materialized only for a text entry that actually needs
/// line counts (#606).
fn entry_stat_change<S: ObjectSource + ?Sized>(
    store: &S,
    e: &DiffEntry,
) -> Result<StatChange, String> {
    if e.kind == DiffKind::ModeChanged {
        // Pure mode flip — no content delta. git shows `| 0`.
        return Ok(StatChange::Text {
            added: 0,
            deleted: 0,
        });
    }
    let old = load_blob(store, e.old_hash)?;
    let new = load_blob(store, e.new_hash)?;
    let sniffs_binary = {
        let old_prefix = old
            .prefix(store, BINARY_SNIFF_LEN)
            .map_err(super::read_err)?;
        let new_prefix = new
            .prefix(store, BINARY_SNIFF_LEN)
            .map_err(super::read_err)?;
        is_binary(&old_prefix) || is_binary(&new_prefix)
    };
    if sniffs_binary {
        return Ok(StatChange::Binary {
            old_len: old.len(),
            new_len: new.len(),
        });
    }
    let old_bytes = old.into_content(store).map_err(super::read_err)?;
    let new_bytes = new.into_content(store).map_err(super::read_err)?;
    Ok(match diff_line_counts(&old_bytes, &new_bytes) {
        Some((added, deleted)) => StatChange::Text { added, deleted },
        // Unreachable in practice (the prefix sniff already agreed both
        // sides are text), but fall back to sizes rather than unwrap so a
        // future divergence degrades safely instead of panicking.
        None => StatChange::Binary {
            old_len: old_bytes.len() as u64,
            new_len: new_bytes.len() as u64,
        },
    })
}

/// Render `git diff --stat`-compatible output: one `<name> | <count>
/// <graph>` row per changed file, then a `N files changed, …` summary.
///
/// Layout matches git: the name column is padded to the longest display
/// name, the count column is right-aligned to the widest total, and the
/// `+`/`-` graph is scaled to the terminal width when the largest change
/// would overflow it. Width = `COLUMNS` (if a positive integer) else 80,
/// exactly as git does even when stdout is not a tty.
///
/// A diffstat is display-only by definition — every row is a byte size or
/// a line count a human reads and discards — so this reads every changed
/// blob without BLAKE3 re-verification via [`DisplaySource`] (#625).
/// Callers pass their source directly; the no-verify choice lives here,
/// not at each call site.
pub(in crate::commands) fn render_stat<'a, S: ObjectSource + ?Sized>(
    out: &mut impl Write,
    store: &S,
    entries: impl Iterator<Item = &'a DiffEntry>,
) -> Result<(), String> {
    let store = &DisplaySource::new(store);
    // Gather per-file change shapes (and the blob bytes we need to count).
    let mut rows: Vec<StatRow> = Vec::new();
    for e in entries {
        let name = super::c_quote_name(&e.path);
        let change = entry_stat_change(store, e)?;
        rows.push(StatRow { name, change });
    }
    if rows.is_empty() {
        return Ok(());
    }

    // Column metrics. `max_change` and the count-column width come from
    // text rows only (binary rows render `Bin …`, not a number).
    let name_width = rows
        .iter()
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(0);
    let max_change = rows
        .iter()
        .filter_map(|r| match r.change {
            StatChange::Text { added, deleted } => Some(added + deleted),
            StatChange::Binary { .. } => None,
        })
        .max()
        .unwrap_or(0);
    let number_width = decimal_width(max_change);

    // Graph width: COLUMNS (or 80) minus the fixed framing (leading space,
    // " | ", the count column, and the space before the graph) — the
    // reservation git uses, derived empirically as `name + number + 6`.
    let total_width = terminal_columns();
    let graph_width = total_width
        .saturating_sub(name_width)
        .saturating_sub(number_width)
        .saturating_sub(6)
        .max(1);
    // git scales the graph only when the largest change can't fit.
    let scaled = max_change > graph_width;

    for r in &rows {
        match r.change {
            StatChange::Text { added, deleted } => {
                let total = added + deleted;
                let graph = stat_graph(added, deleted, graph_width, max_change, scaled);
                // git emits `| 0` with no trailing space/graph for a
                // zero-change row (empty-file add, mode-only); the graph
                // (and its leading space) appear only when there is one.
                if graph.is_empty() {
                    writeln!(
                        out,
                        " {name:<name_width$} | {total:>number_width$}",
                        name = r.name
                    )
                } else {
                    writeln!(
                        out,
                        " {name:<name_width$} | {total:>number_width$} {graph}",
                        name = r.name,
                    )
                }
                .map_err(|e| format!("write: {e}"))?;
            }
            StatChange::Binary { old_len, new_len } => {
                writeln!(
                    out,
                    " {name:<name_width$} | Bin {old_len} -> {new_len} bytes",
                    name = r.name,
                )
                .map_err(|e| format!("write: {e}"))?;
            }
        }
    }

    writeln!(out, "{}", stat_summary(&rows)).map_err(|e| format!("write: {e}"))?;
    Ok(())
}

/// The ` N files changed[, I insertions(+)][, D deletions(-)]` summary
/// line, matching git's `print_stat_summary`. git's clause rule: show
/// insertions when `ins != 0 || del == 0`, and deletions when
/// `del != 0 || ins == 0`. So a one-sided change shows only its side
/// (`1 file changed, 1 insertion(+)`), while a zero-change diff (mode-only,
/// binary-only, empty-file add) shows BOTH `0 insertions(+), 0
/// deletions(-)`. Pluralization is git's (`insertion`/`insertions`).
fn stat_summary(rows: &[StatRow]) -> String {
    use std::fmt::Write as _;
    let (mut ins, mut del) = (0usize, 0usize);
    for r in rows {
        if let StatChange::Text { added, deleted } = r.change {
            ins += added;
            del += deleted;
        }
    }
    let mut summary = format!(
        " {} {} changed",
        rows.len(),
        if rows.len() == 1 { "file" } else { "files" }
    );
    if ins != 0 || del == 0 {
        let _ = write!(
            summary,
            ", {ins} insertion{}(+)",
            if ins == 1 { "" } else { "s" }
        );
    }
    if del != 0 || ins == 0 {
        let _ = write!(
            summary,
            ", {del} deletion{}(-)",
            if del == 1 { "" } else { "s" }
        );
    }
    summary
}

/// The `+`/`-` graph for one file. Unscaled: literal `added` `+` then
/// `deleted` `-`. Scaled (git's algorithm): scale the total to the graph
/// width via [`scale_linear`], then split it across `+`/`-`.
fn stat_graph(
    added: usize,
    deleted: usize,
    graph_width: usize,
    max_change: usize,
    scaled: bool,
) -> String {
    let (plus, minus) = if scaled {
        let mut total = scale_linear(added + deleted, graph_width, max_change);
        if total < 2 && added > 0 && deleted > 0 {
            total = 2;
        }
        if added < deleted {
            let a = scale_linear(added, graph_width, max_change);
            (a, total - a)
        } else {
            let d = scale_linear(deleted, graph_width, max_change);
            (total - d, d)
        }
    } else {
        (added, deleted)
    };
    let mut g = "+".repeat(plus);
    g.push_str(&"-".repeat(minus));
    g
}

/// git's diffstat scaling: map `it` changes onto `width` columns. Returns
/// 0 for no change, else at least 1 (so any change shows at least one
/// mark) — `1 + it*(width-1)/max_change`, integer arithmetic, matching
/// git's `scale_linear`.
fn scale_linear(it: usize, width: usize, max_change: usize) -> usize {
    if it == 0 {
        return 0;
    }
    1 + it * (width - 1) / max_change
}

/// Number of decimal digits needed to print `n` (at least 1, for `0`).
fn decimal_width(n: usize) -> usize {
    let mut w = 1;
    let mut v = n;
    while v >= 10 {
        v /= 10;
        w += 1;
    }
    w
}

/// Graph width source: `COLUMNS` when it parses to a positive integer,
/// else git's piped default of 80.
fn terminal_columns() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.trim().parse::<usize>().ok())
        .filter(|&c| c > 0)
        .unwrap_or(80)
}

/// Load a diff side's top-level object once — every view `render_stat`
/// needs (sniff prefix, byte length, full content) derives from this
/// single read. A side with no hash (add/delete) is the empty blob (#624).
fn load_blob<S: ObjectSource + ?Sized>(store: &S, h: Option<Hash>) -> Result<LoadedBlob, String> {
    match h {
        Some(h) => LoadedBlob::load(store, &h).map_err(super::read_err),
        None => Ok(LoadedBlob::empty()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_width_counts_digits() {
        assert_eq!(decimal_width(0), 1);
        assert_eq!(decimal_width(9), 1);
        assert_eq!(decimal_width(10), 2);
        assert_eq!(decimal_width(201), 3);
    }

    #[test]
    fn scale_linear_matches_git_formula() {
        // it == 0 → 0; otherwise 1 + it*(width-1)/max_change.
        assert_eq!(scale_linear(0, 47, 201), 0);
        // The values verified against real git: a.txt total 13 → 3,
        // its single deletion → 1; the 201-change file fills the width.
        assert_eq!(scale_linear(13, 47, 201), 3);
        assert_eq!(scale_linear(1, 47, 201), 1);
        assert_eq!(scale_linear(201, 47, 201), 47);
    }

    #[test]
    fn stat_graph_unscaled_is_literal() {
        // When not scaling, the graph is `added` '+' then `deleted` '-'.
        assert_eq!(stat_graph(3, 0, 66, 4, false), "+++");
        assert_eq!(stat_graph(3, 1, 66, 4, false), "+++-");
        assert_eq!(stat_graph(0, 1, 66, 4, false), "-");
    }

    #[test]
    fn stat_graph_scaled_splits_like_git() {
        // a.txt: +12/-1 over graph_width 47, max_change 201 → "++-".
        assert_eq!(stat_graph(12, 1, 47, 201, true), "++-");
        // the max-change file fills the width: 46 '+' + 1 '-'.
        assert_eq!(
            stat_graph(200, 1, 47, 201, true),
            format!("{}-", "+".repeat(46))
        );
    }

    // -----------------------------------------------------------------
    // render_stat over chunked blobs (#606): binary sizing must come from
    // manifest metadata, never a full reassembly.
    // -----------------------------------------------------------------

    use mkit_core::object::{Blob, ChunkedBlob, Object};
    use mkit_core::store::{StoreError, StoreResult};
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// A fake [`ObjectSource`] for unit tests: objects are arbitrary bytes
    /// keyed by an arbitrary [`Hash`] (no content-hash re-verification,
    /// unlike the real store — fixtures are built directly). Records every
    /// hash passed to `read` so a test can assert exactly which objects
    /// `render_stat` touched — in particular, that a chunked blob's
    /// trailing chunks are never read just to size or classify it.
    #[derive(Default)]
    struct RecordingSource {
        objects: HashMap<Hash, Vec<u8>>,
        reads: RefCell<Vec<Hash>>,
    }

    impl RecordingSource {
        fn put(&mut self, h: Hash, obj: &Object) {
            self.objects
                .insert(h, mkit_core::serialize::serialize(obj).unwrap());
        }
    }

    impl ObjectSource for RecordingSource {
        fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
            self.reads.borrow_mut().push(*h);
            self.objects
                .get(h)
                .cloned()
                .ok_or_else(|| StoreError::ObjectNotFound(mkit_core::hash::to_hex(h)))
        }
    }

    /// Deterministic-enough fake hashes for test fixtures — content is
    /// never re-verified by [`RecordingSource`], so any distinct 32-byte
    /// pattern works as a key.
    fn fake_hash(tag: u8) -> Hash {
        [tag; 32]
    }

    /// A `len`-byte buffer of `fill`, with a NUL byte written at offset 10
    /// so it sniffs as binary — well within `BINARY_SNIFF_LEN`.
    fn binary_bytes(fill: u8, len: usize) -> Vec<u8> {
        let mut data = vec![fill; len];
        data[10] = 0;
        data
    }

    fn modified_entry(path: &str, old_hash: Hash, new_hash: Hash) -> DiffEntry {
        DiffEntry {
            path: path.to_string(),
            kind: DiffKind::Modified,
            old_hash: Some(old_hash),
            new_hash: Some(new_hash),
            old_mode: None,
            new_mode: None,
            old_path: None,
        }
    }

    #[test]
    fn render_stat_binary_chunked_blob_reads_no_trailing_chunks() {
        // Both sides are ChunkedBlob manifests whose first chunk alone
        // exceeds BINARY_SNIFF_LEN and is binary. Only the manifest and the
        // first chunk of each side are ever stored — if render_stat tried
        // to reassemble the full content (reading every chunk) it would
        // hit a missing object and this test would fail with an error
        // instead of exercising the reads-list assertion below.
        let mut store = RecordingSource::default();

        let old_chunk0 = fake_hash(1);
        let old_chunk1 = fake_hash(2); // deliberately never stored
        let old_manifest_hash = fake_hash(3);
        store.put(
            old_chunk0,
            &Object::Blob(Blob {
                data: binary_bytes(b'a', BINARY_SNIFF_LEN + 1000),
            }),
        );
        store.put(
            old_manifest_hash,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 3_000_000,
                chunk_size: 0,
                chunks: vec![old_chunk0, old_chunk1],
            }),
        );

        let new_chunk0 = fake_hash(4);
        let new_chunk1 = fake_hash(5); // deliberately never stored
        let new_manifest_hash = fake_hash(6);
        store.put(
            new_chunk0,
            &Object::Blob(Blob {
                data: binary_bytes(b'b', BINARY_SNIFF_LEN + 500),
            }),
        );
        store.put(
            new_manifest_hash,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 4_000_000,
                chunk_size: 0,
                chunks: vec![new_chunk0, new_chunk1],
            }),
        );

        let entry = modified_entry("big.bin", old_manifest_hash, new_manifest_hash);
        let mut out = Vec::new();
        render_stat(&mut out, &store, std::iter::once(&entry)).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("Bin 3000000 -> 4000000 bytes"),
            "sizes should come from manifest total_size: {rendered}"
        );

        let reads = store.reads.borrow();
        assert!(
            !reads.contains(&old_chunk1),
            "second chunk of the old side was read, but the sniff+size path \
             never needs it: {reads:?}"
        );
        assert!(
            !reads.contains(&new_chunk1),
            "second chunk of the new side was read, but the sniff+size path \
             never needs it: {reads:?}"
        );
    }

    #[test]
    fn render_stat_binary_chunked_blob_sizes_match_manifest_total() {
        // Here every chunk IS stored (so a full reassembly would also
        // "work"), isolating the thing this test actually checks: the
        // rendered Bin sizes are exactly each manifest's total_size, which
        // in turn equals the true concatenated length of its chunks.
        let mut store = RecordingSource::default();

        let old_chunk_a = fake_hash(11);
        let old_chunk_b = fake_hash(12);
        let old_head_bytes = binary_bytes(b'x', BINARY_SNIFF_LEN + 1000); // 9000
        let old_tail_bytes = vec![b'y'; 3000];
        let old_total = (old_head_bytes.len() + old_tail_bytes.len()) as u64;
        let old_manifest_hash = fake_hash(13);
        store.put(
            old_chunk_a,
            &Object::Blob(Blob {
                data: old_head_bytes,
            }),
        );
        store.put(
            old_chunk_b,
            &Object::Blob(Blob {
                data: old_tail_bytes,
            }),
        );
        store.put(
            old_manifest_hash,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: old_total,
                chunk_size: 0,
                chunks: vec![old_chunk_a, old_chunk_b],
            }),
        );

        let new_chunk_a = fake_hash(14);
        let new_chunk_b = fake_hash(15);
        let new_head_bytes = binary_bytes(b'z', BINARY_SNIFF_LEN + 1500); // 9500
        let new_tail_bytes = vec![b'w'; 5500];
        let new_total = (new_head_bytes.len() + new_tail_bytes.len()) as u64;
        let new_manifest_hash = fake_hash(16);
        store.put(
            new_chunk_a,
            &Object::Blob(Blob {
                data: new_head_bytes,
            }),
        );
        store.put(
            new_chunk_b,
            &Object::Blob(Blob {
                data: new_tail_bytes,
            }),
        );
        store.put(
            new_manifest_hash,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: new_total,
                chunk_size: 0,
                chunks: vec![new_chunk_a, new_chunk_b],
            }),
        );

        assert_eq!(old_total, 12000);
        assert_eq!(new_total, 15000);

        let entry = modified_entry("big.bin", old_manifest_hash, new_manifest_hash);
        let mut out = Vec::new();
        render_stat(&mut out, &store, std::iter::once(&entry)).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert_eq!(
            rendered,
            " big.bin | Bin 12000 -> 15000 bytes\n \
             1 file changed, 0 insertions(+), 0 deletions(-)\n"
        );
    }

    /// How many times `render_stat` read each side's top-level object.
    fn reads_per_side(store: &RecordingSource, old: &Hash, new: &Hash) -> (usize, usize) {
        let reads = store.reads.borrow();
        (
            reads.iter().filter(|h| *h == old).count(),
            reads.iter().filter(|h| *h == new).count(),
        )
    }

    #[test]
    fn render_stat_inline_binary_blob_reads_each_side_once() {
        // An inline (non-chunked) binary entry: the sniff prefix and the
        // Bin byte sizes must both come from ONE load of each side's
        // object. Taking them through separate prefix + len store reads
        // re-read (and in the real store, re-hash-verified) every small
        // blob per changed file, which measurably slowed a
        // many-small-files commit's diffstat (#624).
        let mut store = RecordingSource::default();
        let old_hash = fake_hash(21);
        let new_hash = fake_hash(22);
        store.put(
            old_hash,
            &Object::Blob(Blob {
                data: binary_bytes(b'a', 10_240),
            }),
        );
        store.put(
            new_hash,
            &Object::Blob(Blob {
                data: binary_bytes(b'b', 12_288),
            }),
        );

        let entry = modified_entry("f.bin", old_hash, new_hash);
        let mut out = Vec::new();
        render_stat(&mut out, &store, std::iter::once(&entry)).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("Bin 10240 -> 12288 bytes"),
            "sizes should come from the single loaded object: {rendered}"
        );
        assert_eq!(
            reads_per_side(&store, &old_hash, &new_hash),
            (1, 1),
            "each side's object must be read exactly once: {:?}",
            store.reads.borrow()
        );
    }

    #[test]
    fn render_stat_inline_text_blob_reads_each_side_once() {
        // Same single-read guarantee for the text path: the sniff and the
        // line counts share one load per side.
        let mut store = RecordingSource::default();
        let old_hash = fake_hash(23);
        let new_hash = fake_hash(24);
        store.put(
            old_hash,
            &Object::Blob(Blob {
                data: b"one\ntwo\n".to_vec(),
            }),
        );
        store.put(
            new_hash,
            &Object::Blob(Blob {
                data: b"one\nthree\nfour\n".to_vec(),
            }),
        );

        let entry = modified_entry("f.txt", old_hash, new_hash);
        let mut out = Vec::new();
        render_stat(&mut out, &store, std::iter::once(&entry)).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("1 file changed, 2 insertions(+), 1 deletion(-)"),
            "line counts should match the text diff: {rendered}"
        );
        assert_eq!(
            reads_per_side(&store, &old_hash, &new_hash),
            (1, 1),
            "each side's object must be read exactly once: {:?}",
            store.reads.borrow()
        );
    }

    // -----------------------------------------------------------------
    // `DisplaySource` (#625): wrapping the source for display-only reads
    // must be invisible to render output and to the #628 read-count
    // guarantees above — the wrapper only changes verification.
    // -----------------------------------------------------------------

    #[test]
    fn render_stat_through_display_source_matches_direct_output() {
        // Golden-output guard: every row shape `render_stat` can produce —
        // text, inline binary, and chunked binary — must render
        // byte-identically whether the source is read directly or through
        // `DisplaySource`.
        let mut store = RecordingSource::default();

        let text_old = fake_hash(31);
        let text_new = fake_hash(32);
        store.put(
            text_old,
            &Object::Blob(Blob {
                data: b"one\ntwo\n".to_vec(),
            }),
        );
        store.put(
            text_new,
            &Object::Blob(Blob {
                data: b"one\nthree\nfour\n".to_vec(),
            }),
        );

        let bin_old = fake_hash(33);
        let bin_new = fake_hash(34);
        store.put(
            bin_old,
            &Object::Blob(Blob {
                data: binary_bytes(b'a', 10_240),
            }),
        );
        store.put(
            bin_new,
            &Object::Blob(Blob {
                data: binary_bytes(b'b', 12_288),
            }),
        );

        let chunk_old0 = fake_hash(35);
        let chunk_old_manifest = fake_hash(36);
        store.put(
            chunk_old0,
            &Object::Blob(Blob {
                data: binary_bytes(b'c', BINARY_SNIFF_LEN + 1000),
            }),
        );
        store.put(
            chunk_old_manifest,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 3_000_000,
                chunk_size: 0,
                chunks: vec![chunk_old0],
            }),
        );
        let chunk_new0 = fake_hash(37);
        let chunk_new_manifest = fake_hash(38);
        store.put(
            chunk_new0,
            &Object::Blob(Blob {
                data: binary_bytes(b'd', BINARY_SNIFF_LEN + 500),
            }),
        );
        store.put(
            chunk_new_manifest,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 4_000_000,
                chunk_size: 0,
                chunks: vec![chunk_new0],
            }),
        );

        let entries = [
            modified_entry("text.txt", text_old, text_new),
            modified_entry("bin.dat", bin_old, bin_new),
            modified_entry("big.bin", chunk_old_manifest, chunk_new_manifest),
        ];

        let mut direct = Vec::new();
        render_stat(&mut direct, &store, entries.iter()).unwrap();

        let display = DisplaySource::new(&store);
        let mut wrapped = Vec::new();
        render_stat(&mut wrapped, &display, entries.iter()).unwrap();

        assert_eq!(
            direct, wrapped,
            "DisplaySource must not change render_stat's byte output"
        );
    }

    #[test]
    fn render_stat_through_display_source_preserves_single_read_per_side() {
        // The #624 single-read guarantee (each side's top-level object
        // read exactly once) must hold through `DisplaySource` too.
        let mut store = RecordingSource::default();
        let old_hash = fake_hash(51);
        let new_hash = fake_hash(52);
        store.put(
            old_hash,
            &Object::Blob(Blob {
                data: binary_bytes(b'a', 10_240),
            }),
        );
        store.put(
            new_hash,
            &Object::Blob(Blob {
                data: binary_bytes(b'b', 12_288),
            }),
        );

        let entry = modified_entry("f.bin", old_hash, new_hash);
        let display = DisplaySource::new(&store);
        let mut out = Vec::new();
        render_stat(&mut out, &display, std::iter::once(&entry)).unwrap();

        assert_eq!(
            reads_per_side(&store, &old_hash, &new_hash),
            (1, 1),
            "DisplaySource must not add or remove reads: {:?}",
            store.reads.borrow()
        );
    }

    #[test]
    fn render_stat_through_display_source_reads_no_trailing_chunks() {
        // The #606 no-trailing-chunk-read guarantee for chunked binaries
        // must hold through `DisplaySource` too.
        let mut store = RecordingSource::default();

        let old_chunk0 = fake_hash(53);
        let old_chunk1 = fake_hash(54); // deliberately never stored
        let old_manifest_hash = fake_hash(55);
        store.put(
            old_chunk0,
            &Object::Blob(Blob {
                data: binary_bytes(b'a', BINARY_SNIFF_LEN + 1000),
            }),
        );
        store.put(
            old_manifest_hash,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 3_000_000,
                chunk_size: 0,
                chunks: vec![old_chunk0, old_chunk1],
            }),
        );

        let new_chunk0 = fake_hash(56);
        let new_chunk1 = fake_hash(57); // deliberately never stored
        let new_manifest_hash = fake_hash(58);
        store.put(
            new_chunk0,
            &Object::Blob(Blob {
                data: binary_bytes(b'b', BINARY_SNIFF_LEN + 500),
            }),
        );
        store.put(
            new_manifest_hash,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 4_000_000,
                chunk_size: 0,
                chunks: vec![new_chunk0, new_chunk1],
            }),
        );

        let entry = modified_entry("big.bin", old_manifest_hash, new_manifest_hash);
        let display = DisplaySource::new(&store);
        let mut out = Vec::new();
        render_stat(&mut out, &display, std::iter::once(&entry)).unwrap();

        let reads = store.reads.borrow();
        assert!(
            !reads.contains(&old_chunk1),
            "DisplaySource must not cause the old side's trailing chunk to be read: {reads:?}"
        );
        assert!(
            !reads.contains(&new_chunk1),
            "DisplaySource must not cause the new side's trailing chunk to be read: {reads:?}"
        );
    }
}
