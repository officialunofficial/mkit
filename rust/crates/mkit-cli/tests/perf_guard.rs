//! #610 (perf regression suite #609, Tier 2): a machine-independent
//! timing-ratio guard for the "everyday operations" `add` scenario on the
//! `/performance` page — re-`add`ing an unchanged file after `touch`
//! (`scripts/bench-vs-git.sh` step 6, `rehash-unchanged`).
//!
//! `touch` bumps mtime, which invalidates the index v2 stat cache (see
//! `mkit_core::worktree::stat_matches`) and forces `add` down the "pure
//! re-hash" path: read + FastCDC-chunk + BLAKE3-hash the file again, same
//! as a first `add`. What the re-hash path must still skip is writing any
//! chunk that's already durably stored — `WriteBatch::write_prehashed`'s
//! `final_path.exists()` dedup hit (`mkit-core/src/batch.rs`) — so an
//! unchanged re-add pays for hashing but not for storing. A regression
//! that silently defeats that dedup check (writing every chunk again
//! regardless of whether it's already on disk) would erase that saving
//! without tripping any functional test, since the resulting object store
//! is still byte-for-byte correct — exactly the kind of silent
//! performance-only regression that let #606 ship for three weeks before
//! a manual re-measure caught it.
//!
//! This cannot be a deterministic proxy (#609's tier 1): "how much
//! faster" is a wall-clock question, not a count. Per #609's design
//! rules it's a same-process timing *ratio* — unchanged-re-add duration
//! over first-add duration — instead of an absolute wall-clock bound, so
//! it stays meaningful across CI machines. It's still real-clock and
//! therefore judged too noise-prone for the default suite: quarantined
//! to the serial `--ignored` CI lane per #505's convention (see
//! `.config/nextest.toml`'s `ignored-lane` profile, which names this
//! test in its `default-filter`).
//!
//! Run locally: `cargo test -p mkit-cli --test perf_guard -- --ignored --nocapture`.
//! Bisecting a regression this test catches: `git bisect` with that
//! command as the bisect script (nonzero exit on ratio-bound violation);
//! the failure message names the measured means and the bound.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::path::Path;
use std::time::{Duration, Instant};

mod common;
use common::{install_fixed_key, mkit};

/// The `/performance` page's `video100m.bin` fixture is 100 MiB; this
/// guard uses a much smaller one — a fixture of only a handful of
/// `FastCDC` chunks would be too small to show a write-skip saving, but a
/// full 100 MiB is unnecessary wall-clock for a guard, not a benchmark
/// (see `scripts/bench-vs-git.sh` for the real, hyperfine-measured numbers
/// this guard is a cheap proxy for). 8 MiB is ~128 average-size (64 KiB)
/// `FastCDC` chunks: enough that "skip writing chunks already on disk" is
/// the dominant cost difference between the two scenarios.
const FIXTURE_BYTES: usize = 8 * 1024 * 1024;

/// Repeats per timed scenario. The reported duration is the *minimum*
/// across repeats, not the mean: on a shared/loaded machine (CI, or a
/// dev box running other work) contention only ever adds time, so the
/// fastest observed run is the best estimate of the operation's true
/// cost and the least polluted by unrelated noise.
const REPS: u32 = 5;

/// How much cheaper an unchanged re-add must be than a first add.
/// Calibrated against this guard's own red/green evidence (see the PR
/// description for #610): with the dedup check intact, the measured
/// ratio was ~0.55–0.65 across repeated local runs (including under
/// concurrent machine load, where it was even lower); with the
/// `final_path.exists()` dedup hit deliberately disabled, it rose to
/// ~0.9–1.1. `0.85` sits with comfortable margin above the healthy
/// range and below the broken one — a generous bound that still catches
/// a fully-disabled dedup fast path, per #609's "prefer generous
/// machine-independent bounds" rule for the serial lane.
const MAX_REHASH_TO_FIRST_ADD_RATIO: f64 = 0.85;

/// Cheap deterministic PRNG (`SplitMix64`) — fills `buf` with varied,
/// non-repeating bytes so `FastCDC` sees realistic content-defined chunk
/// boundaries (a `vec![0u8; N]`-style fixture risks degenerate,
/// unrepresentative chunking), without pulling in a `rand`
/// dev-dependency or paying for `/dev/urandom` on a multi-MiB fixture.
fn fill_pseudo_random(buf: &mut [u8], seed: u64) {
    let mut state = seed;
    let mut i = 0;
    while i < buf.len() {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        let n = bytes.len().min(buf.len() - i);
        buf[i..i + n].copy_from_slice(&bytes[..n]);
        i += n;
    }
}

/// Time a first `add` of `fixture` into a brand-new repo: full read,
/// chunk, hash, AND write of every chunk (nothing is on disk yet).
fn time_first_add(fixture: &[u8], xdg: &Path) -> Duration {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    assert!(
        mkit(root, xdg, &["init"]).status.success(),
        "init must succeed"
    );
    install_fixed_key(root).unwrap();
    std::fs::write(root.join("big.bin"), fixture).unwrap();

    let t0 = Instant::now();
    let out = mkit(root, xdg, &["add", "big.bin"]);
    let elapsed = t0.elapsed();
    assert!(
        out.status.success(),
        "first add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    elapsed
}

/// Time a re-`add` of `fixture` after `touch`: `add`, `commit`, `touch`
/// (untimed setup — the mtime bump alone invalidates the stat cache,
/// forcing the timed `add` below onto the full read+chunk+hash path),
/// then the timed `add`, whose every chunk is already durably stored.
fn time_rehash_unchanged_add(fixture: &[u8], xdg: &Path) -> Duration {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    assert!(
        mkit(root, xdg, &["init"]).status.success(),
        "init must succeed"
    );
    install_fixed_key(root).unwrap();
    let file = root.join("big.bin");
    std::fs::write(&file, fixture).unwrap();
    assert!(
        mkit(root, xdg, &["add", "big.bin"]).status.success(),
        "setup add must succeed"
    );
    assert!(
        mkit(root, xdg, &["commit", "-m", "v1"]).status.success(),
        "setup commit must succeed"
    );

    // Force a real mtime change a couple of seconds into the future —
    // some filesystems have coarse (1s) mtime resolution, so this can
    // never accidentally land inside the racy-write smudge window and
    // get skipped as "no cache" instead of "stale cache, must re-hash".
    // Either sentinel forces the same re-hash path; a real bump keeps
    // the scenario honest about what `touch` does.
    let bumped = std::time::SystemTime::now() + Duration::from_secs(2);
    let f = std::fs::File::options().write(true).open(&file).unwrap();
    f.set_modified(bumped).unwrap();
    drop(f);

    let t0 = Instant::now();
    let out = mkit(root, xdg, &["add", "big.bin"]);
    let elapsed = t0.elapsed();
    assert!(
        out.status.success(),
        "rehash add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    elapsed
}

#[test]
#[ignore = "real-clock timing ratio; run via the serial --ignored CI lane (see .config/nextest.toml)"]
fn add_unchanged_rehash_after_touch_is_cheaper_than_first_add() {
    let xdg = tempfile::tempdir().unwrap();
    let xdg = xdg.path();

    let mut fixture = vec![0u8; FIXTURE_BYTES];
    fill_pseudo_random(&mut fixture, 0xD10D_610D_1234_5678);

    let first_add = (0..REPS)
        .map(|_| time_first_add(&fixture, xdg))
        .min()
        .unwrap();
    let rehash_unchanged = (0..REPS)
        .map(|_| time_rehash_unchanged_add(&fixture, xdg))
        .min()
        .unwrap();

    let ratio = rehash_unchanged.as_secs_f64() / first_add.as_secs_f64();
    assert!(
        ratio <= MAX_REHASH_TO_FIRST_ADD_RATIO,
        "unchanged re-add after touch took {rehash_unchanged:?} vs {first_add:?} for a \
         first add — ratio {ratio:.3} exceeds the {MAX_REHASH_TO_FIRST_ADD_RATIO} bound. \
         A healthy re-add re-hashes the file but skips writing chunks already durably \
         stored (WriteBatch::write_prehashed's dedup hit in mkit-core/src/batch.rs); \
         this ratio rising toward 1.0 means that skip stopped happening."
    );
}
