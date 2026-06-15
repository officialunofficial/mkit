//! Throwaway measurement for issue #349 (MMB-P evaluation, Phase 1).
//!
//! Quantifies how much a non-zero `inactive_peaks` boundary (the "pyramid
//! bagging" knob) shrinks a commit-history MMR **inclusion proof** for an
//! *active* leaf — i.e. the win MMB-P would unlock for `history-mmr` once a
//! GC / prune floor exists. mkit hardcodes `inactive_peaks = 0` today
//! (history.rs `prove`/`root`), so this measures the hypothetical upside.
//!
//! Run:
//!   cargo run --release --example mmbp_proof_size -p mkit-core \
//!     --features history-mmr
//!
//! It builds an MMR of `N` leaves, then for a set of inactivity floors `F`
//! (fraction of oldest leaves treated as pruned/inactive) reports the
//! inclusion-proof digest count for active leaves vs the `inactive_peaks=0`
//! baseline. Proof bytes ≈ digests × 32 (Blake3) + small framing.
//!
//! Throwaway measurement: the casts below are benign at this scale.
#![allow(clippy::cast_precision_loss, clippy::doc_markdown)]

use commonware_cryptography::Blake3;
use commonware_storage::merkle::mmr::{Location, StandardHasher, mem::Mmr};
use commonware_storage::merkle::{Bagging, Family};

type Fam = commonware_storage::merkle::mmr::Family;

fn build(
    n: u64,
    hasher: &StandardHasher<Blake3>,
) -> Mmr<<Blake3 as commonware_cryptography::Hasher>::Digest> {
    let mut mmr = Mmr::new();
    let mut i = 0u64;
    // Build in chunks so the pending batch stays bounded.
    while i < n {
        let end = (i + 50_000).min(n);
        let mut batch = mmr.new_batch();
        for k in i..end {
            let elem = blake_elem(k);
            batch = batch.add(hasher, &elem);
        }
        let merkleized = batch.merkleize(&mmr, hasher);
        mmr.apply_batch(&merkleized).expect("apply batch");
        i = end;
    }
    mmr
}

fn blake_elem(k: u64) -> [u8; 32] {
    // Distinct 32-byte leaf payloads (stand-in for commit hashes).
    let mut e = [0u8; 32];
    e[..8].copy_from_slice(&k.to_le_bytes());
    e
}

fn digit(v: usize) -> String {
    v.to_string()
}

fn measure(n: u64) {
    let hasher = StandardHasher::<Blake3>::new(Bagging::ForwardFold);
    let mmr = build(n, &hasher);
    let size = mmr.size();
    let peaks = Fam::peaks(size).count();

    // Sample active leaves to average over: the newest leaf, the leaf just
    // above the floor, and a spread in between.
    println!(
        "\n=== N = {n} leaves  (MMR size = {}, peaks = {peaks}) ===",
        *size
    );
    println!(
        "{:<10} {:>13} {:>12} {:>10} {:>12} {:>10}",
        "floor%", "inactive_pk", "avg_digests", "max", "vs_base_avg", "bytes(avg)"
    );

    // Baseline (inactive_peaks = 0) average over the same sample set.
    let baseline = avg_max_digests(&mmr, &hasher, 0, 0, n);

    for pct in [0u64, 50, 90, 99, 999] {
        // pct is in tenths of a percent for the last entry (999 => 99.9%).
        let floor = if pct == 999 {
            n * 999 / 1000
        } else {
            n * pct / 100
        };
        let ip = Fam::inactive_peaks(size, Location::new(floor));
        let (avg, max) = avg_max_digests(&mmr, &hasher, ip, floor, n);
        let vs = baseline.0 - avg;
        let label = if pct == 999 {
            "99.9".to_string()
        } else {
            pct.to_string()
        };
        println!(
            "{:<10} {:>13} {:>12} {:>10} {:>12} {:>10}",
            label,
            digit(ip),
            format!("{avg:.2}"),
            max,
            format!("-{vs:.2}"),
            format!("{:.0}", avg * 32.0),
        );
    }
}

/// Average + max inclusion-proof digest count over a sample of ACTIVE
/// leaves (location in `floor..n`) at the given `inactive_peaks`.
fn avg_max_digests(
    mmr: &Mmr<<Blake3 as commonware_cryptography::Hasher>::Digest>,
    hasher: &StandardHasher<Blake3>,
    inactive_peaks: usize,
    floor: u64,
    n: u64,
) -> (f64, usize) {
    let active_lo = floor;
    let active_hi = n; // exclusive
    if active_lo >= active_hi {
        return (0.0, 0);
    }
    // Sample up to 64 evenly spread active leaves (always include the newest).
    let span = active_hi - active_lo;
    let samples = span.min(64);
    let mut total = 0usize;
    let mut max = 0usize;
    let mut count = 0usize;
    for s in 0..samples {
        let loc = active_lo + (s * span / samples);
        let proof = mmr
            .proof(hasher, Location::new(loc), inactive_peaks)
            .expect("proof");
        let d = proof.digests.len();
        total += d;
        max = max.max(d);
        count += 1;
    }
    (total as f64 / count as f64, max)
}

fn main() {
    println!("MMB-P Phase-1 measurement (issue #349)");
    println!("inclusion-proof digest count for ACTIVE leaves vs inactive_peaks");
    for n in [1_000u64, 100_000, 1_000_000] {
        measure(n);
    }
    println!(
        "\nNote: proof bytes ≈ digests × 32 (Blake3) + framing. inactive_peaks>0\n\
         folds the inactive-prefix peaks into one accumulator, so active-leaf\n\
         proofs drop by ~(#inactive peaks − 1) digests."
    );
}
