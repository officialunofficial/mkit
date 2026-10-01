# Decoder scratch reservation (WP-4.18 continuation)

This implements the 2026-10-01 **RULING 4.18 decoder budget**, under R-203,
R-198 and R-200. No new decision row is allocated.

## A — Fixed contract

- Paid indexed D34/Multi launch; optional sync inspection, native proofs,
  no leases, GC, Events or async holds.
- Keep 48 MiB resident allowance, 256 calls per slice, 100 ops/1 MiB apply,
  1,000 calls per alarm, 128 MB isolate and six connections.
- Reserve decoder scratch from R-203's fixed 8 MiB window and RFC block cap.
- Preserve all existing frame admission and corruption/resource error classes.
- No new storage key, timer, protocol, foundation or normative scope.

## B — Root decisions

- Resume `fix-decoder-scratch-budget`; merge feature base before final gates.
- Coordinate `indexed/job.rs` with Fix B; preserve its current-pack cap guard.
- Target `feat/mkit-server`, open a PR, and never merge or perform release work.
- Authored non-test Rust cap 900; two independent read-only self-reviews.
- The broad valid-frame requirement includes custom public slice geometry;
  default-only Worker configuration does not authorize reducing its admission.

## C — Implementation choices

The allocator reproduction at base `b90f74a3` requests 51,418,822 live bytes
above its seeded baseline, versus 50,331,648 allowed. It fills the in-pack LRU
before decoding a later-corrupted frame with legal 128 KiB RLE blocks.

Retain the configured read geometry and original admission formula. Reducing
physical read geometry changes whether compressed payloads need a carry;
that can reject a valid large-wire/small-claim frame. Instead reduce **retained**
windows: checkpoint and release the idle WindowReader before nested delta-base
decoding. Commit the existing post-entry cursor after that delta succeeds,
then resume on the next alarm. Existing cursor hashes, source etags, per-slice
call accounting and failure checkpoint rules stay in charge.

Reserve 28 MiB for R-203 working allocations: three 8 MiB windows cover
old/new ring growth; 4 MiB covers bounded block scratch and decoder tables.
The default nested decoder phase now holds a 16 MiB source frame, two 1 MiB
entry buffers and a 1 MiB LRU alongside that allowance: 47 MiB, leaving
1 MiB for row/cursor metadata. The acquired source window is gone before a
normal WindowReader decode; the feed's two-window copy does not coincide with
decoder scratch. Object validation/parsing starts after the decoder drops.
The original eight-region entry admission calculation remains unchanged;
the smaller cache retains its one newest admitted object, including custom
near-five-MiB entries. Release MemberCache's duplicate chain only after its
byte/dependency charges have been staged; its needed canonical base remains
in the LRU.

Counting-allocator evidence meters actual `run_due`/VerifyTimer calls,
including range acquisition and allocations freed during rejection. It covers
the original overrun, valid custom 64 KiB geometry, valid five-MiB compressed
wire with a small claim, and later corruption while reacquiring a wide-wire
in-pack base, including a near-five-MiB custom nested decode with real preceding
frame metadata. Cold 50-hop in-pack and mixed member/in-pack regressions check
final usability, per-slice calls and once-only external charging. It is requested
Rust allocation evidence, not isolate RSS or
JavaScript backing-array measurement. WP-4.18 still owns release-Worker and
whole-isolate evidence.

## D — Escalation

Park a concrete valid-frame or fixed-budget conflict rather than reject newly
valid frames, raise a budget, weaken a test or introduce a new foundation.
Flakes/base conflicts require isolation and unchanged-base evidence.
