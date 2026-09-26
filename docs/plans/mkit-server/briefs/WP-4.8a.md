## Purpose

WP-4.8 (Workers async verification) must read packs of up to 4 GiB from R2 inside a 128 MB isolate. It reads large
Range windows (about 16 MiB, one subrequest per window) across several alarm slices, and checkpoints progress in
Durable Object storage so a CPU-limit restart resumes where it stopped. This WP provides the pure, runtime-free core of
that: a reader that yields exactly the entries `PackEntries` would yield, but over windows, with bounded memory and a
resumable cursor. It does **not** resolve deltas and does not store anything. That is WP-4.7/4.8.

## A. Fixed by the plan and specs (do not change)

1. **Format rules** come from `docs/specs/SPEC-PACKFILE.md`:
   - §1: layout; trailer = `BLAKE3(bytes[0 .. len-32])`.
   - §2: framing, `payload_len` ≤ 2^31-1, bounds-checked against the pre-trailer tail.
   - §3: entry types `0x00`/`0x02`/`0x03`/`0x04`; `0x03`/`0x04` only in v2.
   - §3.3: zstd bomb guards; claims checked before any allocation, and the exact length re-checked.
   - §5: `MAX_ENTRIES` and the `MAX_TOTAL_PAYLOAD` payload-sum cap.
   - §6: no trailing data.
   - **§11 (streaming hook):** a streaming reader verifies the trailer at END of stream, and the caller MUST discard
     everything it staged if that check fails.
2. **Equivalence with the buffered reader** (amended in amendment 1). For any byte string `P`, a full window-reader run
   with limits that do not bind agrees with `PackEntries::new(P)` followed by full iteration:
   - **Ok ⇔ Ok.** If both succeed, the yielded entries are equal in order and content. `PackEntry::Raw{bytes}` /
     `PackEntry::Delta{base, stream}` are compared by value, with zstd entries decompressed exactly as `PackEntries` does.
   - **Err ⇔ Err.** The error *variant* may differ: `PackEntries` checks the trailer before parsing entries, while the
     streaming reader checks it last (§11). Entries yielded before an `Err` are provisional.
   - **The one permitted divergence is a resource-limit failure.** The window reader may return `PackfileTooLarge`,
     from the `limits` budget or from a failed `try_reserve` (B.3), on a pack `PackEntries` accepts, because
     `PackEntries` has no budget. That is the only case where the window reader may fail while `PackEntries` succeeds.
   - Differential tests therefore run with `DecodeLimits::default()`, which is at least any test pack's needs. The
     budget-failure cases are tested separately (Tests 3).
3. **Module location:**
   - The module is `mkit_core::pack::window`, in the file `rust/crates/mkit-core/src/pack/window.rs`.
   - `src/pack.rs` declares it with a single line, `pub mod window;` (the Rust 2018 non-`mod.rs` layout).
   - Do **NOT** convert `pack.rs` into `pack/mod.rs`. WP-5.7a adds `pack/rewrite.rs` the same way, in parallel.
4. **Compatibility:**
   - mkit-core is published, so the API is additive only.
   - `PackError` is **not** `#[non_exhaustive]`, so you MUST NOT add variants to it. Reuse existing variants (see B.6).
   - No async runtime and no new dependencies beyond what mkit-core already has. `blake3` 1.8.x with `hazmat` is already
     used, in `src/upload_parts.rs`.
   - The module must compile for `wasm32-unknown-unknown` with `--no-default-features --features pack-ruzstd`.

## B. Decided by the orchestrator (do not change)

1. **Sans-IO state machine.** The reader never performs I/O itself. This is required because the Workers caller
   fetches windows asynchronously from R2 while native callers read files. The public surface is exactly:
   ```rust
   pub struct WindowReader { /* private */ }

   #[derive(Debug, Clone, Copy, PartialEq, Eq)]
   #[non_exhaustive]
   pub struct WindowRequest { pub offset: u64, pub len: u64 }

   #[derive(Debug)]
   #[non_exhaustive]
   pub enum Step {
       /// The caller must fetch exactly this byte range and call `feed`.
       NeedWindow(WindowRequest),
       /// The next entry, in pack order. Provisional until `Done` (SPEC-PACKFILE §11).
       Entry(PackEntry<'static>),
       /// End of pack: framing, no trailing data, trailer and (if given) pack id all verified.
       Done(WindowSummary),
   }

   #[derive(Debug, Clone, PartialEq, Eq)]
   #[non_exhaustive]
   pub struct WindowSummary {
       pub version: u32,
       pub entry_count: u32,
       pub raw_only: bool,             // same meaning as PackEntries::is_raw_only
       pub first_non_raw: Option<u32>, // same meaning as PackEntries::first_non_raw_index
   }

   impl WindowReader {
       pub fn new(pack_len: u64, window_size: u64, limits: DecodeLimits,
                  expected_pack_id: Option<Hash>) -> Result<Self, PackError>;
       pub fn resume(cursor: &WindowCursor, limits: DecodeLimits) -> Result<Self, PackError>;
       pub fn step(&mut self) -> Result<Step, PackError>;
       pub fn feed(&mut self, offset: u64, bytes: &[u8]) -> Result<(), PackError>;
       /// `Some` only when positioned at an entry boundary (never mid-entry); `None` otherwise.
       pub fn checkpoint(&self) -> Option<WindowCursor>;
   }

   pub struct WindowCursor { /* private */ }
   impl WindowCursor {
       pub fn to_bytes(&self) -> Vec<u8>;
       pub fn from_bytes(bytes: &[u8]) -> Result<Self, PackError>;
   }

   /// Convenience synchronous driver.
   pub trait WindowSource {
       fn read_window(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, PackError>;
   }
   impl WindowSource for &[u8] { /* in-memory, for tests and native callers */ }
   pub fn read_all<S: WindowSource>(source: &mut S, pack_len: u64, window_size: u64,
       limits: DecodeLimits, expected_pack_id: Option<Hash>,
       sink: impl FnMut(PackEntry<'static>) -> Result<(), PackError>) -> Result<WindowSummary, PackError>;
   ```
   You may add private items. Public items beyond this list need a justification in the PR.
2. **Window geometry:**
   - `window_size` is a power of two in `[64 KiB, 64 MiB]`. Anything else is rejected in `new`, reusing an existing
     `PackError` variant (see B.6).
   - Window `k` is exactly `offset = k × window_size`, `len = min(window_size, pack_len − offset)`.
   - **The trailer may straddle windows** (amendment 1): the 32 trailer bytes `[pack_len−32, pack_len)` can span the last
     two windows (e.g. `pack_len = 65,537`, `window_size = 65,536`: the last window holds one byte). The reader
     accumulates the trailer bytes across windows and compares them at `Done`. Likewise, an entry frame (header or
     payload) may straddle any number of windows.
   - `feed` MUST reject any (offset, len) other than the outstanding request.
   - `pack_len < 44` gives `PackfileTooShort`.
3. **Memory bound:**
   - Resident bytes are at most one window + one carried partial entry + one decompressed entry.
   - The carried partial entry (an entry straddling windows) and each `0x03`/`0x04` claimed `uncompressed_len` are
     charged against `limits.max_decoded_bytes`. Going over gives `PackfileTooLarge`, before allocating.
   - Use `Vec::try_reserve` for these buffers, so a failed allocation is an error (`PackfileTooLarge`), not an abort.
   - Entries are never retained after they are yielded.
4. **Streaming trailer and pack-id hashing:**
   - Hash incrementally with `blake3::hazmat` subtree chaining values, window by window, following BLAKE3's left-balanced
     tree rule exactly as `src/upload_parts.rs` does (`left_subtree_len`, `merge_subtrees_non_root`,
     `merge_subtrees_root`).
   - The state must be O(log n) chaining values, not one per window.
   - Two roots are needed:
     - the **trailer** root over `[0, pack_len−32)`, which must equal the trailer bytes, else `PackfileCorrupted`;
     - if `expected_pack_id` is `Some`, the **pack-id** root over `[0, pack_len)` (SPEC-PACKFILE §7), else
       `PackfileCorrupted`.
   - Both are checked only at `Done`.
   - A single-window pack must also work (the root is then a plain hash).
5. **Cursor semantics:**
   - The cursor is produced and stored by the **server** (Durable Object storage). It is trusted at rest, but it may be
     stale, truncated or belong to another pack.
   - Encoding: canonical, versioned (`version: u8 = 1`), little-endian. It contains:
     - `pack_len`, `window_size` and the optional `expected_pack_id`;
     - the entry index and byte offset of the next entry;
     - the running payload sum;
     - the completed-window count;
     - the chaining-value stack(s);
     - a trailing BLAKE3-derived 32-byte checksum over the preceding fields.
   - Max encoded size: 4 KiB.
   - `from_bytes` rejects any version other than 1, a bad checksum, or inconsistent fields (offset outside
     `[12, pack_len−32]`, index > entry count, CV stack depth inconsistent with the window count), with `PackfileCorrupted`.
   - `resume` then re-requests the window containing the next entry.
   - Binding: a cursor from pack A used on pack B must fail. It fails either at `from_bytes`/`resume`, when
     `expected_pack_id` or `pack_len` differ, or at `Done` through the trailer and pack-id roots. It must never yield a
     `Done`.
6. **Error variant reuse** (no new variants):

   | Condition | Variant |
   |---|---|
   | wrong `feed` range, invalid `window_size`, bad cursor, trailer or pack-id mismatch | `PackfileCorrupted` |
   | budget exceeded, allocation failure | `PackfileTooLarge` |
   | framing and trailing data | the same variants `PackEntries` uses |
   | zstd | `ZstdEntryTruncated` / `DecompressedSizeOverCap` / `DecompressedSizeMismatch` / `ZstdDecompress` |

   Document this mapping in the module docs.
7. **32-bit safety:**
   - All offset and length arithmetic is `u64` with checked operations, converted to `usize` only for in-memory slices,
     through `usize::try_from` (failure gives `PackfileTooLarge`).
   - `overflow-checks` is on in release, so there must be no unchecked `+`/`-` on untrusted values.
8. **zstd decode** reuses mkit-core's existing internal `zstd_decompress_capped(frame, capacity)` in `pack.rs`. It
   already selects the C zstd backend under `pack-zstd`, else ruzstd under `pack-ruzstd`. Reuse it, and reuse
   `require_zstd_frame_magic` and the `0x03`/`0x04` length-prefix parsing that `PackEntries` uses. Don't duplicate the
   decoder selection.

## C. Your decisions (record each in the PR under "Executor decisions")

- The internal structure: state enum, how the CV stack merges incrementally, how straddling entries are carried.
- Whether `read_all` and the `&[u8]` source live in `window.rs` or a small submodule.
- The exact cursor byte layout, within B.5.
- The bench design: add `rust/benches/benches/pack_window.rs`, registered in `rust/benches/Cargo.toml` like the existing benches. It reports throughput against
  `PackEntries` on a 256 MiB synthetic pack at 1 MiB and 16 MiB windows.
- Whether any small internal refactor in `pack.rs` is needed to share the frame parser with `PackEntries`. Preferred:
  share it rather than duplicate it, but `PackEntries`'s behaviour and public API must stay byte-identical, as the
  existing tests and goldens prove.

## Tests (required)

1. **Differential against `PackEntries`:**
   - over every golden in `rust/tests/golden/pack-v2/`, including `large_literals`, and all pack fixtures under
     `rust/tests/golden/`;
   - over a proptest corpus of valid packs (built with `PackWriter`, mixed raw, delta and zstd) and mutated packs
     (bit flips, truncation, extra bytes);
   - at window sizes of 64 KiB and 1 MiB, and with `window_size` chosen so entry headers and payloads straddle
     boundaries. For tiny packs, use a 64 KiB window with the pack spanning multiple windows via padding entries.
   - Check Ok/Err agreement and entry equality, as in A.2.
2. **Resume:** checkpoint after every entry, serialize, resume in a fresh `WindowReader`, finish, and get the same
   result. Also: a corrupted cursor byte, a cursor from another pack, a truncated cursor and a wrong version all fail
   per B.5.
3. **Decompression bombs:**
   - a small pack claiming a 1 GiB zstd entry with a 16 MiB budget gives `PackfileTooLarge` before allocation;
   - a straddling entry larger than the budget is rejected.
4. **Memory:** assert that peak resident buffer bytes, instrumented internally with a test-only counter, stay within
   window + budget.
5. **32-bit:** `payload_len = u32::MAX` and pack lengths near `u32::MAX`/`u64::MAX` give clean errors. Extend the
   wasm32 harness (`rust/crates/mkit-core-wasm-check`, run by `scripts/wasm-ruzstd-check.sh`) with a window-reader
   differential over the pack-v2 goldens.
6. **Trailer and id:** a correct trailer with a wrong `expected_pack_id` gives `PackfileCorrupted` at `Done`, and a
   single-window pack hashes correctly.

## D. Escalate (stop and report, do not improvise) if

- `blake3::hazmat` can't produce a streaming root identical to `hash::hash` for some length class. Report the class.
- Sharing the frame parser would require changing `PackEntries`'s public API or observable behaviour.
- Section A or B contradicts itself or the spec.

## Gate additions

- `bash scripts/wasm-ruzstd-check.sh`
- `cargo nextest run -p mkit-core --no-default-features --features pack-ruzstd`
- `cargo nextest run -p mkit-core --all-features -E 'test(/pack|window/)'`
- the goldens unchanged: `git diff --exit-code rust/tests/golden/`
