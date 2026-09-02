/**
 * Real benchmark results: mkit vs git, measured 2026-09-02 on one machine (see `methodology`). Numbers were produced
 * with hyperfine and `du -k` in throwaway temp directories (`scripts/bench-vs-git.sh`), then baked in here as static
 * data — nothing on this page is estimated or extrapolated. Where git wins, the data says so.
 *
 * Means and standard deviations are in seconds, copied verbatim from hyperfine's `--export-json` output.
 *
 * Rows are grouped by workload (`theme`): the `large-files` benchmarks are where mkit's chunking is built to win; the
 * `everyday` benchmarks are the routine operations where the honest verdict is roughly even.
 *
 * `methodology.commit` records the mkit commit SHA the benchmarked binary was built from — keep it in sync with
 * `scripts/bench-vs-git.sh`, which emits the same provenance (commit + dirty flag) for every re-measure (#607).
 *
 * The reference machine changed with this measurement: earlier rows (through the 2026-07-08 measurement) were taken on
 * an Apple M4 Max / APFS; this and future measurements use the 4-core Linux container documented in
 * `methodology.machine` — the same class of box these benchmarks now run on routinely, so numbers stay reproducible
 * without needing access to specific Apple hardware. Several ratios moved as a result (see per-row notes) — most
 * shifted further in mkit's favor, one (`size-big-v1`) flipped because of a filesystem block-size effect explained on
 * that row.
 */

/** Which workload section a row renders under. */
export type Theme = 'large-files' | 'everyday'

export type Measurement = {
  /** Mean wall-clock seconds across runs. */
  mean: number
  /** Standard deviation in seconds. */
  stddev: number
}

export type TimingBenchmark = {
  id: string
  theme: Theme
  name: string
  description: string
  mkit: Measurement
  git: Measurement
  note?: string
}

export type SizeBenchmark = {
  id: string
  theme: Theme
  name: string
  description: string
  /** `du -k .mkit` in KiB — an absolute size, or growth, per the row's `description`. */
  mkitKiB: number
  /** `du -k .git` in KiB, loose objects (the state git leaves you in until a gc/repack) — same convention as `mkitKiB`. */
  gitKiB: number
  note?: string
}

export const timingBenchmarks: TimingBenchmark[] = [
  {
    id: 'append-1m',
    theme: 'large-files',
    name: 'Commit a 1 MiB Change to the 100 MiB File',
    description: 'Append 1 MiB to the already-committed 100 MiB file, then add + commit the new version.',
    mkit: { mean: 0.1609, stddev: 0.0162 },
    git: { mean: 3.3673, stddev: 0.2131 },
    note:
      'mkit wins by ~20.9×: content-defined chunking re-hashes the file but stores only the changed chunks, so the ' +
      'second version costs about a megabyte. git re-compresses and stores the whole 101 MiB blob again. The gap is ' +
      'far wider here than the ~5× this row showed on the Apple M4 Max this page previously measured — this ' +
      'container’s disk stack makes git’s full-object rewrite comparatively far more expensive.',
  },
  {
    id: 'big-1g',
    theme: 'large-files',
    name: 'Add + Commit One 1 GiB File',
    description: 'Same shape at 1 GiB, 3 runs each.',
    mkit: { mean: 11.5799, stddev: 1.4542 },
    git: { mean: 41.3829, stddev: 1.0715 },
    note:
      'mkit wins by ~3.6×, matching the ratio measured on the previous reference machine almost exactly. First ' +
      'ingest scales linearly for both tools; mkit’s wall clock is I/O + BLAKE3.',
  },
  {
    id: 'big-100m',
    theme: 'large-files',
    name: 'Add + Commit One 100 MiB File',
    description: 'A single 100 MiB file of incompressible bytes (a stand-in for video or other compressed media).',
    mkit: { mean: 0.7899, stddev: 0.256 },
    git: { mean: 3.2911, stddev: 0.0715 },
    note:
      'mkit wins by ~4.2×: the file splits into roughly 1,300 content-defined chunks, each hashed with BLAKE3 and ' +
      'barrier-synced from a thread pool, while git’s SHA-1 + zlib pass stays CPU-bound. mkit’s own run-to-run ' +
      'variance is high here (±256 ms on a 790 ms mean) — this container’s shared disk I/O is noisier than ' +
      'dedicated hardware.',
  },
  {
    id: 'small-files',
    theme: 'everyday',
    name: 'Add + Commit 100 Small Files',
    description: '100 files of 10 KiB random bytes each, staged and committed in one shot.',
    mkit: { mean: 0.0444, stddev: 0.0088 },
    git: { mean: 0.1391, stddev: 0.0187 },
    note:
      'mkit wins by ~3.1× while making every commit crash-durable (git does not fsync loose objects by default). ' +
      'Durability is batched behind two fixed full flushes, then renamed into place — git’s core.fsyncMethod=batch ' +
      'design, on by default.',
  },
  {
    id: 'rehash-unchanged',
    theme: 'everyday',
    name: 'Re-add an Unchanged 100 MiB File',
    description: 'touch the committed file (mtime changes, bytes don’t) and run add again — a pure re-hash.',
    mkit: { mean: 0.1405, stddev: 0.0074 },
    git: { mean: 0.3034, stddev: 0.0077 },
    note:
      'mkit wins by ~2.2× here, versus a near-tie on the previous reference machine: the changed mtime invalidates ' +
      'both tools’ stat caches, so both re-read and re-hash the full 100 MiB, but git’s SHA-1 pass over ' +
      'incompressible bytes costs more on this CPU than mkit’s single BLAKE3 pass.',
  },
  {
    id: 'init',
    theme: 'everyday',
    name: 'Init an Empty Repository',
    description: 'mkit init vs git init in a fresh directory.',
    mkit: { mean: 0.0032, stddev: 0.0019 },
    git: { mean: 0.0025, stddev: 0.0004 },
    note:
      'Too fast to read much into: both finish in a few milliseconds, under hyperfine’s ~5 ms calibration floor for ' +
      'shell-startup precision. mkit’s run also tripped hyperfine’s outlier warning (occasional spikes to ~38 ms ' +
      'across 365 runs) — process-spawn and scheduler noise on a shared container, not a real cost difference.',
  },
  {
    id: 'status-unchanged',
    theme: 'everyday',
    name: 'Status With an Unchanged 100 MiB File',
    description: 'mkit status / git status in a clean repo holding the committed 100 MiB file, stat cache warm.',
    mkit: { mean: 0.0026, stddev: 0.0002 },
    git: { mean: 0.0023, stddev: 0.0002 },
    note:
      'A tie, both under hyperfine’s ~5 ms precision floor. An unchanged file is proven clean by one stat call ' +
      'against the index stat cache — O(stat), no read, no hash, the same trick git plays.',
  },
]

export const sizeBenchmarks: SizeBenchmark[] = [
  {
    id: 'size-big-v1',
    theme: 'large-files',
    name: 'One 100 MiB File, One Commit',
    description: 'Repository size after the first commit of the 100 MiB file.',
    mkitKiB: 106160,
    gitKiB: 102604,
    note:
      'git is slightly smaller here — a reversal from the ~10% mkit lead this row showed on the previous (APFS) ' +
      'reference machine. Incompressible input means zlib buys git nothing on content bytes, but mkit splits the ' +
      'file into roughly 1,300 content-defined-chunk objects versus git’s single loose blob, and each small file ' +
      'rounds up to this filesystem’s 4 KiB block size — overhead that shows up more on ext4 than it did on APFS.',
  },
  {
    id: 'size-big-v2',
    theme: 'large-files',
    name: 'Growth After a 1 MiB Change',
    description:
      'Additional repository bytes after appending 1 MiB to the 100 MiB file and committing the second version.',
    mkitKiB: 1104,
    gitKiB: 103476,
    note:
      'mkit stores ~1.1 MiB: the appended megabyte, one re-cut boundary chunk, and a fresh manifest. git’s loose ' +
      'store duplicates the whole ~101 MiB blob (growth shown here) until `git gc` repacks it back down to ~1.0 ' +
      'MiB growth, matching mkit — so mkit’s store is incremental by construction while git’s is dense only after ' +
      'a maintenance pass.',
  },
  {
    id: 'size-small',
    theme: 'everyday',
    name: '100 Small Files, One Commit',
    description: 'Repository size after committing 100 × 10 KiB of random bytes (1,000 KiB of content).',
    mkitKiB: 1600,
    gitKiB: 1704,
    note: 'Effectively a tie — both store roughly the content plus per-object overhead.',
  },
]

export type TransferBenchmark = {
  id: string
  theme: Theme
  name: string
  description: string
  /** Bytes put on the wire by the pre-delta push path (whole changed chunk re-uploaded). */
  wholeChunkBytes: number
  /** Bytes put on the wire with delta-on-the-wire encoding. */
  deltaBytes: number
  note?: string
}

/**
 * Delta-on-the-wire push, added in the transport delta-encoding work (PR #401). A small edit to a large already-pushed
 * file now sends a chunk delta instead of the whole re-cut chunk. Bytes are counted on the wire end-to-end over a local
 * `file://` remote by the push/fetch integration suite (`rust/crates/mkit-cli/tests/push_delta.rs`), which asserts the
 * second push is under 16 KiB and at least 20× smaller than the first — these figures are the measured run, not the
 * asserted bound.
 */
export const transferBenchmarks: TransferBenchmark[] = [
  {
    id: 'push-small-edit',
    theme: 'large-files',
    name: 'Push a 16-Byte Edit to a 2 MiB File',
    description:
      'Edit 16 bytes in the middle of a 2 MiB FastCDC-chunked file the remote already holds, then push the new commit. Bytes counted on the wire.',
    wholeChunkBytes: 72704, // ~71 KiB: the whole re-cut FastCDC chunk
    deltaBytes: 1536, // ~1.5 KiB: chunk delta (93 B) + fresh manifest, tree, commit, packmap node
    note:
      'The chunk delta is 93 bytes; the rest of the ~1.5 KiB is the new manifest, tree, commit, and packmap node, ' +
      'versus re-sending the whole ~71 KiB re-cut chunk. Delta is a transfer encoding only — it is used only when it ' +
      'beats the raw chunk, and every reconstructed object is re-verified against its hash before storage.',
  },
]

export const methodology = {
  date: '2026-09-02',
  /**
   * Full SHA of the mkit commit the benchmarked binary was built from — not merely the date, which is easy to
   * mis-anchor (see #607: two investigations chased the wrong baseline because "measured 2026-06-12" undershot PR #341,
   * which merged two days later and changed every timing on this page). `scripts/bench-vs-git.sh` emits the same field
   * for future re-measures; keep this in sync with whatever it records.
   */
  commit: 'bb98978e5e1e0eda9d03ccab3540b65b745ad2fa',
  machine:
    '4-core Intel Xeon @ 2.10 GHz, 15 GB RAM, ext4 on a virtual disk, Linux 6.18 (Ubuntu 24.04) — a shared ' +
    'CI-style container, not dedicated hardware. This replaces the Apple M4 Max / APFS machine earlier ' +
    'measurements on this page used, chosen so the suite runs on the same kind of box these benchmarks are ' +
    'actually re-measured on.',
  versions: 'mkit 0.4.1 (release build, cargo build --release) · git 2.43.0 · hyperfine 1.18.0',
  harness:
    'scripts/bench-vs-git.sh — hyperfine with --warmup and per-command --prepare resetting a temp directory to a ' +
    'clean state between runs; 3 runs for the 1 GiB case, hyperfine defaults elsewhere; results from --export-json. ' +
    'Sizes via du -k.',
  workload:
    'Random (incompressible) bytes, standing in for already-compressed media like video. Compressible source code ' +
    'would flatter git’s zlib store and is not what these benchmarks measure.',
  caveats: [
    'Signed vs unsigned: every mkit commit is Ed25519-signed; the git side runs unsigned, as git defaults to. ' +
      'Signing costs mkit well under a millisecond per commit, but the comparison is asymmetric.',
    'Durability: mkit batches each command’s object writes behind two fixed full flushes plus per-file barriers ' +
      '(SPEC-OBJECTS §10.1), so a commit is durable when the command returns; git does not fsync loose objects by ' +
      'default. Per-object flushing is available via the durability.objects = per-object config key.',
    'One machine, one filesystem, one day — now a shared virtualized container rather than dedicated hardware, so ' +
      'expect more run-to-run noise (see the init/big-100m notes below) than a quiet dedicated machine would show. ' +
      'Ratios on spinning disks, network filesystems, or a different OS/filesystem will differ further — flush ' +
      'cost and small-file block-size overhead are both hardware/filesystem-dependent.',
    'Both tools were run through their CLI end to end (process spawn included), with stock configuration: no git ' +
      'core.fsmonitor, no mkit tuning.',
  ],
  commands: [
    '# the whole suite is reproducible from the repo root:',
    'cargo build --release -p mkit-cli   # in rust/',
    'scripts/bench-vs-git.sh             # hyperfine JSON + sizes into ./bench-results',
  ],
} as const
