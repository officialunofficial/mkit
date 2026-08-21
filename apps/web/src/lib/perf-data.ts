/**
 * Real benchmark results: mkit vs git, measured 2026-07-08 on one machine (see `methodology`). Numbers were produced
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
    mkit: { mean: 0.4085, stddev: 0.0421 },
    git: { mean: 2.0376, stddev: 0.0138 },
    note:
      'mkit wins by ~5.0×: content-defined chunking re-hashes the file but stores only the changed chunks, so the ' +
      'second version costs about a megabyte. git re-compresses and stores the whole 101 MiB blob again.',
  },
  {
    id: 'big-1g',
    theme: 'large-files',
    name: 'Add + Commit One 1 GiB File',
    description: 'Same shape at 1 GiB, 3 runs each.',
    mkit: { mean: 5.1225, stddev: 0.1476 },
    git: { mean: 18.5051, stddev: 0.1423 },
    note: 'mkit wins by ~3.6×. First ingest scales linearly for both tools; mkit’s wall clock is I/O + BLAKE3.',
  },
  {
    id: 'big-100m',
    theme: 'large-files',
    name: 'Add + Commit One 100 MiB File',
    description: 'A single 100 MiB file of incompressible bytes (a stand-in for video or other compressed media).',
    mkit: { mean: 0.7687, stddev: 0.0291 },
    git: { mean: 2.1463, stddev: 0.0237 },
    note:
      'mkit wins by ~2.8×: the file splits into ~1,600 content-defined chunks, each hashed with BLAKE3 and ' +
      'barrier-synced from a thread pool, while git’s SHA-1 + zlib pass stays CPU-bound. mkit’s flush cost is ' +
      'constant per commit, not per chunk.',
  },
  {
    id: 'small-files',
    theme: 'everyday',
    name: 'Add + Commit 100 Small Files',
    description: '100 files of 10 KiB random bytes each, staged and committed in one shot.',
    mkit: { mean: 0.1657, stddev: 0.0038 },
    git: { mean: 0.2955, stddev: 0.0127 },
    note:
      'mkit wins by ~1.8× while making every commit crash-durable (git does not fsync loose objects by default). ' +
      'Durability is batched behind two fixed full flushes, then renamed into place — git’s core.fsyncMethod=batch ' +
      'design, on by default.',
  },
  {
    id: 'rehash-unchanged',
    theme: 'everyday',
    name: 'Re-add an Unchanged 100 MiB File',
    description: 'touch the committed file (mtime changes, bytes don’t) and run add again — a pure re-hash.',
    mkit: { mean: 0.1473, stddev: 0.0286 },
    git: { mean: 0.1738, stddev: 0.0023 },
    note:
      'Close to a tie, mkit a hair ahead: the changed mtime invalidates both tools’ stat caches, so both re-read and ' +
      're-hash 100 MiB in well under 200 ms and write nothing new.',
  },
  {
    id: 'init',
    theme: 'everyday',
    name: 'Init an Empty Repository',
    description: 'mkit init vs git init in a fresh directory.',
    mkit: { mean: 0.013, stddev: 0.0009 },
    git: { mean: 0.0135, stddev: 0.0009 },
  },
  {
    id: 'status-unchanged',
    theme: 'everyday',
    name: 'Status With an Unchanged 100 MiB File',
    description: 'mkit status / git status in a clean repo holding the committed 100 MiB file, stat cache warm.',
    mkit: { mean: 0.0151, stddev: 0.0017 },
    git: { mean: 0.0146, stddev: 0.0012 },
    note:
      'A tie. An unchanged file is proven clean by one stat call against the index stat cache — O(stat), no read, ' +
      'no hash, the same trick git plays.',
  },
]

export const sizeBenchmarks: SizeBenchmark[] = [
  {
    id: 'size-big-v1',
    theme: 'large-files',
    name: 'One 100 MiB File, One Commit',
    description: 'Repository size after the first commit of the 100 MiB file.',
    mkitKiB: 104988,
    gitKiB: 115228,
    note:
      'Roughly even: incompressible input means zlib buys git nothing, so both stores hold roughly the content ' +
      'plus bookkeeping (the gap is mostly filesystem allocation, not format).',
  },
  {
    id: 'size-big-v2',
    theme: 'large-files',
    name: 'Growth After a 1 MiB Change',
    description:
      'Additional repository bytes after appending 1 MiB to the 100 MiB file and committing the second version.',
    mkitKiB: 1156,
    gitKiB: 114788,
    note:
      'mkit stores ~1.1 MiB: the appended megabyte, one re-cut boundary chunk, and a fresh manifest. git’s loose ' +
      'store duplicates the whole ~112 MiB blob until git gc repacks it back to ~zero growth, so mkit’s store is ' +
      'incremental by construction while git’s is dense only after a maintenance pass.',
  },
  {
    id: 'size-small',
    theme: 'everyday',
    name: '100 Small Files, One Commit',
    description: 'Repository size after committing 100 × 10 KiB of random bytes (1,000 KiB of content).',
    mkitKiB: 1236,
    gitKiB: 1312,
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
  date: '2026-07-08',
  /**
   * Full SHA of the mkit commit the benchmarked binary was built from — not merely the date, which is easy to
   * mis-anchor (see #607: two investigations chased the wrong baseline because "measured 2026-06-12" undershot PR #341,
   * which merged two days later and changed every timing on this page). `scripts/bench-vs-git.sh` emits the same field
   * for future re-measures; keep this in sync with whatever it records.
   */
  commit: 'eb5508b029843172c007bca356846cc8a289e92e',
  machine: 'Apple M4 Max, 16 cores, 128 GB RAM, APFS SSD, macOS 26.5.1',
  versions: 'mkit (development build, cargo build --release) · git 2.50.1 (Apple Git-155) · hyperfine 1.20.0',
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
    'One machine, one filesystem, one day. Ratios on spinning disks, network filesystems, or Linux will differ — ' +
      'flush cost in particular is hardware-dependent.',
    'Both tools were run through their CLI end to end (process spawn included), with stock configuration: no git ' +
      'core.fsmonitor, no mkit tuning.',
  ],
  commands: [
    '# the whole suite is reproducible from the repo root:',
    'cargo build --release -p mkit-cli   # in rust/',
    'scripts/bench-vs-git.sh             # hyperfine JSON + sizes into ./bench-results',
  ],
} as const
