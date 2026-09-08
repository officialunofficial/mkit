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
    name: 'Commit a 1 MiB change to the 100 MiB file',
    description: 'Append 1 MiB to the already-committed 100 MiB file, then add and commit the new version.',
    mkit: { mean: 0.1609, stddev: 0.0162 },
    git: { mean: 3.3673, stddev: 0.2131 },
    note: 'mkit is about 20.9 times faster in this measurement. Content-defined chunking re-hashes the file but stores only changed chunks, adding about 1 MiB. Git compresses and stores the full 101 MiB blob again. File rewrite costs depend on the storage system.',
  },
  {
    id: 'big-1g',
    theme: 'large-files',
    name: 'Add and commit one 1 GiB file',
    description: 'Add and commit a 1 GiB file of incompressible bytes, with 3 runs per tool.',
    mkit: { mean: 11.5799, stddev: 1.4542 },
    git: { mean: 41.3829, stddev: 1.0715 },
    note: 'mkit is about 3.6 times faster in this measurement. Initial processing time scales linearly for both tools. mkit spends time on file I/O and BLAKE3 hashing.',
  },
  {
    id: 'big-100m',
    theme: 'large-files',
    name: 'Add and commit one 100 MiB file',
    description: 'A single 100 MiB file of incompressible bytes (a stand-in for video or other compressed media).',
    mkit: { mean: 0.7899, stddev: 0.256 },
    git: { mean: 3.2911, stddev: 0.0715 },
    note: 'mkit is about 4.2 times faster in this measurement. It divides the file into roughly 1,300 chunks, hashes each with BLAKE3, and synchronizes writes from a thread pool. Git’s SHA-1 hashing and zlib compression are CPU-bound. mkit has high variation between runs: a 256 ms standard deviation on a 790 ms mean. Shared disk I/O affects these timings.',
  },
  {
    id: 'small-files',
    theme: 'everyday',
    name: 'Add and commit 100 small files',
    description: '100 files of 10 KiB random bytes each, staged and committed together.',
    mkit: { mean: 0.0444, stddev: 0.0088 },
    git: { mean: 0.1391, stddev: 0.0187 },
    note: 'mkit is about 3.1 times faster in this measurement. Each commit is crash-durable; Git does not fsync loose objects by default. mkit uses two full flushes before renaming objects into place, following Git’s core.fsyncMethod=batch design, enabled by default.',
  },
  {
    id: 'rehash-unchanged',
    theme: 'everyday',
    name: 'Re-add an unchanged 100 MiB file',
    description:
      'Run touch on the committed file to change its modification time without changing its contents, then run add to re-hash it.',
    mkit: { mean: 0.1405, stddev: 0.0074 },
    git: { mean: 0.3034, stddev: 0.0077 },
    note: 'mkit is about 2.2 times faster in this measurement. The changed modification time invalidates both stat caches, so both tools read and hash the full 100 MiB again. Git’s SHA-1 pass takes longer than mkit’s BLAKE3 pass on this CPU.',
  },
  {
    id: 'init',
    theme: 'everyday',
    name: 'Initialize an empty repository',
    description: 'mkit init vs git init in a fresh directory.',
    mkit: { mean: 0.0032, stddev: 0.0019 },
    git: { mean: 0.0025, stddev: 0.0004 },
    note: 'Both commands finish in a few milliseconds, below hyperfine’s roughly 5 ms shell calibration threshold. mkit had outliers up to about 38 ms across 365 runs. These timings do not support a reliable speed comparison.',
  },
  {
    id: 'status-unchanged',
    theme: 'everyday',
    name: 'Status with an unchanged 100 MiB file',
    description: 'mkit status / git status in a clean repo holding the committed 100 MiB file, stat cache warm.',
    mkit: { mean: 0.0026, stddev: 0.0002 },
    git: { mean: 0.0023, stddev: 0.0002 },
    note: 'Both timings are below hyperfine’s roughly 5 ms shell calibration threshold. Both tools check cached file metadata with one stat call, without reading or hashing file contents.',
  },
]

export const sizeBenchmarks: SizeBenchmark[] = [
  {
    id: 'size-big-v1',
    theme: 'large-files',
    name: 'One 100 MiB file, one commit',
    description: 'Repository size after the first commit of the 100 MiB file.',
    mkitKiB: 106160,
    gitKiB: 102604,
    note: 'Git uses slightly less storage in this measurement. zlib does not reduce the incompressible content. mkit stores roughly 1,300 chunk objects, while Git stores one loose blob. Each file uses a multiple of the filesystem’s 4 KiB block size, increasing mkit’s overhead on ext4 compared with the previous APFS measurement.',
  },
  {
    id: 'size-big-v2',
    theme: 'large-files',
    name: 'Growth after a 1 MiB change',
    description:
      'Additional repository bytes after appending 1 MiB to the 100 MiB file and committing the second version.',
    mkitKiB: 1104,
    gitKiB: 103476,
    note: 'mkit adds about 1.1 MiB: the appended data, one changed boundary chunk, and a new manifest. Git’s loose object store adds the full 101 MiB blob. After git gc, Git’s growth falls to about 1.0 MiB, similar to mkit.',
  },
  {
    id: 'size-small',
    theme: 'everyday',
    name: '100 small files, one commit',
    description: 'Repository size after committing 100 × 10 KiB of random bytes (1,000 KiB of content).',
    mkitKiB: 1600,
    gitKiB: 1704,
    note: 'Both repositories use similar storage: the content size plus per-object overhead.',
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
    name: 'Push a 16-byte edit to a 2 MiB file',
    description:
      'Edit 16 bytes in the middle of a 2 MiB FastCDC-chunked file the remote already holds, then push the new commit. Bytes counted on the wire.',
    wholeChunkBytes: 72704, // ~71 KiB: the whole re-cut FastCDC chunk
    deltaBytes: 1536, // ~1.5 KiB: chunk delta (93 B) + fresh manifest, tree, commit, packmap node
    note: 'The chunk delta is 93 bytes. The new manifest, tree, commit, and packmap node bring the transfer to about 1.5 KiB, compared with about 71 KiB for the changed chunk. Delta encoding applies only to transfers and only when it is smaller than the raw chunk. The receiver verifies each reconstructed object’s hash before storage.',
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
    '4-core Intel Xeon @ 2.10 GHz, 15 GB RAM, ext4 on a virtual disk, Linux 6.18 (Ubuntu 24.04). A shared virtualized container.',
  versions: 'mkit 0.4.1 (release build, cargo build --release) · git 2.43.0 · hyperfine 1.18.0',
  harness:
    'scripts/bench-vs-git.sh — hyperfine with --warmup and per-command --prepare resetting a temp directory to a ' +
    'clean state between runs; 3 runs for the 1 GiB case, hyperfine defaults elsewhere; results from --export-json. ' +
    'Sizes via du -k.',
  workload:
    'Random (incompressible) bytes, representing already-compressed media such as video. Compressible source code ' +
    'may compress more in Git’s zlib store and is not what these benchmarks measure.',
  caveats: [
    'Signed vs unsigned: every mkit commit is Ed25519-signed; the git side runs unsigned, as git defaults to. ' +
      'Signing costs mkit well under a millisecond per commit, but the comparison is asymmetric.',
    'Durability: mkit batches each command’s object writes using two fixed full flushes plus per-file barriers ' +
      '(SPEC-OBJECTS §10.1), so a commit is durable when the command returns; git does not fsync loose objects by ' +
      'default. Per-object flushing is available via the durability.objects = per-object config key.',
    'Results are from one shared virtualized container. Scheduling and disk contention affect timings. ' +
      'Other hardware, operating systems, and filesystems may produce different ratios. Flush costs and ' +
      'small-file block-size overhead depend on the hardware and filesystem.',
    'Both tools were run through their CLI end to end (process spawn included), with stock configuration: no git ' +
      'core.fsmonitor, no mkit tuning.',
  ],
  commands: [
    '# the whole suite is reproducible from the repo root:',
    'cargo build --release -p mkit-cli   # in rust/',
    'scripts/bench-vs-git.sh             # hyperfine JSON + sizes into ./bench-results',
  ],
} as const
