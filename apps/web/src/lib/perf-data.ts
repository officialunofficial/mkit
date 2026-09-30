/**
 * Real benchmark results: mkit vs git, measured 2026-09-28 on one machine (see `methodology`). Numbers were produced
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
    mkit: { mean: 0.1485, stddev: 0.0426 },
    git: { mean: 2.836, stddev: 0.127 },
    note: 'Content-defined chunking re-hashes the file but stores only changed chunks, adding about 1 MiB. Git compresses and stores the full 101 MiB blob again. File rewrite costs depend on the storage system.',
  },
  {
    id: 'big-1g',
    theme: 'large-files',
    name: 'Add and commit one 1 GiB file',
    description: 'Add and commit a 1 GiB file of incompressible bytes, with 3 runs per tool.',
    mkit: { mean: 3.5203, stddev: 1.0404 },
    git: { mean: 35.6965, stddev: 0.2242 },
    note: 'Time scales linearly with file size for both tools. mkit’s time goes to file I/O and BLAKE3 hashing. With only 3 runs, mkit’s standard deviation is large (1.04 s on a 3.52 s mean), but the ranges (2.7–4.7 s vs 35.5–36.0 s) do not overlap.',
  },
  {
    id: 'big-100m',
    theme: 'large-files',
    name: 'Add and commit one 100 MiB file',
    description: 'The file holds incompressible bytes, standing in for video or other compressed media.',
    mkit: { mean: 0.3733, stddev: 0.0429 },
    git: { mean: 2.8377, stddev: 0.2281 },
    note: 'mkit divides the file into roughly 1,300 chunks, hashes each with BLAKE3, and syncs writes to disk from a thread pool. Git’s SHA-1 hashing and zlib compression are CPU-bound. Run-to-run variation was lower in this measurement (a 43 ms standard deviation on a 373 ms mean), but shared disk I/O still affects these timings.',
  },
  {
    id: 'small-files',
    theme: 'everyday',
    name: 'Add and commit 100 small files',
    description: '100 files of 10 KiB random bytes each, staged and committed together.',
    mkit: { mean: 0.0552, stddev: 0.0086 },
    git: { mean: 0.1327, stddev: 0.0159 },
    note: 'mkit makes each commit crash-durable by default with two full flushes before renaming objects into place, following Git’s core.fsyncMethod=batch design. Git does not fsync loose objects by default.',
  },
  {
    id: 'rehash-unchanged',
    theme: 'everyday',
    name: 'Re-add an unchanged 100 MiB file',
    description:
      'Run touch on the committed file to change its modification time without changing its contents, then run add to re-hash it.',
    mkit: { mean: 0.1087, stddev: 0.0102 },
    git: { mean: 0.2597, stddev: 0.0439 },
    note: 'The changed modification time invalidates both stat caches, so both tools read and hash the full 100 MiB again. Git’s SHA-1 pass takes longer than mkit’s BLAKE3 pass on this CPU.',
  },
  {
    id: 'init',
    theme: 'everyday',
    name: 'Initialize an empty repository',
    description: 'mkit init vs git init in a fresh directory.',
    mkit: { mean: 0.0033, stddev: 0.0007 },
    git: { mean: 0.0038, stddev: 0.0007 },
    note: 'Both commands finish in a few milliseconds, below hyperfine’s roughly 5 ms shell calibration threshold. mkit’s slowest run was about 7 ms across 332 runs. These timings do not support a reliable speed comparison.',
  },
  {
    id: 'status-unchanged',
    theme: 'everyday',
    name: 'Status with an unchanged 100 MiB file',
    description:
      'mkit status and git status in a clean repository containing the committed 100 MiB file, with a warm stat cache.',
    mkit: { mean: 0.003, stddev: 0.0006 },
    git: { mean: 0.0025, stddev: 0.0007 },
    note: 'Both timings are below hyperfine’s roughly 5 ms shell calibration threshold. Both tools check cached file metadata with one stat call, without reading or hashing file contents.',
  },
  {
    id: 'checkout-100m',
    theme: 'large-files',
    name: 'Checkout a branch that changed a 100 MiB file',
    description:
      'main has a committed 100 MiB file; branch v2 appends 1 MiB to it. Measures checking out v2 from main.',
    mkit: { mean: 0.4118, stddev: 0.1659 },
    git: { mean: 0.3613, stddev: 0.0457 },
    note: 'In this measurement git is about 14% faster, but mkit’s standard deviation is 166 ms on a 412 ms mean (runs ranged from 261 to 783 ms), so the two overlap and the data does not support a reliable winner. On 2026-09-19 a separate run (mkit commit d7afae5, same container class) measured mkit about 6% faster; the two runs disagree, which is consistent with noise. Restoring a ChunkedBlob writes every chunk to one shared file sequentially, and only each chunk’s read-and-verify step runs in parallel. cargo bench -p mkit-benches --bench restore_chunk_fanout measures that step alone: a 128 MiB restore’s chunk-read phase drops from 115.3 ms to 83.2 ms (about 28%). This row measures the full add, commit, checkout, and git process-spawn round trip end to end.',
  },
]

export const sizeBenchmarks: SizeBenchmark[] = [
  {
    id: 'size-big-v1',
    theme: 'large-files',
    name: 'One 100 MiB file, one commit',
    description: 'Repository size after the first commit of the 100 MiB file.',
    mkitKiB: 106100,
    gitKiB: 102604,
    note: 'Git uses slightly less storage in this measurement. zlib does not reduce the incompressible content. mkit stores roughly 1,300 chunk objects, while Git stores one loose blob. Each file occupies whole 4 KiB filesystem blocks, so mkit’s chunk files add more overhead on ext4 than in the previous APFS measurement.',
  },
  {
    id: 'size-big-v2',
    theme: 'large-files',
    name: 'Growth after a 1 MiB change',
    description:
      'Additional repository bytes after appending 1 MiB to the 100 MiB file and committing the second version.',
    mkitKiB: 1232,
    gitKiB: 103476,
    note: 'mkit adds about 1.2 MiB: the appended data, one changed boundary chunk, and a new manifest. Git’s loose object store adds the full 101 MiB blob. After git gc, Git’s growth falls to about 1.0 MiB, similar to mkit.',
  },
  {
    id: 'size-small',
    theme: 'everyday',
    name: '100 small files, one commit',
    description: 'Repository size after committing 100 × 10 KiB of random bytes (1,000 KiB of content).',
    mkitKiB: 1612,
    gitKiB: 1692,
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

/**
 * Criterion microbenchmarks of one mkit core path, before vs after a change. Unlike the rows above there is no Git
 * baseline: these track mkit against its own previous commit. Medians in milliseconds, copied from criterion's
 * `--baseline` comparison output.
 */
export type MicroBenchmark = {
  id: string
  name: string
  description: string
  beforeMs: number
  afterMs: number
  note?: string
}

export const microBenchmarks: MicroBenchmark[] = [
  {
    id: 'list-refs-100',
    name: 'List 100 branch refs',
    description: 'list_refs over 100 ref files on a warm page cache.',
    beforeMs: 0.2203,
    afterMs: 0.1699,
  },
  {
    id: 'list-refs-1k',
    name: 'List 1,000 branch refs',
    description: 'list_refs over 1,000 ref files on a warm page cache.',
    beforeMs: 2.5926,
    afterMs: 2.2149,
  },
  {
    id: 'list-refs-10k',
    name: 'List 10,000 branch refs',
    description: 'list_refs over 10,000 ref files on a warm page cache.',
    beforeMs: 28.943,
    afterMs: 22.236,
    note: 'Measured 2026-09-28 with cargo bench -p mkit-benches --bench refs_ops on the same class of 4-core container as the methodology below. Each ref file is now read with one stack-buffer read (open, read, close) instead of fs::read, which adds a size-hint statx and an end-of-file probe read. About 23% faster at 10,000 refs and 25% at 100; the 1,000-ref run shows 15%.',
  },
]

export const methodology = {
  date: '2026-09-28',
  /**
   * Full SHA of the mkit commit the benchmarked binary was built from — not merely the date, which is easy to
   * mis-anchor (see #607: two investigations chased the wrong baseline because "measured 2026-06-12" undershot PR #341,
   * which merged two days later and changed every timing on this page). `scripts/bench-vs-git.sh` emits the same field
   * for future re-measures; keep this in sync with whatever it records.
   */
  commit: 'a693e2ebd5e2af4e00aa57a739c2e9a32c81a7a3',
  machine:
    '4-core Intel Xeon @ 2.10 GHz, 15 GB RAM, ext4 on a virtual disk, Linux 6.18 (Ubuntu 24.04). A shared virtualized container.',
  versions: 'mkit 0.4.2 (release build, cargo build --release) · git 2.43.0 · hyperfine 1.20.0',
  harness:
    'scripts/bench-vs-git.sh — hyperfine with --warmup and per-command --prepare resetting a temp directory to a ' +
    'clean state between runs; 3 runs for the 1 GiB case, hyperfine defaults elsewhere; results from --export-json. ' +
    'Sizes via du -k.',
  workload:
    'Random (incompressible) bytes, representing already-compressed media such as video. Compressible content such ' +
    'as source code may compress better in Git’s zlib store; these benchmarks do not measure it.',
  caveats: [
    'Signing: every mkit commit is Ed25519-signed; Git commits are unsigned, which is Git’s default. ' +
      'Signing adds well under a millisecond per mkit commit, but the two sides do different work.',
    'Durability: mkit batches each command’s object writes using two fixed full flushes plus per-file barriers ' +
      '(SPEC-OBJECTS §10.1), so a commit is durable when the command returns; Git does not fsync loose objects by ' +
      'default. To flush each object individually, set durability.objects = per-object.',
    'Results are from one shared virtualized container. Scheduling and disk contention affect timings. ' +
      'Other hardware, operating systems, and filesystems may produce different ratios. Flush costs and ' +
      'small-file block-size overhead depend on the hardware and filesystem.',
    'Both tools ran as CLI processes end to end, including process startup, with default configuration: no Git ' +
      'core.fsmonitor and no mkit tuning.',
  ],
  commands: [
    '# the whole suite is reproducible from the repo root:',
    'cargo build --release -p mkit-cli   # in rust/',
    'scripts/bench-vs-git.sh             # hyperfine JSON + sizes into ./bench-results',
  ],
} as const
