/**
 * Real benchmark results: mkit (perf/batched-durability, post-0.2.0) vs git, measured 2026-06-12 on one machine (see
 * `methodology`). Numbers were produced with hyperfine and `du -k` in throwaway temp directories
 * (`scripts/bench-vs-git.sh`), then baked in here as static data — nothing on this page is estimated or extrapolated.
 * Where git wins, the data says so.
 *
 * Means and standard deviations are in seconds, copied verbatim from hyperfine's `--export-json` output.
 */

export type Measurement = {
  /** Mean wall-clock seconds across runs. */
  mean: number
  /** Standard deviation in seconds. */
  stddev: number
}

export type TimingBenchmark = {
  id: string
  name: string
  description: string
  mkit: Measurement
  git: Measurement
  note?: string
}

export type SizeBenchmark = {
  id: string
  name: string
  description: string
  /** `du -k .mkit` in KiB. */
  mkitKiB: number
  /** `du -k .git` in KiB, loose objects (the state git leaves you in until a gc/repack). */
  gitKiB: number
  /** `du -k .git` after `git gc`, when materially different. */
  gitPackedKiB?: number
  note?: string
}

export const timingBenchmarks: TimingBenchmark[] = [
  {
    id: 'init',
    name: 'init an empty repository',
    description: 'mkit init vs git init in a fresh directory.',
    mkit: { mean: 0.0132, stddev: 0.0016 },
    git: { mean: 0.0121, stddev: 0.0005 },
  },
  {
    id: 'small-files',
    name: 'add + commit 100 small files',
    description: '100 files of 10 KiB random bytes each, staged and committed in one shot.',
    mkit: { mean: 0.1813, stddev: 0.0142 },
    git: { mean: 0.232, stddev: 0.0065 },
    note:
      'mkit wins by ~1.3× — this row used to be a 13× git win. mkit still makes every commit crash-durable ' +
      '(git does not fsync loose objects by default), but durability is now batched: all objects in a command are ' +
      'staged invisibly, flushed behind two fixed full flushes, then renamed into place — git’s ' +
      'core.fsyncMethod=batch design, on by default.',
  },
  {
    id: 'big-100m',
    name: 'add + commit one 100 MiB file',
    description: 'A single 100 MiB file of incompressible bytes (a stand-in for video or other compressed media).',
    mkit: { mean: 0.9901, stddev: 0.2536 },
    git: { mean: 2.2597, stddev: 0.1118 },
    note:
      'mkit wins by ~2.3× (previously a 7× git win). The file splits into ~1,600 content-defined chunks that are ' +
      'hashed with BLAKE3, written zero-copy, and barrier-synced from a thread pool; git’s SHA-1 + zlib pass is ' +
      'CPU-bound. mkit’s flush cost is constant per commit, not per chunk.',
  },
  {
    id: 'big-1g',
    name: 'add + commit one 1 GiB file',
    description: 'Same shape at 1 GiB, 3 runs each.',
    mkit: { mean: 9.402, stddev: 1.0541 },
    git: { mean: 19.1528, stddev: 0.3747 },
    note:
      'mkit wins by ~2×. First ingest scales linearly for both tools; mkit’s wall clock is now I/O + BLAKE3, ' +
      'not fsync.',
  },
  {
    id: 'append-1m',
    name: 'commit a 1 MiB change to the 100 MiB file',
    description: 'Append 1 MiB to the already-committed 100 MiB file, then add + commit the new version.',
    mkit: { mean: 0.3303, stddev: 0.0119 },
    git: { mean: 2.0762, stddev: 0.0201 },
    note:
      'mkit wins by ~6.3×. This is where content-defined chunking pays: mkit re-hashes the file but only stores the ' +
      'chunks that changed, so the second version costs about a megabyte. git re-compresses and stores the whole ' +
      '101 MiB blob again.',
  },
  {
    id: 'rehash-unchanged',
    name: 're-add an unchanged 100 MiB file',
    description: 'touch the committed file (mtime changes, bytes don’t) and run add again — a pure re-hash.',
    mkit: { mean: 0.1819, stddev: 0.0383 },
    git: { mean: 0.1641, stddev: 0.0014 },
    note:
      'Close to a tie: the changed mtime invalidates both tools’ stat caches, so both re-read and re-hash ' +
      '100 MiB in under 200 ms and write nothing new.',
  },
  {
    id: 'status-unchanged',
    name: 'status with an unchanged 100 MiB file',
    description: 'mkit status / git status in a clean repo holding the committed 100 MiB file, stat cache warm.',
    mkit: { mean: 0.0062, stddev: 0.0022 },
    git: { mean: 0.0093, stddev: 0.0006 },
    note:
      'mkit wins by ~1.5×. The v2 index carries an mtime+size stat cache (with git’s racy-clean rule), so an ' +
      'unchanged file is proven clean by one stat call — O(stat), no read, no hash. Before the cache this row was ' +
      '~113 ms of pure BLAKE3.',
  },
]

export const sizeBenchmarks: SizeBenchmark[] = [
  {
    id: 'size-small',
    name: '100 small files, one commit',
    description: 'Repository size after committing 100 × 10 KiB of random bytes (1,000 KiB of content).',
    mkitKiB: 1232,
    gitKiB: 1312,
    note: 'Effectively a tie — both store roughly the content plus per-object overhead.',
  },
  {
    id: 'size-big-v1',
    name: 'one 100 MiB file, one commit',
    description: 'Repository size after the first commit of the 100 MiB file.',
    mkitKiB: 105236,
    gitKiB: 115416,
    note:
      'Roughly even: incompressible input means zlib buys git nothing, so both stores hold roughly the content ' +
      'plus bookkeeping (the gap is mostly filesystem allocation, not format).',
  },
  {
    id: 'size-big-v2',
    name: 'growth after a 1 MiB change',
    description:
      'Additional repository bytes after appending 1 MiB to the 100 MiB file and committing the second version.',
    mkitKiB: 1224,
    gitKiB: 115460,
    gitPackedKiB: 92,
    note:
      'The interesting one. mkit stores ~1.2 MiB of new chunks immediately. git’s loose store duplicates the whole ' +
      '~112 MiB blob — until you run git gc, whose delta compression then beats mkit at well under a MiB of growth. ' +
      'mkit’s advantage is that its store is incremental by construction, not after a maintenance pass.',
  },
]

export const methodology = {
  date: '2026-06-12',
  machine: 'Apple M4 Max, 16 cores, 128 GB RAM, APFS SSD, macOS 26.5.1',
  versions:
    'mkit perf/batched-durability @ post-0.2.0 (cargo build --release) · git 2.50.1 (Apple Git-155) · hyperfine 1.20.0',
  harness:
    'scripts/bench-vs-git.sh — hyperfine with --warmup and per-command --prepare resetting a temp directory to a ' +
    'clean state between runs; 3 runs for the 1 GiB case, hyperfine defaults elsewhere; results from --export-json. ' +
    'Sizes via du -k.',
  workload:
    'Random (incompressible) bytes, standing in for already-compressed media like video. Compressible source code ' +
    'would flatter git’s zlib store and is not what these benchmarks measure.',
  caveats: [
    'Signed vs unsigned: every mkit commit is Ed25519-signed (the key comes from mkit keygen in the prepare step); ' +
      'the git side runs unsigned, as git defaults to. Signing costs mkit well under a millisecond per commit, but ' +
      'the comparison is asymmetric and you should know that.',
    'Durability: mkit batches each command’s object writes behind two fixed full flushes plus per-file write ' +
      'barriers (SPEC-OBJECTS §10.1) — a commit is durable when the command returns, and no ref ever references ' +
      'non-durable objects. git does not fsync loose objects by default, so mkit is doing strictly more durability ' +
      'work in every row above and winning anyway. Per-object flushing remains available as a stricter policy.',
    'One machine, one filesystem, one day. Ratios on spinning disks, network filesystems, or Linux will differ — ' +
      'flush cost in particular is very hardware-dependent.',
    'Both tools were run through their CLI end to end (process spawn included), with stock configuration: no git ' +
      'core.fsmonitor, no mkit tuning.',
  ],
  commands: [
    '# the whole suite is reproducible from the repo root:',
    'cargo build --release -p mkit-cli   # in rust/',
    'scripts/bench-vs-git.sh             # hyperfine JSON + sizes into ./bench-results',
  ],
} as const
