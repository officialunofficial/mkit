/**
 * Real benchmark results: mkit 0.2.0 vs git, measured 2026-06-11 on one machine (see `methodology`). Numbers were
 * produced with hyperfine and `du -k` in throwaway temp directories, then baked in here as static data — nothing on
 * this page is estimated or extrapolated. Where git wins, the data says so.
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
    mkit: { mean: 0.0134, stddev: 0.0009 },
    git: { mean: 0.014, stddev: 0.0029 },
  },
  {
    id: 'small-files',
    name: 'add + commit 100 small files',
    description: '100 files of 10 KiB random bytes each, staged and committed in one shot.',
    mkit: { mean: 1.0987, stddev: 0.1868 },
    git: { mean: 0.0816, stddev: 0.0039 },
    note:
      'git wins by ~13×. Almost none of mkit’s time is CPU: mkit fsyncs every object write for crash durability, ' +
      'while git does not fsync loose objects by default. That’s a durability-for-speed trade, not free speed — ' +
      'but the wall-clock cost is real and it’s mkit paying it.',
  },
  {
    id: 'big-100m',
    name: 'add + commit one 100 MiB file',
    description: 'A single 100 MiB file of incompressible bytes (a stand-in for video or other compressed media).',
    mkit: { mean: 13.4628, stddev: 0.389 },
    git: { mean: 1.95, stddev: 0.0143 },
    note:
      'git wins by ~7×. Same fsync story at larger scale: mkit’s first ingest splits the file into a few thousand ' +
      'content-defined chunks and durably syncs each one; git’s SHA-1 + zlib pass is CPU-bound but unsynced.',
  },
  {
    id: 'big-1g',
    name: 'add + commit one 1 GiB file',
    description: 'Same shape at 1 GiB, 3 runs each.',
    mkit: { mean: 150.1651, stddev: 9.7727 },
    git: { mean: 19.3469, stddev: 0.3937 },
    note: 'git wins by ~7.8×. First ingest scales linearly for both tools; mkit’s per-chunk fsync dominates.',
  },
  {
    id: 'append-1m',
    name: 'commit a 1 MiB change to the 100 MiB file',
    description: 'Append 1 MiB to the already-committed 100 MiB file, then add + commit the new version.',
    mkit: { mean: 0.3108, stddev: 0.0096 },
    git: { mean: 2.116, stddev: 0.2305 },
    note:
      'mkit wins by ~7×. This is where content-defined chunking pays: mkit re-hashes the file but only stores the ' +
      'chunks that changed, so the second version costs about a megabyte. git re-compresses and stores the whole ' +
      '101 MiB blob again.',
  },
  {
    id: 'rehash-unchanged',
    name: 're-add an unchanged 100 MiB file',
    description: 'touch the committed file (mtime changes, bytes don’t) and run add again — a pure re-hash.',
    mkit: { mean: 0.1197, stddev: 0.003 },
    git: { mean: 0.1629, stddev: 0.0013 },
    note:
      'Close to a tie. BLAKE3 out-hashes hardware-accelerated SHA-1 here, but both tools detect “nothing changed” ' +
      'in under 200 ms with no new writes.',
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
    mkitKiB: 105036,
    gitKiB: 114844,
    note:
      'Roughly even: incompressible input means zlib buys git nothing, so both stores hold roughly the content ' +
      'plus bookkeeping (the gap is mostly filesystem allocation, not format).',
  },
  {
    id: 'size-big-v2',
    name: 'growth after a 1 MiB change',
    description:
      'Additional repository bytes after appending 1 MiB to the 100 MiB file and committing the second version.',
    mkitKiB: 1148,
    gitKiB: 115120,
    gitPackedKiB: 92,
    note:
      'The interesting one. mkit stores ~1.1 MiB of new chunks immediately. git’s loose store duplicates the whole ' +
      '~112 MiB blob — until you run git gc, whose delta compression then beats mkit at just 92 KiB of growth. ' +
      'mkit’s advantage is that its store is incremental by construction, not after a maintenance pass.',
  },
]

export const methodology = {
  date: '2026-06-11',
  machine: 'Apple M4 Max, 16 cores, 128 GB RAM, APFS SSD, macOS 26.5.1',
  versions: 'mkit 0.2.0 (cargo build --release) · git 2.50.1 (Apple Git-155) · hyperfine 1.20.0',
  harness:
    'hyperfine with --warmup and per-command --prepare resetting a temp directory to a clean state between runs; ' +
    '5–100+ runs per benchmark, 3 runs for the 1 GiB case; results from --export-json. Sizes via du -k.',
  workload:
    'Random (incompressible) bytes, standing in for already-compressed media like video. Compressible source code ' +
    'would flatter git’s zlib store and is not what these benchmarks measure.',
  caveats: [
    'Signed vs unsigned: every mkit commit is Ed25519-signed (the key comes from mkit keygen in the prepare step); ' +
      'the git side runs unsigned, as git defaults to. Signing costs mkit well under a millisecond per commit, but ' +
      'the comparison is asymmetric and you should know that.',
    'Durability vs speed: mkit fsyncs every object write; git does not fsync loose objects by default. This is most ' +
      'of why git wins the bulk-ingest rows. Equalising it (core.fsync=committed on the git side) would slow git; ' +
      'we benchmarked both tools as configured out of the box.',
    'One machine, one filesystem, one day. Ratios on spinning disks, network filesystems, or Linux will differ — ' +
      'fsync cost in particular is very hardware-dependent.',
    'Both tools were run through their CLI end to end (process spawn included), with stock configuration: no git ' +
      'core.fsmonitor, no mkit tuning.',
  ],
  commands: [
    '# init',
    "hyperfine --warmup 2 --prepare 'rm -rf work && mkdir work' \\",
    "  'cd work && mkit init'  'cd work && git init -q'",
    '',
    '# 100 small files (prepare re-creates the repo and copies the files in)',
    "mkit:  prepare = 'mkit init && mkit keygen'   run = 'mkit add . && mkit commit -m bench'",
    "git:   prepare = 'git init -q && git config user.*'   run = 'git add . && git commit -q -m bench'",
    '',
    '# large files: same shape with one 100 MiB / 1 GiB file of /dev/urandom bytes',
    '# append: cat 1MiB >> video.bin between prepare and run, against a pre-committed v1',
    "# unchanged: prepare = 'touch video.bin'   run = 'mkit add video.bin' / 'git add video.bin'",
    '',
    '# sizes',
    'du -k .mkit   du -k .git   (git gc -q before the packed number)',
  ],
} as const
