/**
 * Real benchmark results: mkit vs git, measured 2026-06-12 on one machine (see `methodology`). Numbers were produced
 * with hyperfine and `du -k` in throwaway temp directories (`scripts/bench-vs-git.sh`), then baked in here as static
 * data — nothing on this page is estimated or extrapolated. Where git wins, the data says so.
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
  /** `du -k .mkit` in KiB — an absolute size, or growth, per the row's `description`. */
  mkitKiB: number
  /** `du -k .git` in KiB, loose objects (the state git leaves you in until a gc/repack) — same convention as `mkitKiB`. */
  gitKiB: number
  /**
   * `.git` after `git gc`, same measurement convention as `gitKiB` for the row (absolute total for the size rows;
   * growth = v2 packed total − v1 packed total for the growth row). Emitted by `bench-vs-git.sh` as `size-big-v2 git
   * packed growth KiB`. Omitted when not materially different.
   */
  gitPackedKiB?: number
  note?: string
}

export const timingBenchmarks: TimingBenchmark[] = [
  {
    id: 'init',
    name: 'init an empty repository',
    description: 'mkit init vs git init in a fresh directory.',
    mkit: { mean: 0.0131, stddev: 0.0007 },
    git: { mean: 0.0119, stddev: 0.0009 },
  },
  {
    id: 'small-files',
    name: 'add + commit 100 small files',
    description: '100 files of 10 KiB random bytes each, staged and committed in one shot.',
    mkit: { mean: 0.1663, stddev: 0.0141 },
    git: { mean: 0.2205, stddev: 0.0055 },
    note:
      'mkit wins by ~1.3× while making every commit crash-durable (git does not fsync loose objects by default). ' +
      'Durability is batched: all objects in a command are staged invisibly, flushed behind two fixed full flushes, ' +
      'then renamed into place — git’s core.fsyncMethod=batch design, on by default.',
  },
  {
    id: 'big-100m',
    name: 'add + commit one 100 MiB file',
    description: 'A single 100 MiB file of incompressible bytes (a stand-in for video or other compressed media).',
    mkit: { mean: 0.6399, stddev: 0.0529 },
    git: { mean: 2.0037, stddev: 0.0121 },
    note:
      'mkit wins by ~3.1×. The file splits into ~1,600 content-defined chunks that are hashed with BLAKE3, written ' +
      'zero-copy, and barrier-synced from a thread pool; git’s SHA-1 + zlib pass is CPU-bound. mkit’s flush cost is ' +
      'constant per commit, not per chunk.',
  },
  {
    id: 'big-1g',
    name: 'add + commit one 1 GiB file',
    description: 'Same shape at 1 GiB, 3 runs each.',
    mkit: { mean: 4.4803, stddev: 0.2679 },
    git: { mean: 18.7992, stddev: 0.4621 },
    note: 'mkit wins by ~4.2×. First ingest scales linearly for both tools; mkit’s wall clock is I/O + BLAKE3.',
  },
  {
    id: 'append-1m',
    name: 'commit a 1 MiB change to the 100 MiB file',
    description: 'Append 1 MiB to the already-committed 100 MiB file, then add + commit the new version.',
    mkit: { mean: 0.2495, stddev: 0.0077 },
    git: { mean: 1.9642, stddev: 0.0199 },
    note:
      'mkit wins by ~7.9×. This is where content-defined chunking pays: mkit re-hashes the file but only stores the ' +
      'chunks that changed, so the second version costs about a megabyte. git re-compresses and stores the whole ' +
      '101 MiB blob again.',
  },
  {
    id: 'rehash-unchanged',
    name: 're-add an unchanged 100 MiB file',
    description: 'touch the committed file (mtime changes, bytes don’t) and run add again — a pure re-hash.',
    mkit: { mean: 0.1463, stddev: 0.0053 },
    git: { mean: 0.1624, stddev: 0.0012 },
    note:
      'Close to a tie: the changed mtime invalidates both tools’ stat caches, so both re-read and re-hash ' +
      '100 MiB in under 200 ms and write nothing new.',
  },
  {
    id: 'status-unchanged',
    name: 'status with an unchanged 100 MiB file',
    description: 'mkit status / git status in a clean repo holding the committed 100 MiB file, stat cache warm.',
    mkit: { mean: 0.008, stddev: 0.0014 },
    git: { mean: 0.0086, stddev: 0.0006 },
    note:
      'A tie. The index carries a stat cache (mtime, size, inode, ctime, plus git’s racy-clean rule), so an ' +
      'unchanged file is proven clean by one stat call: O(stat), no read, no hash — the same trick git plays.',
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
    mkitKiB: 105084,
    gitKiB: 115272,
    note:
      'Roughly even: incompressible input means zlib buys git nothing, so both stores hold roughly the content ' +
      'plus bookkeeping (the gap is mostly filesystem allocation, not format).',
  },
  {
    id: 'size-big-v2',
    name: 'growth after a 1 MiB change',
    description:
      'Additional repository bytes after appending 1 MiB to the 100 MiB file and committing the second version.',
    mkitKiB: 1116,
    gitKiB: 114900,
    gitPackedKiB: 0,
    note:
      'The interesting one. mkit stores ~1.1 MiB immediately: the appended megabyte (incompressible — a floor no store ' +
      'can beat), one re-cut boundary chunk, and a fresh chunk manifest. git’s loose store duplicates the whole ' +
      '~112 MiB blob until you run git gc, which then repacks both versions (the old one as a tiny delta against ' +
      'the new), netting the growth to ~zero against the loose baseline. mkit’s store is incremental by ' +
      'construction, no maintenance pass required; git’s density arrives only after one.',
  },
]

export type TransferBenchmark = {
  id: string
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
    name: 'push a 16-byte edit to a 2 MiB file',
    description:
      'Edit 16 bytes in the middle of a 2 MiB FastCDC-chunked file the remote already holds, then push the new commit. Bytes counted on the wire.',
    wholeChunkBytes: 72704, // ~71 KiB: the whole re-cut FastCDC chunk
    deltaBytes: 1536, // ~1.5 KiB: chunk delta (93 B) + fresh manifest, tree, commit, packmap node
    note:
      'Before this change the push re-sent the entire re-cut ~71 KiB chunk; with delta encoding the chunk delta itself ' +
      'is 93 bytes and the whole push is ~1.5 KiB — the rest is the new chunk manifest, tree, commit, and packmap ' +
      'node. Identical objects are deduped before a delta is even considered, and a delta is only used when it beats ' +
      'sending the chunk raw, so correctness never depends on the heuristic. Content addressing is unchanged: delta is ' +
      'a transfer encoding only, and every reconstructed object is re-verified against its hash before it is stored.',
  },
]

export const methodology = {
  date: '2026-06-12',
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
    'Signed vs unsigned: every mkit commit is Ed25519-signed (the key comes from mkit keygen in the prepare step); ' +
      'the git side runs unsigned, as git defaults to. Signing costs mkit well under a millisecond per commit, but ' +
      'the comparison is asymmetric and you should know that.',
    'Durability: mkit batches each command’s object writes behind two fixed full flushes plus per-file write ' +
      'barriers (SPEC-OBJECTS §10.1) — a commit is durable when the command returns, and no ref ever references ' +
      'non-durable objects. git does not fsync loose objects by default, so every row above has mkit doing strictly ' +
      'more durability work. Per-object flushing is available via the durability.objects = per-object config key.',
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
