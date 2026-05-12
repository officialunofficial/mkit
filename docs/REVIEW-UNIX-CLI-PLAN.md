# Review follow-up: investigation findings & remediation plan

Companion to `docs/REVIEW-UNIX-CLI.md`. The first document was the
review; this one is the deeper investigation that turns it into a
concrete sequence of PRs. Each section below corresponds to one
finding in the review and is grounded in a code sweep across the
workspace.

The headline change from the original review: **two findings got
bigger, two got cheaper.**

- The SIGINT/SIGTERM half of the HIGH finding is *also* aspirational —
  not just SIGPIPE. The poll-loop checkpoints have zero call sites.
- The stdout-prose finding spans 16 files, not 2. The blast radius is
  ~3× what the review estimated.
- The SIGPIPE-ignore fix is a 2-line patch — `libc` is already a `cfg(unix)`
  dep, no new crates required.
- The clap migration is cheaper than feared: `HELP_TEXT` is NOT pinned
  byte-exact by any test, only by substring assertions.

---

## 1. Signals (HIGH) — bigger than the review claimed

The poll-loop checkpoints documented in `docs/CLI.md` §Signals are also
unimplemented. `signal::is_shutdown()` / `signal::interrupted()` have
**zero call sites outside `signal.rs` itself**.

Hot loops that should be polling but aren't:

| File | Loop | Effect |
|------|------|--------|
| `remote_dispatch.rs:204-288` | `fetch_object_closure` BFS — downloads every reachable object | `Ctrl-C` during a clone keeps downloading until done |
| `remote_dispatch.rs:113-147` | `push_all` per-object upload | `Ctrl-C` during push keeps uploading |
| `remote_dispatch.rs:174-197` | `fetch_all` per-ref iteration | same |
| `commands/log.rs:51-86` | unbounded commit-walk; the prime SIGPIPE victim | `mkit log \| head -1` against any non-trivial history gets killed by kernel SIGPIPE |

### Patch sketch (zero new deps)

`libc = "0.2"` is already a `[target.'cfg(unix)'.dependencies]` in
`rust/crates/mkit-cli/Cargo.toml:76`. The `#![deny(unsafe_code)]` at
`lib.rs:17` is `deny`, not `forbid`, so a targeted `#[allow]` block is
valid — and `config.rs:283-302` (`getpwuid_r` opt-in) already
establishes the SAFETY-comment pattern to copy.

```rust
// signal.rs
pub fn install() {
    #[cfg(unix)]
    {
        // SAFETY: ignoring SIGPIPE is well-defined on POSIX. `SIG_IGN`
        // is a documented constant, not a function pointer; `libc::signal`
        // is async-signal-safe. No Rust memory is touched. Same pattern
        // as the getpwuid_r opt-in at config.rs:283.
        #[allow(unsafe_code)]
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }
    }
}
```

Then add `if crate::signal::is_shutdown() { return Err(...); }` at the
top of each of the four loops above. A new
`DispatchError::Interrupted` variant in `remote_dispatch.rs` maps
cleanly to `exit::TEMPFAIL` (75), which is exactly what the docs
already promise.

### Test plan

No SIGPIPE/SIGINT integration test exists today. Add one in
`rust/crates/mkit-cli/tests/`: spawn `mkit log` into a pipe whose read
end closes after one line; assert the exit status is `0` (or `13` if
we choose to propagate), **never** `141`. This is the regression guard
that would have caught the gap originally.

### `signal-hook` deferral remains correct

For SIGINT/SIGTERM the module's TODO is still the right call —
`signal-hook` pulls in ~3 transitive crates (`signal-hook-registry`,
`arc-swap`) and the cooperative checkpoint pattern is enough for now.
Wire SIGPIPE first because it is the active breakage; queue SIGINT
behind the checkpoint additions.

---

## 2. stdout/stderr discipline (MEDIUM) — 16 files, not 2

The audit found **41 stdout-prose sites and 3 silent-failure sites
across 16 files**. The clean-stdout commands are `diff`, `cat`, `tree`,
`hash`, `blame`, `tag`, `rm` — i.e. everything that already does one
thing on data and exits.

### Silent-failure sites (fix first — these print errors and exit 0)

| File | Line | Issue | Correct exit |
|------|------|-------|--------------|
| `log.rs` | 59-62 | `(read error: …)` → break → `exit::OK` | `exit::DATAERR` |
| `log.rs` | 64-67 | `(not a commit: …)` → break → `exit::OK` | `exit::DATAERR` |
| `bisect.rs` | 119-123 | `bisect skip: no current candidate` → `exit::OK` | `exit::USAGE` |

### Stdout-prose sites (route to stderr)

Counts per file, prioritised by likely scripting use:

| File | Sites | Notes |
|------|-------|-------|
| `status.rs` | 7 | branch banners, "nothing to commit", section headers |
| `bisect.rs` | 6 | progress + result lines |
| `keygen.rs` | 3 algorithms × 2 lines | "generated …", "public: …", "identity: …" |
| `stash.rs` | 4 | "stashed:", "popped", "dropped", "(no stash entries)" |
| `merge.rs` | 3 | "already up to date", "fast-forward", "merged" |
| `checkout.rs` | 3 | "switched to branch", file-count line |
| `rebase.rs` | 2 | "rebase aborted", "rebased N commit(s)" |
| `push.rs`, `pull.rs`, `fetch.rs`, `clone.rs`, `init.rs`, `cherry_pick.rs`, `sparse_checkout.rs`, `remote.rs`, `commit.rs`, `attest.rs`, `log.rs` | 1-2 each | confirmations / status |

Plus one stream-direction oddity:

- `config_cmd.rs:77-83` — success confirmation **on stderr** ("wrote
  `<key>` to user-scoped config at …"). Direction is wrong; this is
  status, belongs on stderr only if we treat it as diagnostic.
  Actually consistent with the rule "stderr is for the human", so
  this one is defensible — but worth a comment so a future cleanup
  doesn't "fix" it.

And one mixed-stream case:

- `verify_attest.rs:156,165,213` — per-attestation read errors and
  malformed-envelope errors go to stdout; the final
  `bad: at least one attestation failed verification` is also stdout.
  Exit code is correctly `exit::DATAERR`, so this isn't silent-failure,
  but `mkit verify-attest | jq` (after the JSON work below) would
  choke on the prose. Move all diagnostic prose to stderr.

### Recommended PR shape

One PR per command cluster, ordered by audit coverage:

1. **silent-failure fixes** (`log.rs`, `bisect.rs`) — smallest, highest signal.
2. **`status.rs`** — biggest single beneficiary, paired with `--porcelain=v1` below.
3. **transport commands** (`push.rs`, `pull.rs`, `fetch.rs`, `clone.rs`) — all 1-line changes.
4. **history-mutation commands** (`commit.rs`, `checkout.rs`, `merge.rs`, `rebase.rs`, `cherry_pick.rs`) — bundle.
5. **`stash.rs` + `bisect.rs` + `verify_attest.rs`** — bundle.
6. **`keygen.rs`** — touchy because users may be scraping the
   "public: …" line; introduce `--porcelain` simultaneously and
   deprecate the current shape with a one-version overlap.

Each PR also needs to update the corresponding integration tests in
`tests/cli_wire.rs` and especially `tests/status_integration.rs`,
which contains 17 string-contains assertions against English status
prose. Those tests are the actual blocker — they pin the bad behavior
in place.

---

## 3. Machine-readable output (MEDIUM) — clear consumer map

The actual consumers of mkit stdout in this repo are:

| Consumer | What it parses | Hardness |
|----------|---------------|----------|
| `.github/workflows/rust.yml:113-119` | `mkit version` byte-exact | Already pinned, no change needed |
| `rust/crates/mkit-cli/tests/version_snapshot.rs:18-39` | same | same |
| `rust/crates/mkit-cli/tests/cli_wire.rs:125-130, 165-170` | `merge` / `rebase` English ("fast-forward", "rebased") | Substring — fragile |
| `rust/crates/mkit-cli/tests/cli_wire.rs:233-243` | `blame` tab-delimited format | **Accidental porcelain contract** — formalise it |
| `rust/crates/mkit-cli/tests/status_integration.rs` (17 sites) | English status prose | Fragile; switch to `--porcelain` |
| `install.sh:320` | `mkit version` — just prints, no parse | None |
| `contrib/signers/mkit-sign-{se,ctap,tpm}/tests/e2e.sh` | Each signer's own JSON, not mkit core | None |

Conclusion: the only real external consumer is CI's version assertion,
which already works. Every other parsing consumer is *inside* the test
suite — meaning the tests themselves are the de-facto contract today,
and they pin English prose. **Adding `--porcelain` simultaneously
fixes the tests and the contract.**

### Per-command schemas

| Command | Mode | Shape |
|---------|------|-------|
| `mkit status --porcelain=v1` | git-compatible | `XY <path>\n` per file; `DiffKind::Added\|Removed\|Modified\|ModeChanged` → `A/D/M/T`; `PartiallyStaged` → `MM` |
| `mkit log --format=json` | JSONL | `{hash, parents[], author, timestamp, title}` per commit |
| `mkit blame --format=json` | JSONL | `{hash, line_num, text}` per line (formalises the tab format in `cli_wire.rs:233-243`) |
| `mkit branch --format=json` | JSONL | `{name, current, hash}` per branch |
| `mkit remote --format=json` | JSONL | `{url, transport}` per remote |
| `mkit config --format=json` | object | flat `{key: value}` |

### Git-compatibility judgement

**Follow git's `--porcelain=v1` for `mkit status`. Diverge for log /
blame / branch.** `git status --porcelain` is understood by every
editor plugin and CI harness in existence; mkit's `DiffKind` maps 1-1
to git's XY codes. But mkit's commit author is an Identity wire string
(`ed25519:<hex>` / `mid:<N>`), not `Name <email>` — stuffing it into
git's author line would be lossy and misleading. JSONL there.

### Reusable pinning pattern

`mkit version` is locked at three layers: `build.rs` (compile time),
`tests/version_snapshot.rs` (test time), `.github/workflows/rust.yml`
(CI time). Each porcelain contract should get the same triple lock.

### Phasing

1. **PR 1:** `mkit status --porcelain=v1`. Migrate `status_integration.rs`
   to assert the porcelain output. This is the unlock for the §2
   stderr cleanup — the integration tests stop pinning English.
2. **PR 2:** `mkit log --format=json`. Update `cli_wire.rs` to assert JSON.
3. **PR 3:** `mkit blame --format=json`. Migrate the existing tab-format test.
4. **PR 4:** `mkit branch --format=json` + `mkit remote --format=json`.
5. **PR 5 (0.2 milestone):** `mkit config --format=json`.

---

## 4. Clap migration (MEDIUM) — strangler, ~12–14 PRs

### Complexity tiers

**Top 5** (each warrants its own PR):

1. **`attest`** — 7 flags, including `--additional-signer "alg=…,signer=…,path=…"` mini-DSL inside a repeatable flag. clap's `value_delimiter` can't express this; needs a custom `value_parser`.
2. **`commit`** — fused `-am<msg>` form (`commit.rs:187,197`) has no native clap analogue.
3. **`stash`** — 5 subcommands plus bare-invocation default-subcommand alias (`stash.rs:24`).
4. **`keygen`** — `--algorithm ed25519|secp256k1|p256` enum + algorithm-discriminated branches.
5. **`verify-attest`** — clap surface is small, but the TOML trust-roots reader is hand-rolled (orthogonal to clap).

**Runners-up:** `rebase` (positional-or-flag: `<branch>` | `--continue` | `--abort`), `bisect` (5 subcommands), `config` (positional `<key> [value]`), `remote` (2 subcommands), `clone` (stub-rejected `--depth`/`--sparse`).

**Trivial** (~22 commands): `init`, `cat`, `hash`, `tree`, `add`, `rm`,
`status`, `diff`, `verify`, `push`, `pull`, `fetch`, `checkout`, `tag`,
`blame`, `serve`, `cherry-pick`, `merge` — ~2/3 of the surface is one
`#[derive(Parser)]` struct apiece.

### Snapshot impact

| File | What it pins | clap-compat? |
|------|--------------|--------------|
| `tests/version_snapshot.rs:18-38` | `mkit X.Y.Z\n` byte-exact, empty stderr | ✓ if `version` stays in the dispatcher (don't delegate to clap's `--version`) |
| `tests/help_snapshot.rs:46-58` | 29 subcommand names appear in `--help` | ✓ clap auto-includes |
| `tests/help_snapshot.rs:72-83` | **Unknown subcommand exits 64** | ✗ clap defaults to exit 2 — must override before migrating |
| `cli.rs:110-152` | substring presence of subcommand names | ✓ |

**No byte-exact assertion exists on the full `HELP_TEXT` block.** The
prose in `cli.rs:5-7` about Homebrew/Scoop stability is real for
`mkit version` but unsubstantiated for `--help`. Confirm with the
docs maintainer before assuming the help block can change shape.

### Strangler approach

PR 0 (setup, blocking everything else):
- Add `clap = { version = "...", features = ["derive"] }` to `mkit-cli/Cargo.toml`.
- Configure a `clap::Command` wrapper with `.error_exit_code(exit::USAGE)` so unknown subcommands stay at 64.
- Map clap's `ErrorKind` variants to mkit's sysexits constants (`InvalidValue` → `DATAERR`, `MissingRequiredArgument` → `USAGE`, etc.).
- Keep the `match argv[1]` dispatcher and `mkit version` arm intact.
- No command migrated yet. This PR exists to land the exit-code shim.

PRs 1–10 (one per command or small cluster):
- Migrate trivial commands in clusters of 3–4 (`init`+`cat`+`hash`+`tree`, etc.).
- Each complex command (attest, commit, stash, keygen, verify-attest) gets its own PR.
- Each PR updates its command's integration tests and runs the full snapshot suite.

### Top risk: exit-code drift

Two specific traps:

1. **Top-level exit-2 trap.** If PR 0 forgets `.error_exit_code(exit::USAGE)`,
   `tests/help_snapshot.rs:81` (`assert_eq!(output.status.code(), Some(64))`)
   fails immediately. Land the exit-code shim *before* migrating any command.

2. **Per-command sysexits split.** Some commands return different exit
   codes for different argument errors — `attest.rs:89` returns
   `exit::DATAERR` for a malformed `--commit` hash but `exit::USAGE` for
   a missing flag. clap collapses both into one `ErrorKind`; preserving
   the split requires routing through clap for *shape* errors and doing
   post-parse validation for *value* errors. Every migrated command's
   PR must include an exit-code matrix in its description so reviewers
   can verify the contract.

The `mkit version` byte-exact contract is also at risk but trivially
avoidable: keep `"version"` as a literal arm in the dispatcher; never
let clap own `--version`.

---

## Consolidated sequencing

Rolled up across all four findings:

1. **PR 1 (HIGH):** SIGPIPE-ignore in `signal::install()`; add checkpoint
   polls to the 4 hot loops. No new deps. Adds one integration test.
2. **PR 2 (MEDIUM):** Silent-failure fixes in `log.rs` + `bisect.rs`.
   Three lines, three correct exit codes.
3. **PR 3 (MEDIUM):** `mkit status --porcelain=v1` + migrate
   `status_integration.rs` to assert porcelain. Unlocks PR 4.
4. **PR 4 (MEDIUM):** Route status-prose to stderr across the
   transport + history-mutation commands (cluster).
5. **PR 5 (MEDIUM):** `mkit log --format=json` + `cli_wire.rs` migration.
6. **PR 6 (setup, blocks 7+):** Clap shim with sysexits mapping. No commands.
7. **PRs 7–N:** Strangler migration, one command-cluster at a time,
   each with its own exit-code matrix.

PRs 1–5 are all small and independently shippable. PR 6 is the
gating commitment to clap.
