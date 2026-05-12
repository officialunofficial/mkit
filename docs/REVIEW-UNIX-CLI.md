# Review: mkit CLI against Unix-philosophy rules

A targeted review of `mkit-cli` and `mkit serve` against the
McIlroy / Pike / Kernighan / Raymond rules captured in the
`building-unix-programs` skill. Citations point at the offending
or exemplary line so the conversation is concrete.

The headline: **mkit is already well above average on this axis.**
sysexits adherence, NO_COLOR / `isatty` discipline, XDG roots,
foreground-only `serve`, and the byte-pinned `mkit version` contract
all match what the skill asks for. The findings below are mostly
about *closing gaps the docs already commit to* and adding one
machine-readable output mode.

Severity scale:

- **HIGH** — documented contract is unimplemented; breaks scripting today.
- **MEDIUM** — pipeline correctness or scriptability lost; cheap to fix.
- **LOW** — idiomatic polish; ignore until the surface stabilizes.

---

## HIGH — signal handlers are a no-op; the documented SIGPIPE / SIGINT / SIGTERM contract isn't wired up

`docs/CLI.md` §Signals promises:

> **SIGPIPE** is ignored. Pipelines like `mkit log | head -1` exit
> cleanly without a "Broken pipe" message…
> **SIGINT** / **SIGTERM** set a graceful-shutdown flag.

`rust/crates/mkit-cli/src/signal.rs:35-37`:

```rust
pub fn install() {
    // Intentionally empty — see module docs.
}
```

The module docstring is honest about it ("TODO(signal-hook)"), but the
user-facing reference is not. On Unix, the default SIGPIPE action is
**terminate** — so `mkit log | head -1` against a long history will be
killed by the kernel mid-write rather than exiting cleanly. That's the
exact pipeline-composition failure the skill's *Composability checklist*
calls out:

> Handles SIGPIPE (`head` closing the pipe upstream isn't a crash).

**Fix.** Either:

1. Wire the handler now (`signal_hook::flag::register` for SIGINT/SIGTERM,
   plus `signal(SIGPIPE, SIG_IGN)` via `nix` or a raw libc call gated by
   the existing `#[allow(unsafe_code)]` pattern used in `config.rs`); or
2. Until then, soften `docs/CLI.md` to describe the *intended* behavior
   and add a `KNOWN-LIMITATION:` note next to the SIGPIPE bullet so
   shell-script authors don't rely on a contract that isn't there.

Option 1 is preferable — SIGPIPE-ignore is a one-line cost and the
checkpoint-polling sites in push/pull/clone are already calling
`is_shutdown()` per `signal.rs:16-17`.

---

## MEDIUM — `mkit status` and `mkit log` mix data and diagnostics on stdout

The skill calls this out as *"the single most violated rule in modern CLIs."*

`rust/crates/mkit-cli/src/commands/status.rs:46-57, 79-82`:

```rust
match refs::read_head(&mkit_dir) {
    Ok(refs::Head::Branch(name)) => { let _ = writeln!(stdout, "on branch {name}"); }
    …
    Err(_) => { let _ = writeln!(stdout, "no HEAD yet"); }
}
…
if entries.is_empty() {
    let _ = writeln!(stdout, "nothing to commit, working tree clean");
    return exit::OK;
}
```

`rust/crates/mkit-cli/src/commands/log.rs:43-47, 60-66`:

```rust
let Ok(Some(start)) = refs::resolve_head(&mkit_dir) else {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "no commits yet");
    return exit::OK;
};
…
Err(e) => { let _ = writeln!(stdout, "(read error: {e})"); break; }
…
let _ = writeln!(stdout, "(not a commit: {})", format::hex_hash(&cur));
break;
```

Two problems compound here:

1. **Status prose on stdout.** `mkit status | grep '^M'` (a perfectly
   normal user workflow) sees `on branch main` and `nothing to commit,
   working tree clean` lines mingled with the actual change list. Git
   makes the same mistake by default, and porcelain users learn to
   reach for `git status --porcelain`. mkit is young enough to do it
   right the first time.
2. **Read errors written to stdout, then `break` returns `OK`.** Both
   the `(read error:)` and `(not a commit:)` branches in `log.rs` print
   to stdout *and* short-circuit with `exit::OK`. That's the skill's
   *"Silent failures (exit 0 with an error message printed)"* anti-pattern
   verbatim. A CI pipeline running `mkit log | wc -l && echo "history OK"`
   will print "history OK" against a corrupted store.

**Fix.**

- Route status banners, "no commits yet", "(read error)", and
  "(not a commit)" to stderr via the same `emit_err` helper already
  present in both files.
- Return `exit::DATAERR` (65) on the corrupt-object branches in `log.rs`
  instead of `exit::OK`. That's exactly what `DATAERR` is for per
  `exit.rs:16-17`.

---

## MEDIUM — no machine-readable output mode

The skill's composability checklist:

> Output is line-oriented, or structured behind `--json`.

`mkit status`, `mkit log`, `mkit branch`, `mkit remote`, `mkit config`
(no-arg form), and `mkit blame` all emit only the human-shaped variant.
Scripts that want to consume them parse English. `grep -rn 'json'
rust/crates/mkit-cli/src/` returns zero hits outside `serve.rs` (which
uses framed protobuf, not JSON).

This is fine *while the CLI surface is still moving*. Pin it as a
deferred follow-up rather than letting the de-facto contract become
"parse the porcelain." Recommended starting points:

- `mkit status --porcelain` — Git-compatible line format, the lowest
  cost option and instantly familiar.
- `mkit log --format=json` — JSONL (one event per line), per the skill's
  service-logging guidance. The schema is small: `{hash, parents, author,
  timestamp, title}`.

`mkit version` already gets this right — it's byte-pinned for the
Homebrew / Scoop greppers per `cli.rs:9-11` — so the pattern of "pin a
machine-readable contract with a snapshot test" is already in the
codebase.

---

## MEDIUM — hand-rolled argument parsing

`rust/crates/mkit-cli/src/lib.rs:48-102` is a 50-line `match` on
`argv[1]`, and each subcommand walks its own `rest` slice. The skill
is opinionated here:

> Use a real parser (clap for Rust, cobra for Go, argparse for Python).
> Hand-rolled parsers get the edge cases wrong.

Concretely, mkit's current parser misses:

- `--` as the end-of-flags sentinel. `mkit add -- --weirdly-named-file`
  doesn't work today.
- Flag clustering and `=` forms. `mkit log -n=10` and `mkit log -n10`
  both fail; only `mkit log -n 10` works.
- Unknown long flags are sometimes accepted as no-ops (see `--graph` in
  `log.rs:25-27`), sometimes rejected as `usage_error`. There's no
  consistent policy.

A clap migration is a larger refactor than this review wants to land,
but the cost of *not* doing it grows with every new subcommand. The
sysexits-aware patterns already in `lib.rs` map cleanly onto clap's
`derive` API. Suggest filing a tracking issue under the `0.2.0` /
`1.0` umbrella.

---

## LOW — `--graph` silently accepted as a no-op

`rust/crates/mkit-cli/src/commands/log.rs:25-27`:

```rust
"--graph" => {
    // Silently accept for now — presentation-only flag.
}
```

This is a milder cousin of the silent-failure anti-pattern. A user
who passes `--graph` walks away believing they got a graph; they
got a linear log. Either implement it or reject with
`usage_error("--graph is not yet implemented")` and `exit::USAGE`.
The current docstring at the top of the file (`"--graph" is a Phase 10
follow-up`) is candid — propagate that candor to the user-facing surface.

---

## LOW — no `-` convention for stdin / stdout

The skill: *"`-` as a filename means stdin/stdout."* `mkit hash <file>`
and `mkit cat <hash>` are the two places this convention would slot in
naturally:

- `mkit hash -` reads bytes from stdin and prints the hash. Currently
  there's no path that does this — `grep stdin rust/crates/mkit-cli/src/`
  shows stdin is used only by `mkit serve` as the RPC channel.
- `mkit cat <hash> -` (or `mkit cat <hash> > -`) writes the object to
  stdout. `cat` likely already does this implicitly — worth confirming
  it doesn't add a trailing newline that corrupts binary blobs.

Treat as polish; do it when adding the `--json` work above.

---

## What mkit already gets right

These are worth keeping out of any refactor's blast radius:

- **`exit.rs`** is a model sysexits implementation. The
  `error_codes_are_nonzero` test (`exit.rs:60-75`) is exactly the
  guard the skill's exit-code section is asking for.
- **`term.rs`** correctly gates color on `isatty`, with `NO_COLOR`
  beating `CLICOLOR_FORCE`. Matches the skill verbatim.
- **`mkit serve`** runs in the foreground over stdin/stdout, with no
  double-fork, no pidfile, no detach (`commands/serve.rs:48-54`). That
  is precisely the *"don't fight your supervisor"* rule — sshd's forced-
  command path drives it, and SSH process accounting Just Works.
- **`mkit version`** is byte-pinned by snapshot test and enforced by
  `build.rs` against `CARGO_PKG_VERSION` (`cli.rs:9-11`). The skill
  treats this kind of single-line stdout contract as load-bearing
  for distros; mkit treats it the same way.
- **Repo / user XDG split** (`docs/CLI.md` §"File layout") respects
  `$XDG_CONFIG_HOME` / `$XDG_DATA_HOME` / `$XDG_CACHE_HOME` /
  `$XDG_STATE_HOME`. The skill explicitly calls out *"Never read
  config from `$HOME` for a service. Use `$XDG_CONFIG_HOME` for user
  tools."* — done.
- **Per-connection caps in `serve`** (`MAX_FRAMES_PER_CONN`,
  `MAX_BYTES_PER_CONN` at `commands/serve.rs:28-29`) are the kind of
  bounded-work discipline that keeps a daemon supervisable.

---

## Proposed sequencing

1. **This PR / next PR** — wire SIGPIPE / SIGINT / SIGTERM, or downgrade
   the docs claim. (HIGH)
2. **Next PR** — route status/diagnostic prose off stdout in `status.rs`
   and `log.rs`; return `DATAERR` on the corrupt-object branches. (MEDIUM)
3. **0.2 milestone** — `mkit status --porcelain` + `mkit log --format=json`,
   pinned by snapshot tests. (MEDIUM)
4. **0.2 milestone** — `clap`-derive migration; address `--`, `=` forms,
   and the silent-acceptance policy in one go. (MEDIUM)
5. **As-encountered** — `-` filename convention; reject or implement
   `--graph`. (LOW)
