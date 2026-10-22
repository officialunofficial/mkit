# Local build cache

Install sccache and run these commands from the repository root:

```sh
cargo install sccache --locked
just cargo-cached check -p mkit-core
sccache --show-stats
just build-dir-env
just worktree-gc
just worktree-gc --apply
```

The recipes require Python 3.9 or newer. `cargo-cached` runs in **rust/** with
`RUSTC_WRAPPER=sccache`, `CARGO_INCREMENTAL=0`, and a default sccache size of
30 GiB. It fails if sccache is missing. You can set `SCCACHE_CACHE_SIZE` yourself.
If sccache fails, use plain Cargo with `RUSTC_WRAPPER` unset.

Cargo's [build directory setting](https://doc.rust-lang.org/cargo/reference/config.html#buildbuild-dir)
is stable since [Cargo 1.91](https://blog.rust-lang.org/2025/10/30/Rust-1.91.0/).
The pinned toolchain is 1.99, so no fallback is needed.
The recipe sets `CARGO_BUILD_BUILD_DIR` to
`~/.cache/mkit/build/{workspace-path-hash}`. Cargo expands the placeholder
from the workspace manifest path, giving each worktree its own intermediates.
Set `MKIT_BUILD_ROOT` to an absolute path to change the root.
Dependencies, fingerprints, and build scripts move there; final artifacts stay
in the worktree's **rust/target/** directory. Moving intermediates alone does
not reduce disk use. sccache reuses compilation results; GC reclaims finished
worktrees' output. Some rustc invocations are not cacheable.

Never share `CARGO_TARGET_DIR` across worktrees. Cargo locks a target directory,
so parallel builds queue, and different branches replace each other's output.
`cargo-cached` rejects inherited target-directory overrides. Keep any personal
Cargo configuration and command-line target overrides local to each worktree.

To give plain Cargo the same intermediate directory, add the export line printed
by `just build-dir-env` to your shell profile. This export also affects Cargo
in other repositories, so use a project-scoped shell environment if you prefer.
It does not enable sccache or disable incremental compilation for plain Cargo.
Remove the export when reproducing CI or Docker builds locally.

GitHub Actions retains its existing Cargo cache behavior. Cloud Build retains
its existing sccache backend. No tracked TOML (including Cargo configuration includes),
Dockerfile, GitHub YAML (including composite actions), or Cloud Build YAML may
set `build-dir`. The conservative text guard rejects references even in comments
in those inputs. `just check-local-build` runs the guard and shell fixture tests;
this gate is also part of `just ci-scripts`.

## Clean finished worktrees

`just worktree-gc` scans registered worktrees in the current Git repository.
It compares HEAD against the locally fetched `origin/main`, or `main` when
`origin/main` is absent. Run `git fetch --prune` first for current merge and
upstream-deletion information. A branch is eligible when its HEAD is an ancestor
of that base, or its configured upstream is gone (including squash merges).
A new branch with no commits is already an ancestor: stop its builds before GC.

Dry run is the default. `--apply` runs `cargo clean` in each eligible **rust/**
workspace, removing its target and the matching build directory. It keeps source,
worktrees, and branches. It never cleans the main checkout, the current checkout,
`main` branches, detached or locked worktrees, or worktrees with tracked,
untracked, or submodule changes. It ignores inherited target-directory variables
and refuses external, symlinked, or tracked target output. It also refuses
symlinked build directories and build directories overlapping source checkouts.
Neither output directory may contain a registered source checkout.
Unsafe configurations or failed Git/Cargo commands return a nonzero status.

Use the same `MKIT_BUILD_ROOT` you used for builds. GC does not sweep orphaned
caches, other clones, or separate signer/Worker workspaces. Stop builds and edits
in candidate worktrees before applying: the final status and path checks reduce
races but do not lock Git editors. Cargo serializes cleanup with builds through
its output locks. An interrupted clean can be rerun; output rebuilds normally.
