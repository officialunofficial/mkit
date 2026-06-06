# `git` alias shim (opt-in)

`mkit` exposes a git-compatible CLI surface (see [`docs/PARITY.md`](../../docs/PARITY.md)),
so existing git habits — and AI agents that emit `git <cmd>` — can drive it.
This directory provides an **opt-in** shim that forwards `git` to `mkit`.

**It is never installed automatically and never shadows the real `git`.** You
choose to install it, and you choose the name it takes on your `PATH`.

`mkit-git` is a pure forwarder: `git <args>` runs `mkit <args>`. An unsupported
command exits with mkit's usage error rather than falling through to real git.

## Install (pick one)

The simplest, with no shipped file named `git`:

```sh
alias git=mkit          # interactive shells only
```

To also cover scripts and non-interactive tools, put the shim on your `PATH`
**as `git`**, ahead of the real one — for a single project or a dedicated
environment, not system-wide:

```sh
mkdir -p ~/.local/mkit-shim
ln -s "$PWD/contrib/git-shim/mkit-git" ~/.local/mkit-shim/git
export PATH="$HOME/.local/mkit-shim:$PATH"   # ahead of the real git
```

Verify it resolves to the shim and not the real git before relying on it:

```sh
command -v git        # → ~/.local/mkit-shim/git
git version           # → mkit <X.Y.Z>
```

To stop using it, remove the symlink / `PATH` entry (or `unalias git`). Because
the shim only exists where you put it, the real `git` is untouched everywhere
else.

If `mkit` is not on your `PATH`, point the shim at it explicitly:

```sh
MKIT_BIN=/path/to/mkit git status
```
