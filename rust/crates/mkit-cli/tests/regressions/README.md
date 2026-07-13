# Stateful-suite regression transcripts

Each `*.txt` file here is a **minimal failing operation sequence** distilled from a
`tests/state_machine.rs` failure. `replay_checked_in_regressions` parses every `*.txt` in this
directory and replays it through the same harness, asserting the invariant battery now holds &mdash; so a
once-found bug stays covered even if the proptest strategy or proptest's own seed format changes.

This is deliberately independent of proptest's `proptest-regressions/` persistence (which stores
opaque seeds): a transcript is human-readable and stable.

## Format

One operation per line. Blank lines and `#` comments are ignored. Grammar (see `Op` in
`tests/state_machine.rs` for the authoritative encoder/decoder):

```
w <file> <content>     # write file f<file>.txt with a one-byte content
del <file>             # delete f<file>.txt from the worktree
add <file>             # mkit add f<file>.txt
addall                 # mkit add -A
rm <file>              # mkit rm -f f<file>.txt
restore <file>         # mkit restore f<file>.txt
commit                 # mkit commit -m ...
branch <name>          # mkit branch topic<name>
delbranch <name>       # mkit branch -d topic<name>
checkout <name>        # mkit checkout <existing branch mod count>
checkoutnew <name>     # mkit branch topic<name> ; mkit checkout topic<name>
tag <name>             # mkit tag tag<name>
deltag <name>          # mkit tag -d tag<name>
merge <name>           # mkit merge <existing branch mod count>
reset soft|mixed|hard  # mkit reset --<mode>
cherrypick <name>      # mkit cherry-pick <existing branch mod count>
revert                 # mkit revert HEAD
rebase <name>          # mkit rebase <existing branch mod count>
continue|abort|skip    # dispatched to whatever operation is in progress
stash                  # mkit stash
stashpop               # mkit stash pop
gc                     # mkit gc
mv <a> <b>             # mkit mv f<a>.txt f<b>.txt
clean                  # mkit clean -f -d
```

`<file>`/`<name>`/`<content>` are small non-negative integers (mapped modulo a fixed pool size).

To add a regression: copy the `--- transcript ---` block printed by a failing
`stateful_invariants` case into a new `NNN-short-description.txt` file here.
