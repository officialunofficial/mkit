//! CLI surface constants shared by the main dispatcher and the snapshot
//! tests.
//!
//! `CLI_VERSION` MUST equal `env!("CARGO_PKG_VERSION")` — `build.rs`
//! enforces this at compile time so cosmetic edits to `Cargo.toml` can
//! never desync the Homebrew / Scoop contract documented in
//! `docs/CLI.md`. `mkit version` MUST emit exactly `"mkit <X.Y.Z>\n"`.

/// Version string rendered by `mkit version`. Pinned to the package
/// version at compile time via `env!`.
pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Full help text for `mkit --help` / `mkit help` / `mkit` (with no
/// args). Pinned by snapshot tests so downstream tooling that greps the
/// binary output sees a stable surface.
pub const HELP_TEXT: &str = "\
usage: mkit <command> [args]

commands:
  init              Create a new mkit repository
  add [-A|-u] [-f] <path>...  Stage files for the next commit
  add .             Stage all files under cwd (respects .gitignore/.mkitignore)
  add -A            Stage all changes incl. deletions (no path args)
  add -u            Restage only already-tracked files (no path args)
  add -f <path>     Stage an ignored path (overrides .gitignore/.mkitignore)
  add -p <path>...  Interactively choose hunks to stage (y/n/q/a/d per hunk)
  rm [--cached] [-r] [-f] <path>...  Remove path(s) and stage the deletion
  rm --cached       Stage the removal only; keep the worktree file(s)
  mv [-f] <source>... <dest>  Move/rename tracked path(s) and stage it
                    (into <dest> when it is an existing directory; -f
                    overwrites an existing destination)
  restore [--staged] [--worktree] [--source <rev>] [-f] <path>...
                    Discard worktree changes for path(s) (restore from the
                    index), or --staged to unstage (restore the index entry
                    from HEAD); -f overrides the un-staged-edit guard
  reset [--soft|--mixed|--hard] [-f] [-q] [<commit>]
                    Move HEAD/branch (--soft) or HEAD + reset the index to
                    the commit's tree (--mixed, default); worktree untouched.
                    --hard also resets the worktree (keeps untracked files);
                    refuses to discard dirty/staged content without -f
  hash <file>       Hash a file and store it as a blob
  cat <hash>        Display an object by its hash
  cat-file (-t|-s|-p) <object> | cat-file --batch
                    Show an object's type, size, or content
                    (-p: blob bytes, tree listing, or commit/tag summary;
                    --batch reads object names from stdin, takes no <object>)
  show [--stat] [<object>...] Display objects (default HEAD): a commit/remix
                    with its diff vs the first parent, a tag then its target, a
                    tree listing, or a blob's contents (--stat shows a diffstat
                    instead of the patch for commits/remixes)
  tree              Snapshot working directory as a tree object
  ls-tree [-r] [-z] <tree-ish> [<path>...]
                    List a tree's entries as `<mode> <type> <hash>\t<name>`
                    (-r recurses; -z NUL-terminates with raw paths)
  ls-files [-s] [-z] [--others] [--ignored] [--exclude-standard]
                    List tracked files (-s adds stage info; --others lists
                    untracked; --exclude-standard drops ignored)
  rev-parse [--verify] [--short[=N]] [--abbrev-ref] [--show-toplevel] [<rev>...]
                    Resolve revisions to object ids (--short abbreviates,
                    --abbrev-ref HEAD prints the branch, --show-toplevel
                    prints the repo root; --verify is accepted for git-script
                    compatibility — mkit always errors on a bad revision)
  merge-base [--is-ancestor] <a> <b>  Print the common ancestor of two
                    commits (--is-ancestor tests ancestry: exit 0/1, no output)
  rev-list [--count] <rev>  List commit ids reachable from <rev> (--count
                    prints the number)
  show-ref [--heads] [--tags]  List refs as `<hash> <refname>`
  for-each-ref [--format=<fmt>] [<pattern>...]
                    Iterate refs, optionally with a %(atom) format string
  symbolic-ref [--short] <name> [<ref>]
                    Read a symbolic ref, or (with <ref>) repoint it
                    (e.g. symbolic-ref HEAD refs/heads/main)
  update-ref [-d] <ref> [<newvalue> [<oldvalue>]]
                    Create/update/delete refs/heads/* or refs/tags/*
                    (<oldvalue> compare-and-swap; all-zero = must be absent,
                    update mode only; -d's <oldvalue> must be concrete)
  commit [-a] [-q] [--amend] [-m <msg> | -F <file>] [--author <spec>]
                    Create a signed commit (opens $EDITOR if -m/-F omitted).
                    -F reads the message from <file> (`-` = stdin); --author
                    overrides the commit author. After `merge --no-commit`
                    (or a resolved merge) this records a two-parent merge commit.
                    -q suppresses the summary; -S/--gpg-sign, --no-verify,
                    --no-edit are accepted no-ops (mkit always signs, no hooks)
  commit --amend [-m <msg>]  Replace HEAD: re-commit on HEAD's parent, re-sign,
                    move the branch. Reuses HEAD's message if -m omitted.
                    The superseded commit becomes unreachable until `gc` ships.
  log [--oneline] [--abbrev-commit] [--abbrev[=N]] [--format=json] [--graph] [-n N] [<rev> | <A>..<B> | <A>...<B>]
                    Show commit history (default prints the full message
                    body + a UTC date; --oneline/--abbrev-commit abbreviate
                    the commit id, --abbrev[=N] sets the length (default 7);
                    --format=json emits JSONL with the raw timestamp;
                    --graph is accepted but currently a no-op). Optional
                    <rev> starts the walk there; <A>..<B> shows commits in B
                    not in A; <A>...<B> the symmetric difference (empty
                    side = HEAD)
  reflog [<ref>] [--format=json] [-n N]
                    Show a branch's recorded movement history (read-only).
                    Lists the branch's first-parent chain (newest first,
                    addressed <ref>@{N}); defaults to HEAD's branch. With
                    --features history-mmr, cross-checks each entry against
                    the journaled ref-history MMR. Not a full Git reflog:
                    @{N} indexes the reachable chain, so superseded commits
                    (after amend/reset) are not listed.
  status [--porcelain[=v1|v2]] [-s|--short] [-z]
                    Show staged and working tree changes (--porcelain, or
                    its -s/--short alias, emits machine-readable XY lines;
                    --porcelain=v2 emits git's richer per-path format with
                    modes + object ids; special-byte paths are C-style
                    quoted; -z NUL-terminates records with raw paths)
  diff [--staged|--cached] [--name-only|--name-status|--stat] [--merge-base] [--exit-code|--quiet] [--color[=WHEN]|--no-color] [-z] [<rev> [<rev>] | <a>..<b> | <a>...<b>] [<path>...]
                    Show changes as a unified patch (HEAD vs workdir,
                    --staged for HEAD vs index, a single revision vs the
                    worktree, two revisions, an A..B range, or an A...B
                    symmetric range = merge-base(a,b) vs b; --merge-base
                    diffs the merge base of the given revisions (the flag
                    spelling of A...B); revisions
                    are refs, commits, or short hashes). --name-only lists
                    changed paths; --name-status prefixes each with an
                    A/D/M (T = mode change) letter; --stat shows per-file
                    change counts + a +/- graph and a summary line; -z
                    NUL-terminates name-only/-status records with raw paths
                    (else special-byte paths are C-style quoted)
  branch [-v|--verbose] [--format=json]
                    List branches (* marks current; no commit id by
                    default, like git; -v adds the abbreviated id +
                    subject; JSONL with --format=json)
  branch <name>     Create a branch at HEAD
  branch -d <name>  Delete a branch (safe; refuses the current branch)
  branch -D <name>  Force-delete a branch (errors on an absent branch,
                    like git; still refuses the current branch)
  branch -m [<old>] <new>  Rename a branch (current branch if <old> omitted)
  branch --show-current  Print the current branch name
  branch [--list] [--contains [<c>]] [--no-contains [<c>]] [--merged [<c>]] [--no-merged [<c>]] [<pattern>...]
                    Filter the listing (like git): <pattern> are shell globs on
                    branch names (enabled by --list or any filter; `*`/`?`/`[…]`,
                    `*` spans `/`); --contains keeps branches whose tip has <c>
                    as an ancestor; --merged keeps those merged into <c>; the
                    --no-* forms invert. All four commit args default to HEAD
                    when omitted
  checkout <branch> Switch HEAD to a branch and restore files
  checkout -b|-B <new> [<start>]  Create (or -B reset) a branch and switch to it
  switch <branch>   Switch branches (git switch)
  switch -c|-C <new> [<start>]    Create (or -C reset) a branch and switch to it
  clean [-n] [-f] [-d] [-x|-X] [<path>...]
                    Remove untracked files (refuses without -f; -n
                    previews). -d also removes untracked dirs; -x includes
                    ignored files, -X removes only ignored
  tag [<name>] [<commit>]  List tags, or create a lightweight tag
  tag -l [<pattern>]  List tags, optionally filtered by a shell glob
  tag -a <name> [-m <msg>] [--author <spec>] [<commit>]  Create an annotated tag
  tag -s <name> [-m <msg>] [--author <spec>] [<commit>]  Create a signed tag
  tag -d <name>     Delete a tag
  config [--format=json]  Show all configuration values (JSON with --format=json)
  config <key> [--format=json]  Show one value
  config <key> <value>  Set a configuration value
  config user.identity <value>  Set author Identity
                        (ed25519:<hex>, mid:<N>, or raw [kind][len][bytes] hex)
  config user.name|user.email <value>  Git-compatibility aliases; stored and
                        round-tripped but NON-authoritative — they never set
                        the signed author (use user.identity for that)
  config trusted_remote_endpoint <url>  Trust an HTTP/S3 remote for ambient env credentials
  config ssh.strict_host_key_checking <yes|no|accept-new>  Override SSH host policy
  config ssh.user_known_hosts_file <path>  Custom SSH known_hosts file
  config ssh.identity_file <path>  SSH private key file
  merge [--no-commit] [-m <msg>] <branch> | --continue | --abort
                    Merge a branch into HEAD (--no-commit stages the merge and
                    stops before committing; finish with `mkit commit` or
                    `mkit merge --continue`; -m overrides the merge message)
  push [<remote>] [-u|--set-upstream] [--all] [-f|--force|--force-with-lease] [--dry-run]
                    Push current branch to its upstream (--all mirrors every
                    branch; -u records the upstream; prints git's `To <url>` +
                    ref-update summary, or `Everything up-to-date`)
  pull              Pull changes from remote (fast-forward; prints `Updating
                    <a>..<b>`/`Fast-forward`/diffstat, or `Already up to date.`)
  fetch             Download from remote without merging (prints `From <url>`
                    + per-ref summary; silent when nothing changed)
  stash             Stash working dir changes (save WIP; -m for a message)
  stash save -m <msg>  Stash with a message
  stash list        List stash entries (printed as stash@{N})
  stash pop [--index] [<n>|stash@{n}]    Apply and remove a stash entry (default
                    0; --index also restores the staged state, like git)
  stash apply [--index] [<n>|stash@{n}]  Apply a stash entry, keeping it (default
                    0; --index also restores the staged state)
  stash drop [<n>|stash@{n}]   Remove a stash entry without applying
  stash clear       Remove all stash entries
  stash show [<n>|stash@{n}]   Show the diff of a stash entry (default 0)
  clone [--sparse ...] <url>  Clone a repository
  remote [-v|--verbose] [--format=json]  List remotes (names only; -v adds
                    `<name>\t<url> (fetch)`/`(push)`; JSON with --format=json)
  remote add [<name>] <url>  Add a remote (mkit+file://, mkit+https://, mkit+s3://, mkit+ssh://)
  remote set [<name>] <url>  Alias for 'remote add'
  remote remove <name>  Remove a named remote (`default` clears the flat remote)
  remote rename <old> <new>  Rename a named remote
  remote get-url <name>  Print a remote's URL
  remote set-url <name> <url>  Change a remote's URL
  key generate|list|import|export|delete  Manage user-scoped keystore keys
  keygen [--algorithm ed25519|secp256k1|p256] [--force] [--print-pubkey]
                    Generate a new signing key (defaults to Ed25519)
  cherry-pick [-n] [-m <parent-number>] <hash> | --continue | --abort
                    Apply a commit to the current branch (-n stages the change
                    without committing; -m/--mainline selects the mainline
                    parent when replaying a merge commit, like git)
  revert [-n] [--no-edit] <commit> | --continue | --abort
                    Create a new commit undoing <commit> (forward commit;
                    conflict-aware; -n stages the revert without committing)
  rebase <branch>    Replay commits onto a different base
  rebase -i <branch> Interactive: reorder/drop/reword/squash/fixup the todo
  rebase --continue  Continue rebase after conflict resolution
  rebase --abort     Abort rebase and restore original state
  bisect start       Begin binary search for a bug
  bisect good [hash] Mark a commit as good
  bisect bad [hash]  Mark a commit as bad
  bisect reset       End bisect and restore original state
  gc [-n] [--grace-secs SECS]
                    Reclaim unreachable objects older than the grace
                    window (default 14d); -n/--dry-run previews
  sparse-checkout    Manage sparse checkout patterns
  serve <path>       Start SSH transport server (internal)
  mcp [--repository <path>]
                    Start a Model Context Protocol server on stdio so LLM
                    agents can drive this repository (status/diff/log/add/
                    commit/branch + verify/attest); --repository confines
                    tool calls to that path
  pack-shard [--out <dir>] [--force] <hash>
                    Encode a stored pack into Reed-Solomon shards (--out sets
                    the output dir, default .mkit/pack-shards; --force encodes
                    below the size threshold) (feature: pack-shards)
  git export <dest>  Export refs to a git mirror, one-way; --passthrough
                    publishes an imported repo as a true git fork (feature: git-bridge)
  git import <url> [<dir>]  Import a git upstream as a signed downstream fork (feature: git-bridge)
  git fetch|pull     Update refs/remotes/<name>/* and imported tags from the
                    upstream (locally-moved tags are never clobbered);
                    pull also fast-forwards the current branch (feature: git-bridge)
  git verify         Verify bridge state against the local store
                    (--fork-audit re-derives referenced content) (feature: git-bridge)
  git status         Show bridge state dirs: direction, endpoints, key, refs (feature: git-bridge)
  git format-patch <range>  Render native commits as `git am`-able patches (feature: git-bridge)
  blame [--format=json|--porcelain|--line-porcelain] [-w] [-M] [-C] [--ignore-rev <rev>] [--first-parent] [--reverse] [-L <start>,<end>] [<rev>] <file>
                    Show line-level commit attribution; -L limits to a line
                    range, -w ignores whitespace, -M/-C detect moved/copied
                    lines, --ignore-rev/--ignore-revs-file skip noise commits,
                    --first-parent limits the merge-aware walk to first
                    parents, --reverse <start>..<end> walks history forward,
                    <rev> blames as of a revision (default HEAD; JSONL with
                    --format=json, or git-shaped --porcelain/--line-porcelain)
  verify <rev>      Verify the signature on a commit, remix, or signed tag
  attest [--commit <hash>] [--algorithm <alg>] [--signer <kind>] [--predicate-type <URI>] [--predicate-file <path>]
         [--additional-signer \"algorithm=<alg>,signer=<kind>[,path=<p>]\"]... [--external-signer-arg <V>]...
                    Produce a signed DSSE attestation for a commit
                    (--external-signer-arg is repeatable; the supplied list
                    replaces attest.external_signer_args from config)
  verify-attest [--commit <hash>] [--trust-roots <path>] [--algorithm <filter>]
                    Verify every attestation attached to a commit
  self update [--version <tag>] [--check] [--allow-downgrade] [--format human|json]
                    Update this binary in place from a signed GitHub
                    Release, verifying the mkit-native release
                    attestation against keys embedded at build time.
                    Only for installer-managed binaries (curl mkit.sh |
                    sh); refuses with guidance under brew/cargo.
                    --check only reports; `latest` never downgrades
  version           Print version. Also available as the top-level
                    `--version` / `-V` flags; all emit `mkit <X.Y.Z>`.

global flags (before <command>):
  -C <path>         Run as if started in <path> (repeatable, like git)
  -c <key>=<value>  One-shot config override for this invocation (inert /
                    allowlisted keys only; security-sensitive keys refused)
  --no-pager|-P     Accepted no-op (mkit never paginates)
";

#[cfg(test)]
mod tests {
    use super::*;

    /// True iff `needle` occurs in `haystack` as a whole token: the
    /// characters immediately before and after the match (if any) are
    /// not alphanumeric/hyphen. Plain `.contains()` would let a short
    /// command name like `"rm"` match inside an unrelated word (e.g.
    /// "perform"), so this pins word-boundary coverage instead.
    fn contains_word(haystack: &str, needle: &str) -> bool {
        fn is_word_char(c: char) -> bool {
            c.is_ascii_alphanumeric() || c == '-'
        }
        haystack.match_indices(needle).any(|(idx, m)| {
            let before_ok = haystack[..idx]
                .chars()
                .next_back()
                .is_none_or(|c| !is_word_char(c));
            let after_ok = haystack[idx + m.len()..]
                .chars()
                .next()
                .is_none_or(|c| !is_word_char(c));
            before_ok && after_ok
        })
    }

    #[test]
    fn help_contains_every_documented_subcommand() {
        // Every top-level subcommand enumerated in docs/CLI.md — this
        // doubles as a reminder to refresh HELP_TEXT whenever CLI.md
        // grows a new command.
        let required = [
            "init",
            "add",
            "rm",
            "mv",
            "restore",
            "reset",
            "hash",
            "cat",
            "cat-file",
            "tree",
            "ls-tree",
            "ls-files",
            "rev-parse",
            "show",
            "show-ref",
            "for-each-ref",
            "symbolic-ref",
            "update-ref",
            "commit",
            "log",
            "reflog",
            "status",
            "diff",
            "branch",
            "checkout",
            "clean",
            "tag",
            "config",
            "merge",
            "push",
            "pull",
            "fetch",
            "stash",
            "clone",
            "remote",
            "key",
            "keygen",
            "cherry-pick",
            "rebase",
            "bisect",
            "sparse-checkout",
            "self",
            "serve",
            "mcp",
            "pack-shard",
            "blame",
            "verify",
            "version",
        ];
        for cmd in required {
            assert!(
                contains_word(HELP_TEXT, cmd),
                "HELP_TEXT missing documented subcommand: {cmd}"
            );
        }
    }
}
