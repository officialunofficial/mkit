# mkit(1) fish completion
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Install:
#   cp mkit.fish ~/.config/fish/completions/
# or copy to a system completions dir on your distribution.
#
# Scope: subcommand completion + top-level flags. Completing sub-options
# (branch names, remote URLs, etc.) is deferred so this file stays small
# and easy to verify by eye — matches the bash/zsh completions shipped
# alongside it.

# Disable file completion at the top level; we'll only complete known
# subcommands until the user provides one.
complete -c mkit -f

set -l __mkit_subcommands \
    init add rm mv restore reset hash cat cat-file tree ls-tree ls-files rev-parse show-ref for-each-ref symbolic-ref update-ref commit log reflog status diff branch checkout clean \
    tag config merge push pull fetch stash clone remote key keygen \
    cherry-pick revert rebase bisect gc sparse-checkout serve pack-shard blame verify \
    attest verify-attest version help

# Subcommand list (only when no subcommand has been entered yet).
complete -c mkit -n "not __fish_seen_subcommand_from $__mkit_subcommands" \
    -a "$__mkit_subcommands"

# Top-level flags. --version/-V are aliases of the `version` subcommand.
complete -c mkit -n "not __fish_seen_subcommand_from $__mkit_subcommands" \
    -l help -s h -d "Show help"
complete -c mkit -n "not __fish_seen_subcommand_from $__mkit_subcommands" \
    -l version -s V -d "Print version"

# Per-subcommand flags (kept minimal, mirrors mkit.bash).
complete -c mkit -n "__fish_seen_subcommand_from add" \
    -l all -s A -d "Stage all changes incl. deletions"
complete -c mkit -n "__fish_seen_subcommand_from add" \
    -l update -s u -d "Restage only tracked files"
complete -c mkit -n "__fish_seen_subcommand_from add" \
    -l force -s f -d "Stage an ignored path"
complete -c mkit -n "__fish_seen_subcommand_from add" \
    -l patch -s p -d "Interactively choose hunks to stage"
complete -c mkit -n "__fish_seen_subcommand_from rm" \
    -l cached -d "Stage removal only; keep worktree file"
complete -c mkit -n "__fish_seen_subcommand_from rm" \
    -l recursive -s r -d "Remove a directory recursively"
complete -c mkit -n "__fish_seen_subcommand_from rm" \
    -l force -s f -d "Remove even if locally modified"
complete -c mkit -n "__fish_seen_subcommand_from mv" \
    -l force -s f -d "Overwrite an existing destination"
complete -c mkit -n "__fish_seen_subcommand_from restore" \
    -l staged -s S -d "Unstage: restore index entry from HEAD"
complete -c mkit -n "__fish_seen_subcommand_from restore" \
    -l worktree -s W -d "Restore the worktree file"
complete -c mkit -n "__fish_seen_subcommand_from restore" \
    -l source -d "Restore content from this revision" -r
complete -c mkit -n "__fish_seen_subcommand_from restore" \
    -l force -s f -d "Overwrite locally-modified files"
complete -c mkit -n "__fish_seen_subcommand_from reset" \
    -l soft -d "Move HEAD only; keep index and worktree"
complete -c mkit -n "__fish_seen_subcommand_from reset" \
    -l mixed -d "Move HEAD and reset the index (default)"
complete -c mkit -n "__fish_seen_subcommand_from reset" \
    -l hard -d "Also reset the worktree (keeps untracked)"
complete -c mkit -n "__fish_seen_subcommand_from reset" \
    -s f -l force -d "With --hard, discard dirty/staged content"
complete -c mkit -n "__fish_seen_subcommand_from clean" \
    -s n -l dry-run -d "Preview without deleting"
complete -c mkit -n "__fish_seen_subcommand_from clean" \
    -s f -l force -d "Actually delete (required)"
complete -c mkit -n "__fish_seen_subcommand_from clean" \
    -s d -d "Also remove untracked directories"
complete -c mkit -n "__fish_seen_subcommand_from clean" \
    -s x -d "Also remove ignored files"
complete -c mkit -n "__fish_seen_subcommand_from clean" \
    -s X -d "Remove only ignored files"
complete -c mkit -n "__fish_seen_subcommand_from diff" \
    -l staged -d "Diff HEAD vs the staged index"
complete -c mkit -n "__fish_seen_subcommand_from diff" \
    -l cached -d "Alias for --staged"
complete -c mkit -n "__fish_seen_subcommand_from diff" \
    -l name-only -d "List changed paths only"
complete -c mkit -n "__fish_seen_subcommand_from diff" \
    -l name-status -d "List status letter + path"
complete -c mkit -n "__fish_seen_subcommand_from diff" \
    -l stat -d "Diffstat: counts + graph + summary"
complete -c mkit -n "__fish_seen_subcommand_from diff" \
    -s z -d "NUL-terminate name-only/name-status records, raw paths"
complete -c mkit -n "__fish_seen_subcommand_from cat-file" \
    -s t -d "Print object type"
complete -c mkit -n "__fish_seen_subcommand_from cat-file" \
    -s s -d "Print object size"
complete -c mkit -n "__fish_seen_subcommand_from cat-file" \
    -s p -d "Pretty-print object content"
complete -c mkit -n "__fish_seen_subcommand_from cat-file" \
    -l batch -d "Read object names from stdin"
complete -c mkit -n "__fish_seen_subcommand_from ls-tree" \
    -s r -d "Recurse into sub-trees"
complete -c mkit -n "__fish_seen_subcommand_from ls-tree" \
    -s z -d "NUL-terminate records, raw paths"
complete -c mkit -n "__fish_seen_subcommand_from ls-files" \
    -s s -l stage -d "Show stage info"
complete -c mkit -n "__fish_seen_subcommand_from ls-files" \
    -s z -d "NUL-terminate records, raw paths"
complete -c mkit -n "__fish_seen_subcommand_from ls-files" \
    -l others -d "List untracked worktree files"
complete -c mkit -n "__fish_seen_subcommand_from ls-files" \
    -l ignored -d "Show only ignored files"
complete -c mkit -n "__fish_seen_subcommand_from ls-files" \
    -l exclude-standard -d "Drop .mkitignore-ignored files"
complete -c mkit -n "__fish_seen_subcommand_from rev-parse" \
    -l verify -d "Error on an unresolvable revision"
complete -c mkit -n "__fish_seen_subcommand_from rev-parse" \
    -l short -d "Abbreviate the id (default 7)"
complete -c mkit -n "__fish_seen_subcommand_from rev-parse" \
    -l abbrev-ref -d "Print the short symbolic name"
complete -c mkit -n "__fish_seen_subcommand_from rev-parse" \
    -l show-toplevel -d "Print the repository root"
complete -c mkit -n "__fish_seen_subcommand_from show-ref" \
    -l heads -d "Only refs/heads"
complete -c mkit -n "__fish_seen_subcommand_from show-ref" \
    -l tags -d "Only refs/tags"
complete -c mkit -n "__fish_seen_subcommand_from for-each-ref" \
    -l format -d "Output format with %(atom) tokens"
complete -c mkit -n "__fish_seen_subcommand_from symbolic-ref" \
    -l short -d "Print the short ref name"
complete -c mkit -n "__fish_seen_subcommand_from update-ref" \
    -l delete -s d -d "Delete the ref"
complete -c mkit -n "__fish_seen_subcommand_from status" \
    -l porcelain -d "Machine-readable XY output"
complete -c mkit -n "__fish_seen_subcommand_from status" \
    -s s -l short -d "Short format; alias for --porcelain=v1"
complete -c mkit -n "__fish_seen_subcommand_from status" \
    -s z -d "NUL-terminate records; raw unquoted paths"
complete -c mkit -n "__fish_seen_subcommand_from commit" \
    -l all -s a -d "Stage tracked changes"
complete -c mkit -n "__fish_seen_subcommand_from commit" \
    -l amend -d "Replace HEAD instead of adding a new commit"
complete -c mkit -n "__fish_seen_subcommand_from commit" \
    -s m -d "Commit message" -r
complete -c mkit -n "__fish_seen_subcommand_from log" \
    -l oneline -d "Compact one-line log"
complete -c mkit -n "__fish_seen_subcommand_from log" \
    -l abbrev-commit -d "Abbreviate commit ids"
complete -c mkit -n "__fish_seen_subcommand_from log" \
    -l abbrev -d "Abbreviation length (default 7)"
complete -c mkit -n "__fish_seen_subcommand_from log" \
    -l format -d "Output format (json)" -r -a json
complete -c mkit -n "__fish_seen_subcommand_from log" \
    -l graph -d "Accepted for compat; currently a no-op"
complete -c mkit -n "__fish_seen_subcommand_from log" \
    -s n -d "Limit number of commits" -r
complete -c mkit -n "__fish_seen_subcommand_from reflog" \
    -l format -d "Output format (default|json)" -r -a "default json"
complete -c mkit -n "__fish_seen_subcommand_from reflog" \
    -s n -d "Limit number of entries" -r
complete -c mkit -n "__fish_seen_subcommand_from push" \
    -l dry-run -d "Show what would be pushed"
complete -c mkit -n "__fish_seen_subcommand_from clone" \
    -l depth -d "Shallow clone depth" -r
complete -c mkit -n "__fish_seen_subcommand_from clone" \
    -l sparse -d "Sparse checkout"
complete -c mkit -n "__fish_seen_subcommand_from branch" \
    -s v -l verbose -d "Show abbreviated id + subject"
complete -c mkit -n "__fish_seen_subcommand_from branch" \
    -l format -d "Output format" -xa "default json"
complete -c mkit -n "__fish_seen_subcommand_from branch" \
    -s d -d "Delete branch (safe)" -r
complete -c mkit -n "__fish_seen_subcommand_from branch" \
    -s D -d "Force-delete branch" -r
complete -c mkit -n "__fish_seen_subcommand_from branch" \
    -s m -d "Rename branch" -r
complete -c mkit -n "__fish_seen_subcommand_from tag" \
    -l annotate -s a -d "Create an annotated tag object"
complete -c mkit -n "__fish_seen_subcommand_from tag" \
    -l sign -s s -d "Create a signed (Ed25519) tag object"
complete -c mkit -n "__fish_seen_subcommand_from tag" \
    -l message -s m -d "Tag message" -r
complete -c mkit -n "__fish_seen_subcommand_from tag" \
    -l delete -s d -d "Delete a tag" -r
complete -c mkit -n "__fish_seen_subcommand_from tag" \
    -l author -d "Override tagger identity" -r
complete -c mkit -n "__fish_seen_subcommand_from rebase" \
    -l interactive -s i -d "Edit the todo list before replaying"
complete -c mkit -n "__fish_seen_subcommand_from rebase" \
    -l continue -d "Continue an in-progress rebase"
complete -c mkit -n "__fish_seen_subcommand_from rebase" \
    -l skip -d "Skip the current commit"
complete -c mkit -n "__fish_seen_subcommand_from rebase" \
    -l abort -d "Abort an in-progress rebase"
complete -c mkit -n "__fish_seen_subcommand_from revert" \
    -l continue -d "Continue an in-progress revert"
complete -c mkit -n "__fish_seen_subcommand_from revert" \
    -l abort -d "Abort an in-progress revert"

# Subcommands of subcommands.
complete -c mkit -n "__fish_seen_subcommand_from bisect; \
    and not __fish_seen_subcommand_from start good bad reset" \
    -a "start good bad reset"
complete -c mkit -n "__fish_seen_subcommand_from gc" -l dry-run -s n -d "Preview without deleting"
complete -c mkit -n "__fish_seen_subcommand_from gc" -l grace-secs -d "Keep objects younger than SECS"
complete -c mkit -n "__fish_seen_subcommand_from stash; \
    and not __fish_seen_subcommand_from save list pop apply drop clear show" \
    -a "save list pop apply drop clear show"
complete -c mkit -n "__fish_seen_subcommand_from remote; \
    and not __fish_seen_subcommand_from add set remove rename" \
    -a "add set remove rename"
complete -c mkit -n "__fish_seen_subcommand_from key; \
    and not __fish_seen_subcommand_from generate list import export delete" \
    -a "generate list import export delete"

# attest / verify-attest flags.
complete -c mkit -n "__fish_seen_subcommand_from attest" \
    -l commit -d "Commit hash" -r
complete -c mkit -n "__fish_seen_subcommand_from attest" \
    -l algorithm -d "Signing algorithm" -r
complete -c mkit -n "__fish_seen_subcommand_from attest" \
    -l signer -d "Signer kind" -r
complete -c mkit -n "__fish_seen_subcommand_from attest" \
    -l predicate-type -d "Predicate type URI" -r
complete -c mkit -n "__fish_seen_subcommand_from attest" \
    -l predicate-file -d "Predicate file path" -r
complete -c mkit -n "__fish_seen_subcommand_from attest" \
    -l additional-signer -d "Additional signer spec" -r
complete -c mkit -n "__fish_seen_subcommand_from verify-attest" \
    -l commit -d "Commit hash" -r
complete -c mkit -n "__fish_seen_subcommand_from verify-attest" \
    -l trust-roots -d "Trust roots path" -r
complete -c mkit -n "__fish_seen_subcommand_from verify-attest" \
    -l algorithm -d "Algorithm filter" -r

# pack-shard flags.
complete -c mkit -n "__fish_seen_subcommand_from pack-shard" \
    -l out -d "Output directory" -r
complete -c mkit -n "__fish_seen_subcommand_from pack-shard" \
    -l force -d "Overwrite existing shards"

# Generic --help on any subcommand.
complete -c mkit -n "__fish_seen_subcommand_from $__mkit_subcommands" \
    -l help -d "Show help for this subcommand"
