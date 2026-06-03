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
    init add rm restore reset hash cat tree commit log status diff branch checkout \
    tag config merge push pull fetch stash clone remote key keygen \
    cherry-pick rebase bisect sparse-checkout serve blame verify \
    attest verify-attest version help

# Subcommand list (only when no subcommand has been entered yet).
complete -c mkit -n "not __fish_seen_subcommand_from $__mkit_subcommands" \
    -a "$__mkit_subcommands"

# Top-level flags.
complete -c mkit -n "not __fish_seen_subcommand_from $__mkit_subcommands" \
    -l help -s h -d "Show help"
# No top-level --version flag; use the `version` subcommand.

# Per-subcommand flags (kept minimal, mirrors mkit.bash).
complete -c mkit -n "__fish_seen_subcommand_from add" \
    -l all -s A -d "Stage all changes incl. deletions"
complete -c mkit -n "__fish_seen_subcommand_from add" \
    -l update -s u -d "Restage only tracked files"
complete -c mkit -n "__fish_seen_subcommand_from rm" \
    -l cached -d "Stage removal only; keep worktree file"
complete -c mkit -n "__fish_seen_subcommand_from rm" \
    -l recursive -s r -d "Remove a directory recursively"
complete -c mkit -n "__fish_seen_subcommand_from rm" \
    -l force -s f -d "Remove even if locally modified"
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
complete -c mkit -n "__fish_seen_subcommand_from diff" \
    -l staged -d "Diff HEAD vs the staged index"
complete -c mkit -n "__fish_seen_subcommand_from diff" \
    -l cached -d "Alias for --staged"
complete -c mkit -n "__fish_seen_subcommand_from status" \
    -l porcelain -d "Machine-readable XY output"
complete -c mkit -n "__fish_seen_subcommand_from commit" \
    -l all -s a -d "Stage tracked changes"
complete -c mkit -n "__fish_seen_subcommand_from commit" \
    -s m -d "Commit message" -r
complete -c mkit -n "__fish_seen_subcommand_from log" \
    -l oneline -d "Compact one-line log"
complete -c mkit -n "__fish_seen_subcommand_from log" \
    -l graph -d "Accepted for compat; currently a no-op"
complete -c mkit -n "__fish_seen_subcommand_from log" \
    -s n -d "Limit number of commits" -r
complete -c mkit -n "__fish_seen_subcommand_from push" \
    -l dry-run -d "Show what would be pushed"
complete -c mkit -n "__fish_seen_subcommand_from clone" \
    -l depth -d "Shallow clone depth" -r
complete -c mkit -n "__fish_seen_subcommand_from clone" \
    -l sparse -d "Sparse checkout"
complete -c mkit -n "__fish_seen_subcommand_from branch" \
    -s d -d "Delete branch (safe)" -r
complete -c mkit -n "__fish_seen_subcommand_from branch" \
    -s D -d "Force-delete branch" -r
complete -c mkit -n "__fish_seen_subcommand_from branch" \
    -s m -d "Rename branch" -r
complete -c mkit -n "__fish_seen_subcommand_from rebase" \
    -l continue -d "Continue an in-progress rebase"
complete -c mkit -n "__fish_seen_subcommand_from rebase" \
    -l abort -d "Abort an in-progress rebase"

# Subcommands of subcommands.
complete -c mkit -n "__fish_seen_subcommand_from bisect; \
    and not __fish_seen_subcommand_from start good bad reset" \
    -a "start good bad reset"
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

# Generic --help on any subcommand.
complete -c mkit -n "__fish_seen_subcommand_from $__mkit_subcommands" \
    -l help -d "Show help for this subcommand"
