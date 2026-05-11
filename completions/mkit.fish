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
    init add rm hash cat tree commit log status diff branch checkout \
    tag config merge push pull fetch stash clone remote keygen \
    cherry-pick rebase bisect sparse-checkout serve blame verify \
    version help

# Subcommand list (only when no subcommand has been entered yet).
complete -c mkit -n "not __fish_seen_subcommand_from $__mkit_subcommands" \
    -a "$__mkit_subcommands"

# Top-level flags.
complete -c mkit -n "not __fish_seen_subcommand_from $__mkit_subcommands" \
    -l help -s h -d "Show help"
complete -c mkit -n "not __fish_seen_subcommand_from $__mkit_subcommands" \
    -l version -d "Print version"

# Per-subcommand flags (kept minimal, mirrors mkit.bash).
complete -c mkit -n "__fish_seen_subcommand_from commit" \
    -l all -s a -d "Stage tracked changes"
complete -c mkit -n "__fish_seen_subcommand_from commit" \
    -s m -d "Commit message" -r
complete -c mkit -n "__fish_seen_subcommand_from log" \
    -l oneline -d "Compact one-line log"
complete -c mkit -n "__fish_seen_subcommand_from log" \
    -l graph -d "Show ancestry graph"
complete -c mkit -n "__fish_seen_subcommand_from log" \
    -s n -d "Limit number of commits" -r
complete -c mkit -n "__fish_seen_subcommand_from push" \
    -l dry-run -d "Show what would be pushed"
complete -c mkit -n "__fish_seen_subcommand_from clone" \
    -l depth -d "Shallow clone depth" -r
complete -c mkit -n "__fish_seen_subcommand_from clone" \
    -l sparse -d "Sparse checkout"
complete -c mkit -n "__fish_seen_subcommand_from branch" \
    -s d -d "Delete branch" -r
complete -c mkit -n "__fish_seen_subcommand_from rebase" \
    -l continue -d "Continue an in-progress rebase"
complete -c mkit -n "__fish_seen_subcommand_from rebase" \
    -l abort -d "Abort an in-progress rebase"

# Subcommands of subcommands.
complete -c mkit -n "__fish_seen_subcommand_from bisect; \
    and not __fish_seen_subcommand_from start good bad reset" \
    -a "start good bad reset"
complete -c mkit -n "__fish_seen_subcommand_from stash; \
    and not __fish_seen_subcommand_from save list pop drop show" \
    -a "save list pop drop show"
complete -c mkit -n "__fish_seen_subcommand_from remote; \
    and not __fish_seen_subcommand_from add set" \
    -a "add set"

# Generic --help on any subcommand.
complete -c mkit -n "__fish_seen_subcommand_from $__mkit_subcommands" \
    -l help -d "Show help for this subcommand"
