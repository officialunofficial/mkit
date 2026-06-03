# mkit(1) bash completion
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Install:
#   cp mkit.bash /usr/local/etc/bash_completion.d/    (macOS / Homebrew)
#   cp mkit.bash /etc/bash_completion.d/              (most Linux)
# or `source mkit.bash` from your ~/.bashrc.
#
# Scope: subcommand completion + top-level flags. Completing sub-options
# (branch names, remote URLs, etc.) is deferred so this file stays small
# and easy to verify by eye.

_mkit_complete() {
    local cur prev words cword
    _init_completion || return 0

    local subcommands="init add rm restore reset hash cat tree commit log reflog status diff branch checkout tag config merge push pull fetch stash clone remote key keygen cherry-pick rebase bisect sparse-checkout serve pack-shard blame verify attest verify-attest version help"
    # Top-level flags. --version/-V are aliases of the `version` subcommand.
    local top_flags="--help -h --version -V"

    # First non-flag word is the subcommand.
    if [[ $cword -eq 1 ]]; then
        if [[ $cur == -* ]]; then
            COMPREPLY=( $(compgen -W "$top_flags" -- "$cur") )
        else
            COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )
        fi
        return 0
    fi

    # Per-subcommand suggestions. Intentionally minimal — we only
    # surface the --help / --version / well-documented flags so shell
    # users get tab-completion for the common fast-path.
    case "${words[1]}" in
        add)
            COMPREPLY=( $(compgen -W "-A --all -u --update --help" -- "$cur") )
            ;;
        rm)
            COMPREPLY=( $(compgen -W "--cached -r --recursive -f --force --help" -- "$cur") )
            ;;
        restore)
            COMPREPLY=( $(compgen -W "--staged --worktree --source -f --force --help" -- "$cur") )
            ;;
        reset)
            COMPREPLY=( $(compgen -W "--soft --mixed --help" -- "$cur") )
            ;;
        diff)
            COMPREPLY=( $(compgen -W "--staged --cached --help" -- "$cur") )
            ;;
        status)
            COMPREPLY=( $(compgen -W "--porcelain -s --short --help" -- "$cur") )
            ;;
        commit)
            COMPREPLY=( $(compgen -W "-a --all --amend -m --help" -- "$cur") )
            ;;
        log)
            COMPREPLY=( $(compgen -W "--oneline --abbrev-commit --abbrev --format --graph -n --help" -- "$cur") )
            ;;
        reflog)
            COMPREPLY=( $(compgen -W "--format -n --help" -- "$cur") )
            ;;
        push)
            COMPREPLY=( $(compgen -W "--dry-run --help" -- "$cur") )
            ;;
        clone)
            COMPREPLY=( $(compgen -W "--depth --sparse --help" -- "$cur") )
            ;;
        branch)
            COMPREPLY=( $(compgen -W "-d -D -m --help" -- "$cur") )
            ;;
        tag)
            COMPREPLY=( $(compgen -W "-a --annotate -s --sign -m --message -d --delete --author --help" -- "$cur") )
            ;;
        rebase)
            COMPREPLY=( $(compgen -W "--continue --abort --help" -- "$cur") )
            ;;
        bisect)
            COMPREPLY=( $(compgen -W "start good bad reset" -- "$cur") )
            ;;
        stash)
            COMPREPLY=( $(compgen -W "save list pop apply drop clear show" -- "$cur") )
            ;;
        remote)
            COMPREPLY=( $(compgen -W "add set remove rename" -- "$cur") )
            ;;
        key)
            COMPREPLY=( $(compgen -W "generate list import export delete --help" -- "$cur") )
            ;;
        pack-shard)
            COMPREPLY=( $(compgen -W "--out --force --help" -- "$cur") )
            ;;
        attest)
            COMPREPLY=( $(compgen -W "--commit --algorithm --signer --predicate-type --predicate-file --additional-signer --help" -- "$cur") )
            ;;
        verify-attest)
            COMPREPLY=( $(compgen -W "--commit --trust-roots --algorithm --help" -- "$cur") )
            ;;
        *)
            COMPREPLY=( $(compgen -W "--help" -- "$cur") )
            ;;
    esac
}

complete -F _mkit_complete mkit
