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

    local subcommands="init add rm hash cat tree commit log status diff branch checkout tag config merge push pull fetch stash clone remote keygen cherry-pick rebase bisect sparse-checkout serve blame verify version help"
    local top_flags="--help -h --version"

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
        commit)
            COMPREPLY=( $(compgen -W "-m --help" -- "$cur") )
            ;;
        log)
            COMPREPLY=( $(compgen -W "--oneline --graph -n --help" -- "$cur") )
            ;;
        push)
            COMPREPLY=( $(compgen -W "--dry-run --help" -- "$cur") )
            ;;
        clone)
            COMPREPLY=( $(compgen -W "--depth --sparse --help" -- "$cur") )
            ;;
        branch)
            COMPREPLY=( $(compgen -W "-d --help" -- "$cur") )
            ;;
        rebase)
            COMPREPLY=( $(compgen -W "--continue --abort --help" -- "$cur") )
            ;;
        bisect)
            COMPREPLY=( $(compgen -W "start good bad reset" -- "$cur") )
            ;;
        stash)
            COMPREPLY=( $(compgen -W "save list pop drop show" -- "$cur") )
            ;;
        remote)
            COMPREPLY=( $(compgen -W "add set" -- "$cur") )
            ;;
        *)
            COMPREPLY=( $(compgen -W "--help" -- "$cur") )
            ;;
    esac
}

complete -F _mkit_complete mkit
