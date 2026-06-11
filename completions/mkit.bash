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

    local subcommands="init add rm mv restore reset hash cat cat-file show tree ls-tree ls-files rev-parse show-ref for-each-ref symbolic-ref update-ref commit log reflog status diff branch checkout clean tag config merge push pull fetch stash clone remote key keygen cherry-pick revert rebase bisect gc sparse-checkout serve pack-shard git blame verify attest verify-attest version help"
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
            COMPREPLY=( $(compgen -W "-A --all -u --update -f --force -p --patch --help" -- "$cur") )
            ;;
        rm)
            COMPREPLY=( $(compgen -W "--cached -r --recursive -f --force --help" -- "$cur") )
            ;;
        mv)
            COMPREPLY=( $(compgen -W "-f --force --help" -- "$cur") )
            ;;
        restore)
            COMPREPLY=( $(compgen -W "--staged --worktree --source -f --force --help" -- "$cur") )
            ;;
        reset)
            COMPREPLY=( $(compgen -W "--soft --mixed --hard -f --force --help" -- "$cur") )
            ;;
        clean)
            COMPREPLY=( $(compgen -W "-n --dry-run -f --force -d -x -X --help" -- "$cur") )
            ;;
        diff)
            COMPREPLY=( $(compgen -W "--staged --cached --name-only --name-status --stat -z --help" -- "$cur") )
            ;;
        cat-file)
            COMPREPLY=( $(compgen -W "-t -s -p --batch --help" -- "$cur") )
            ;;
        ls-tree)
            COMPREPLY=( $(compgen -W "-r -z --help" -- "$cur") )
            ;;
        ls-files)
            COMPREPLY=( $(compgen -W "-s --stage -z --others --ignored --exclude-standard --help" -- "$cur") )
            ;;
        rev-parse)
            COMPREPLY=( $(compgen -W "--verify --short --abbrev-ref --show-toplevel --help" -- "$cur") )
            ;;
        show-ref)
            COMPREPLY=( $(compgen -W "--heads --tags --help" -- "$cur") )
            ;;
        for-each-ref)
            COMPREPLY=( $(compgen -W "--format --help" -- "$cur") )
            ;;
        symbolic-ref)
            COMPREPLY=( $(compgen -W "--short --help" -- "$cur") )
            ;;
        update-ref)
            COMPREPLY=( $(compgen -W "-d --delete --help" -- "$cur") )
            ;;
        status)
            COMPREPLY=( $(compgen -W "--porcelain -s --short -z --help" -- "$cur") )
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
            COMPREPLY=( $(compgen -W "-v --verbose -d -D -m --format --help" -- "$cur") )
            ;;
        tag)
            COMPREPLY=( $(compgen -W "-a --annotate -s --sign -m --message -d --delete --author --help" -- "$cur") )
            ;;
        rebase)
            COMPREPLY=( $(compgen -W "-i --interactive --continue --skip --abort --help" -- "$cur") )
            ;;
        revert)
            COMPREPLY=( $(compgen -W "--continue --abort --help" -- "$cur") )
            ;;
        bisect)
            COMPREPLY=( $(compgen -W "start good bad reset" -- "$cur") )
            ;;
        gc)
            COMPREPLY=( $(compgen -W "-n --dry-run --grace-secs --help" -- "$cur") )
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
