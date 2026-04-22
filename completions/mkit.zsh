#compdef mkit
# mkit(1) zsh completion
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Install: place this file somewhere on $fpath (for example
# /usr/local/share/zsh/site-functions/_mkit on macOS Homebrew), then
# restart zsh or run `compinit`.
#
# Scope for 0.1.0: subcommand completion + common flags. Argument-level
# completion (branch names, remotes) is deferred.

_mkit() {
    local -a commands
    commands=(
        'init:Create a new mkit repository'
        'add:Stage a file for the next commit'
        'rm:Mark a file for removal in the next commit'
        'hash:Hash a file and store it as a blob'
        'cat:Display an object by its hash'
        'tree:Snapshot working directory as a tree object'
        'commit:Create a signed commit'
        'log:Show commit history'
        'status:Show staged and working tree changes'
        'diff:Show changes'
        'branch:List, create, or delete branches'
        'checkout:Switch HEAD to a branch and restore files'
        'tag:List, create, or delete tags'
        'config:Show or set configuration values'
        'merge:Merge a branch into HEAD'
        'push:Push to remote'
        'pull:Pull changes from remote'
        'fetch:Download from remote without merging'
        'stash:Stash working-dir changes'
        'clone:Clone a repository'
        'remote:Show or configure the origin remote'
        'keygen:Generate a new Ed25519 signing keypair'
        'cherry-pick:Apply a commit to the current branch'
        'rebase:Replay commits onto a different base'
        'bisect:Binary search for a bad commit'
        'sparse-checkout:Manage sparse checkout patterns'
        'serve:Start SSH transport server (internal)'
        'blame:Show line-level commit attribution'
        'verify:Verify the signature on a commit'
        'version:Print version'
        'help:Show help text'
    )

    _arguments -C \
        '(-h --help)'{-h,--help}'[show help]' \
        '--version[print version]' \
        '1: :->command' \
        '*::arg:->args' \
        && return 0

    case $state in
        command)
            _describe -t commands 'mkit command' commands && return 0
            ;;
        args)
            case $words[1] in
                commit)
                    _arguments '-m[commit message]:message:' '--help[show help]'
                    ;;
                log)
                    _arguments \
                        '--oneline[condensed output]' \
                        '--graph[include ASCII graph]' \
                        '-n[limit number of commits]:count:' \
                        '--help[show help]'
                    ;;
                push)
                    _arguments \
                        '--dry-run[show what would be pushed]' \
                        '--help[show help]'
                    ;;
                clone)
                    _arguments \
                        '--depth[truncate history to N commits]:depth:' \
                        '--sparse[sparse-checkout pattern]:pattern:' \
                        '--help[show help]'
                    ;;
                branch)
                    _arguments \
                        '-d[delete branch]:branch:' \
                        '--help[show help]'
                    ;;
                rebase)
                    _arguments \
                        '--continue[continue after conflict resolution]' \
                        '--abort[abort rebase]' \
                        '--help[show help]'
                    ;;
                bisect)
                    _values 'bisect subcommand' \
                        'start[begin binary search]' \
                        'good[mark a commit as good]' \
                        'bad[mark a commit as bad]' \
                        'reset[end bisect and restore HEAD]'
                    ;;
                stash)
                    _values 'stash subcommand' \
                        'save[stash working-dir changes]' \
                        'list[list stash entries]' \
                        'pop[apply and remove stash entry]' \
                        'drop[remove stash entry]' \
                        'show[show diff of stash entry]'
                    ;;
                remote)
                    _values 'remote subcommand' \
                        'add[add a remote]' \
                        'set[alias for add]'
                    ;;
            esac
            ;;
    esac
}

_mkit "$@"
