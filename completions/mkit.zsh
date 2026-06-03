#compdef mkit
# mkit(1) zsh completion
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Install: place this file somewhere on $fpath (for example
# /usr/local/share/zsh/site-functions/_mkit on macOS Homebrew), then
# restart zsh or run `compinit`.
#
# Scope: subcommand completion + common flags. Argument-level completion
# (branch names, remotes) is deferred.

_mkit() {
    local -a commands
    commands=(
        'init:Create a new mkit repository'
        'add:Stage files for the next commit (-A/-u, multi-path)'
        'rm:Remove path(s) and stage the deletion (--cached/-r/-f)'
        'hash:Hash a file and store it as a blob'
        'cat:Display an object by its hash'
        'tree:Snapshot working directory as a tree object'
        'commit:Create a signed commit'
        'log:Show commit history'
        'status:Show staged and working tree changes'
        'diff:Show changes'
        'branch:List, create, or delete branches'
        'checkout:Switch HEAD to a branch and restore files'
        'tag:List/create/delete tags (-a/-s/-m for annotated/signed)'
        'config:Show or set configuration values'
        'merge:Merge a branch into HEAD'
        'push:Push to remote'
        'pull:Pull changes from remote'
        'fetch:Download from remote without merging'
        'stash:Stash working-dir changes'
        'clone:Clone a repository'
        'remote:Show or configure the origin remote'
        'key:Manage user-scoped keystore keys (generate/list/import/export/delete)'
        'keygen:Generate a new Ed25519 signing keypair'
        'cherry-pick:Apply a commit to the current branch'
        'rebase:Replay commits onto a different base'
        'bisect:Binary search for a bad commit'
        'sparse-checkout:Manage sparse checkout patterns'
        'serve:Start SSH transport server (internal)'
        'blame:Show line-level commit attribution'
        'verify:Verify the signature on a commit'
        'attest:Produce a signed DSSE attestation for a commit'
        'verify-attest:Verify every attestation attached to a commit'
        'version:Print version'
        'help:Show help text'
    )

    # No top-level --version flag; the `version` subcommand is canonical.
    _arguments -C \
        '(-h --help)'{-h,--help}'[show help]' \
        '1: :->command' \
        '*::arg:->args' \
        && return 0

    case $state in
        command)
            _describe -t commands 'mkit command' commands && return 0
            ;;
        args)
            case $words[1] in
                add)
                    _arguments \
                        '(-A --all)'{-A,--all}'[stage all changes incl. deletions]' \
                        '(-u --update)'{-u,--update}'[restage only tracked files]' \
                        '--help[show help]' \
                        '*:file:_files'
                    ;;
                rm)
                    _arguments \
                        '--cached[stage removal only; keep worktree file]' \
                        '(-r --recursive)'{-r,--recursive}'[remove a directory recursively]' \
                        '(-f --force)'{-f,--force}'[remove even if locally modified]' \
                        '--help[show help]' \
                        '*:file:_files'
                    ;;
                diff)
                    _arguments \
                        '(--staged --cached)'{--staged,--cached}'[diff HEAD vs the staged index]' \
                        '--help[show help]' \
                        '*:file:_files'
                    ;;
                status)
                    _arguments \
                        '--porcelain[machine-readable XY output]' \
                        '--help[show help]'
                    ;;
                commit)
                    _arguments \
                        '(-a --all)'{-a,--all}'[stage tracked changes before committing]' \
                        '-m[commit message]:message:' \
                        '--help[show help]'
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
                tag)
                    _arguments \
                        '(-a --annotate)'{-a,--annotate}'[create an annotated tag object]' \
                        '(-s --sign)'{-s,--sign}'[create a signed (Ed25519) tag object]' \
                        '(-m --message)'{-m,--message}'[tag message]:message:' \
                        '(-d --delete)'{-d,--delete}'[delete a tag]' \
                        '--author[override tagger identity]:spec:' \
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
                key)
                    _values 'key subcommand' \
                        'generate[generate a new key in the keystore]' \
                        'list[list keystore entries]' \
                        'import[import a key into the keystore]' \
                        'export[export a key from the keystore]' \
                        'delete[delete a key from the keystore]'
                    ;;
                attest)
                    _arguments \
                        '--commit[commit hash]:hash:' \
                        '--algorithm[signing algorithm]:alg:' \
                        '--signer[signer kind]:kind:' \
                        '--predicate-type[predicate type URI]:uri:' \
                        '--predicate-file[predicate file path]:_files' \
                        '*--additional-signer[additional signer spec]:spec:' \
                        '--help[show help]'
                    ;;
                verify-attest)
                    _arguments \
                        '--commit[commit hash]:hash:' \
                        '--trust-roots[trust roots path]:_files' \
                        '--algorithm[algorithm filter]:alg:' \
                        '--help[show help]'
                    ;;
            esac
            ;;
    esac
}

_mkit "$@"
