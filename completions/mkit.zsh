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
        'mv:Move/rename tracked path(s) and stage it (-f to overwrite)'
        'restore:Discard worktree changes for path(s), or --staged to unstage'
        'reset:Move HEAD (--soft) or HEAD + index (--mixed) to a commit'
        'hash:Hash a file and store it as a blob'
        'cat:Display an object by its hash'
        'cat-file:Show an object'\''s type (-t), size (-s), content (-p), or --batch'
        'tree:Snapshot working directory as a tree object'
        'ls-tree:List a tree'\''s entries (-r recurse, -z NUL)'
        'ls-files:List tracked or untracked files'
        'rev-parse:Resolve revisions to object ids'
        'show-ref:List refs as <hash> <refname> (--heads/--tags)'
        'for-each-ref:Iterate refs with an optional --format'
        'symbolic-ref:Read or write a symbolic ref (e.g. HEAD)'
        'update-ref:Create, update, or delete a ref (guarded)'
        'commit:Create a signed commit'
        'log:Show commit history'
        'reflog:Show a branch movement history (read-only)'
        'status:Show staged and working tree changes'
        'diff:Show changes'
        'branch:List, create, rename, or delete branches'
        'checkout:Switch HEAD to a branch and restore files'
        'clean:Remove untracked files (-n preview, -f delete, -d dirs, -x/-X ignored)'
        'tag:List/create/delete tags (-a/-s/-m for annotated/signed)'
        'config:Show or set configuration values'
        'merge:Merge a branch into HEAD'
        'push:Push to remote'
        'pull:Pull changes from remote'
        'fetch:Download from remote without merging'
        'stash:Stash working-dir changes'
        'clone:Clone a repository'
        'remote:Show, add, remove, or rename remotes'
        'key:Manage user-scoped keystore keys (generate/list/import/export/delete)'
        'keygen:Generate a new Ed25519 signing keypair'
        'cherry-pick:Apply a commit to the current branch'
        'revert:Create a new commit undoing a previous commit'
        'rebase:Replay commits onto a different base'
        'bisect:Binary search for a bad commit'
        'gc:Reclaim unreachable objects'
        'sparse-checkout:Manage sparse checkout patterns'
        'serve:Start SSH transport server (internal)'
        'pack-shard:Encode a stored pack into Reed-Solomon shards'
        'blame:Show line-level commit attribution'
        'verify:Verify the signature on a commit'
        'attest:Produce a signed DSSE attestation for a commit'
        'verify-attest:Verify every attestation attached to a commit'
        'version:Print version'
        'help:Show help text'
    )

    # Top-level flags. --version/-V are aliases of the `version` subcommand.
    _arguments -C \
        '(-h --help)'{-h,--help}'[show help]' \
        '(-V --version)'{-V,--version}'[print version]' \
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
                        '(-f --force)'{-f,--force}'[stage an ignored path]' \
                        '(-p --patch)'{-p,--patch}'[interactively choose hunks to stage]' \
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
                mv)
                    _arguments \
                        '(-f --force)'{-f,--force}'[overwrite an existing destination]' \
                        '--help[show help]' \
                        '*:file:_files'
                    ;;
                restore)
                    _arguments \
                        '(-S --staged)'{-S,--staged}'[unstage: restore index entry from HEAD]' \
                        '(-W --worktree)'{-W,--worktree}'[restore the worktree file]' \
                        '--source[restore content from this revision]:rev:' \
                        '(-f --force)'{-f,--force}'[overwrite locally-modified files]' \
                        '--help[show help]' \
                        '*:file:_files'
                    ;;
                reset)
                    _arguments \
                        '(--soft --mixed --hard)--soft[move HEAD only; keep index and worktree]' \
                        '(--soft --mixed --hard)--mixed[move HEAD and reset the index (default)]' \
                        '(--soft --mixed --hard)--hard[also reset the worktree (keeps untracked)]' \
                        '(-f --force)'{-f,--force}'[with --hard, discard dirty/staged content]' \
                        '--help[show help]' \
                        '*:commit:'
                    ;;
                clean)
                    _arguments \
                        '(-n --dry-run)'{-n,--dry-run}'[preview without deleting]' \
                        '(-f --force)'{-f,--force}'[actually delete (required)]' \
                        '-d[also remove untracked directories]' \
                        '(-x -X)-x[also remove ignored files]' \
                        '(-x -X)-X[remove only ignored files]' \
                        '--help[show help]' \
                        '*:file:_files'
                    ;;
                diff)
                    _arguments \
                        '(--staged --cached)'{--staged,--cached}'[diff HEAD vs the staged index]' \
                        '(--name-only --name-status --stat)--name-only[list changed paths only]' \
                        '(--name-only --name-status --stat)--name-status[list status letter + path]' \
                        '(--name-only --name-status --stat)--stat[diffstat: counts + graph + summary]' \
                        '-z[NUL-terminate name-only/name-status records, raw paths]' \
                        '--help[show help]' \
                        '*:file:_files'
                    ;;
                cat-file)
                    _arguments \
                        '(-t -s -p --batch)-t[print object type]' \
                        '(-t -s -p --batch)-s[print object size]' \
                        '(-t -s -p --batch)-p[pretty-print object content]' \
                        '(-t -s -p --batch)--batch[read object names from stdin]' \
                        '--help[show help]' \
                        '*:object:'
                    ;;
                ls-tree)
                    _arguments \
                        '-r[recurse into sub-trees]' \
                        '-z[NUL-terminate records, raw paths]' \
                        '--help[show help]' \
                        '*:tree-ish:'
                    ;;
                ls-files)
                    _arguments \
                        '(-s --stage)'{-s,--stage}'[show stage info]' \
                        '-z[NUL-terminate records, raw paths]' \
                        '--others[list untracked worktree files]' \
                        '--ignored[show only ignored files]' \
                        '--exclude-standard[drop .mkitignore-ignored files]' \
                        '--help[show help]'
                    ;;
                rev-parse)
                    _arguments \
                        '--verify[error on an unresolvable revision]' \
                        '--short=[abbreviate to N chars]:N:' \
                        '--abbrev-ref[print the short symbolic name]' \
                        '--show-toplevel[print the repository root]' \
                        '--help[show help]' \
                        '*:rev:'
                    ;;
                show-ref)
                    _arguments \
                        '--heads[only refs/heads]' \
                        '--tags[only refs/tags]' \
                        '--help[show help]'
                    ;;
                for-each-ref)
                    _arguments \
                        '--format=[output format with %(atom) tokens]:fmt:' \
                        '--help[show help]' \
                        '*:pattern:'
                    ;;
                symbolic-ref)
                    _arguments \
                        '--short[print the short ref name]' \
                        '--help[show help]' \
                        '*:name:'
                    ;;
                update-ref)
                    _arguments \
                        '(-d --delete)'{-d,--delete}'[delete the ref]' \
                        '--help[show help]' \
                        '*:ref:'
                    ;;
                status)
                    _arguments \
                        '--porcelain[machine-readable XY output]' \
                        '(-s --short)'{-s,--short}'[short format; alias for --porcelain=v1]' \
                        '-z[NUL-terminate records; raw unquoted paths]' \
                        '--help[show help]'
                    ;;
                commit)
                    _arguments \
                        '(-a --all)'{-a,--all}'[stage tracked changes before committing]' \
                        '--amend[replace HEAD instead of adding a new commit]' \
                        '-m[commit message]:message:' \
                        '--help[show help]'
                    ;;
                log)
                    _arguments \
                        '--oneline[condensed output]' \
                        '--abbrev-commit[abbreviate commit ids]' \
                        '--abbrev[set abbreviation length]:length:' \
                        '--format[output format]:format:(json)' \
                        '--graph[include ASCII graph]' \
                        '-n[limit number of commits]:count:' \
                        '--help[show help]'
                    ;;
                reflog)
                    _arguments \
                        '--format[output format]:format:(default json)' \
                        '-n[limit number of entries]:count:' \
                        '--help[show help]' \
                        '1:ref:'
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
                        '(-v --verbose)'{-v,--verbose}'[show abbreviated id + subject]' \
                        '-d[delete branch (safe)]:branch:' \
                        '-D[force-delete branch]:branch:' \
                        '-m[rename branch]:branch:' \
                        '--format[output format]:format:(default json)' \
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
                revert)
                    _arguments \
                        '--continue[continue after conflict resolution]' \
                        '--abort[abort revert]' \
                        '--help[show help]'
                    ;;
                bisect)
                    _values 'bisect subcommand' \
                        'start[begin binary search]' \
                        'good[mark a commit as good]' \
                        'bad[mark a commit as bad]' \
                        'reset[end bisect and restore HEAD]'
                    ;;
                gc)
                    _arguments \
                        '(-n --dry-run)'{-n,--dry-run}'[preview without deleting]' \
                        '--grace-secs[keep unreachable objects younger than SECS]:secs:' \
                        '--help[show help]'
                    ;;
                stash)
                    _values 'stash subcommand' \
                        'save[stash working-dir changes]' \
                        'list[list stash entries]' \
                        'pop[apply and remove stash entry]' \
                        'apply[apply stash entry without removing it]' \
                        'drop[remove stash entry]' \
                        'clear[remove all stash entries]' \
                        'show[show diff of stash entry]'
                    ;;
                remote)
                    _values 'remote subcommand' \
                        'add[add a remote]' \
                        'set[alias for add]' \
                        'remove[remove a named remote]' \
                        'rename[rename a named remote]'
                    ;;
                key)
                    _values 'key subcommand' \
                        'generate[generate a new key in the keystore]' \
                        'list[list keystore entries]' \
                        'import[import a key into the keystore]' \
                        'export[export a key from the keystore]' \
                        'delete[delete a key from the keystore]'
                    ;;
                pack-shard)
                    _arguments \
                        '--out[output directory]:_files -/' \
                        '--force[overwrite existing shards]' \
                        '--help[show help]' \
                        '1:hash:'
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
