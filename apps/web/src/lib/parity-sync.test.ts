import { describe, expect, it } from 'vitest'
import { categories } from './parity-data'
import { parseDeferredFlags, readParityMd } from './parity-sync'

describe('parseDeferredFlags', () => {
  it('joins soft-wrapped bullets and extracts the command + flags', () => {
    const markdown = [
      '### Deferred flags (tracked follow-ups, not silently dropped)',
      '',
      'Intro text.',
      '',
      '- `log -p` / `--stat` / `--decorate` / `--author` / `--grep` / `--since` /',
      '  `--until` / `--no-merges` / `--first-parent` / `--all` — needs the log',
      '  renderer + walk extensions.',
      '- `diff -w` / `-b` / `-U<n>` — whitespace and context-line control.',
      '',
      '### Next section',
      '',
      '- not part of the deferred-flags list',
    ].join('\n')

    const entries = parseDeferredFlags(markdown)

    expect(entries).toEqual([
      {
        command: 'log',
        flags: [
          '-p',
          '--stat',
          '--decorate',
          '--author',
          '--grep',
          '--since',
          '--until',
          '--no-merges',
          '--first-parent',
          '--all',
        ],
        text: '`log -p` / `--stat` / `--decorate` / `--author` / `--grep` / `--since` / `--until` / `--no-merges` / `--first-parent` / `--all` — needs the log renderer + walk extensions.',
      },
      {
        command: 'diff',
        flags: ['-w', '-b', '-U<n>'],
        text: '`diff -w` / `-b` / `-U<n>` — whitespace and context-line control.',
      },
    ])
  })

  it('excludes bullets with prose before the em dash (a caveated sub-behavior, not a bare missing flag)', () => {
    const markdown = [
      '### Deferred flags (tracked follow-ups, not silently dropped)',
      '',
      '- `reset --mixed` "Unstaged changes after reset:" file list — needs a',
      "  worktree-vs-target-tree diff; `--hard`'s `HEAD is now at …` ships, `--mixed`",
      '  is otherwise silent.',
    ].join('\n')

    expect(parseDeferredFlags(markdown)).toEqual([])
  })

  it('excludes bullets that name display commands rather than a git subcommand + flag', () => {
    const markdown = [
      '### Deferred flags (tracked follow-ups, not silently dropped)',
      '',
      '- color for `status` / `log` / `branch` (see above).',
    ].join('\n')

    expect(parseDeferredFlags(markdown)).toEqual([])
  })

  it('throws a clear error if the heading is missing (section renamed/moved)', () => {
    expect(() => parseDeferredFlags('# some other doc\n')).toThrow(/Deferred flags/)
  })

  it('parses the real docs/PARITY.md deferred-flags section', () => {
    const entries = parseDeferredFlags(readParityMd())
    // This is the load-bearing sanity check: if PARITY.md's deferred-flags
    // list changes shape, this test documents exactly which commands the
    // sync check currently derives from it.
    expect(entries.map((e) => e.command).toSorted()).toEqual(['add', 'branch', 'diff', 'log'])
  })
})

describe('parity-data.ts stays in sync with docs/PARITY.md deferred flags', () => {
  const deferred = parseDeferredFlags(readParityMd())

  it('never renders a command with deferred flags as unqualified `parity` status', () => {
    const violations: string[] = []
    for (const category of categories) {
      for (const item of category.items) {
        if (item.status !== 'parity') continue
        const names = item.cmd.split('/').map((s) => s.trim())
        for (const entry of deferred) {
          if (names.includes(entry.command)) {
            violations.push(
              `apps/web/src/lib/parity-data.ts: "${item.cmd}" is marked 'parity' but docs/PARITY.md defers ` +
                `${entry.command} flags (${entry.flags.join(', ')}) — downgrade the status or update the note.`,
            )
          }
        }
      }
    }
    expect(violations).toEqual([])
  })
})
