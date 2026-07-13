/**
 * Parses the "### Deferred flags" section of `docs/PARITY.md` — the authoritative, hand-maintained list of git flags
 * that are recognized as in-scope for parity but not yet implemented — into structured entries a test can check
 * `parity-data.ts` against.
 *
 * This exists to close a drift hole: the two files previously shared no generation step or test, only a loose prose
 * comment pointer, so the website could (and did) claim `'parity'` for a command PARITY.md itself lists flags as
 * deferred for. See `parity-sync.test.ts` for the check that uses this parser as a CI gate.
 */
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))

/** Absolute path to the repo's `docs/PARITY.md`, resolved from this file's location (not cwd). */
export const PARITY_MD_PATH = resolve(here, '..', '..', '..', '..', 'docs', 'PARITY.md')

const SECTION_HEADING = '### Deferred flags (tracked follow-ups, not silently dropped)'

export type DeferredEntry = {
  /** The git subcommand these flags are deferred for, e.g. "log". */
  command: string
  /** Deferred flag tokens, as written in PARITY.md (e.g. "-p", "--stat"). */
  flags: string[]
  /** The full, wrap-joined bullet text — used as the caveat/reason when downgrading a status. */
  text: string
}

export function readParityMd(): string {
  return readFileSync(PARITY_MD_PATH, 'utf8')
}

/**
 * Parse "### Deferred flags" bullets into per-command entries.
 *
 * Only bullets whose entire pre-em-dash clause is a slash-separated list of backtick-wrapped flags (e.g. "`log -p` /
 * `--stat` / ... — reason.") are treated as a command-level deferral. Bullets that embed prose before the em dash (e.g.
 * the `reset --mixed` output-message note, which describes a missing message for an otherwise-working flag) or that
 * don't open on a "command flag" pair (e.g. "color for `status` / `log` / `branch`", which names display commands, not
 * git subcommands) describe a narrower, already-caveated gap and are intentionally excluded — they are not claims that
 * the command itself carries undisclosed 'parity' status.
 *
 * Bullets in PARITY.md soft-wrap across multiple raw markdown lines (no repeated "- " marker on continuation lines);
 * those are joined into one bullet before parsing.
 */
export function parseDeferredFlags(markdown: string): DeferredEntry[] {
  const lines = markdown.split('\n')
  const headingIdx = lines.findIndex((l) => l.trim() === SECTION_HEADING)
  if (headingIdx === -1) {
    throw new Error(
      `parity-sync: could not find heading ${JSON.stringify(SECTION_HEADING)} in docs/PARITY.md — has the "Deferred flags" section moved or been renamed?`,
    )
  }

  const rest = lines.slice(headingIdx + 1)
  const endIdx = rest.findIndex((l) => /^#{2,3}\s/.test(l))
  const sectionLines = endIdx === -1 ? rest : rest.slice(0, endIdx)

  // Join wrapped bullets: a line starting with "- " begins a new bullet; any
  // following non-blank line that does NOT start with "- " is a soft-wrapped
  // continuation of the current bullet.
  const bullets: string[] = []
  for (const raw of sectionLines) {
    if (raw.startsWith('- ')) {
      bullets.push(raw.slice(2).trim())
    } else if (bullets.length > 0 && raw.trim() !== '') {
      bullets[bullets.length - 1] += ` ${raw.trim()}`
    }
  }

  const entries: DeferredEntry[] = []
  for (const rawBullet of bullets) {
    // docs/PARITY.md's prose em dashes are written as the `&mdash;` HTML
    // entity per docs/STYLE-GUIDE.md, not the literal `—` character — treat
    // both as the same delimiter so the entity form doesn't make every
    // bullet look like it has no em dash at all (which would fold each
    // bullet's trailing prose into `clause` below and fail the
    // backtick-spans-only check for every entry).
    const bullet = rawBullet.replaceAll('&mdash;', '—')
    const dashIdx = bullet.indexOf('—')
    const clause = (dashIdx === -1 ? bullet : bullet.slice(0, dashIdx)).trim()
    const spans = [...clause.matchAll(/`([^`]+)`/g)].map((m) => m[1]).filter((s): s is string => s !== undefined)
    if (spans.length === 0) continue

    // The clause must be *only* backtick spans joined by " / " (plus
    // trailing punctuation) — any other prose means this bullet describes
    // something narrower than "this command's flags are unimplemented".
    const withoutSpans = clause.replace(/`[^`]+`/g, '')
    if (!/^[\s/]*$/.test(withoutSpans)) continue

    const [first, ...restSpans] = spans
    if (first === undefined) continue
    const firstParts = first.split(/\s+/)
    if (firstParts.length < 2) continue // first span must be "command flag"
    const command = firstParts[0]
    if (command === undefined) continue
    const firstFlag = firstParts.slice(1).join(' ')
    const flags = [firstFlag, ...restSpans]
    if (!flags.every((f) => f.startsWith('-'))) continue // every span after the command must itself be a flag

    entries.push({ command, flags, text: bullet })
  }
  return entries
}
