'use client'
import { useQuery } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { workspaceRead, type WorkspaceFileContent, type WorkspaceView } from '../../lib/workspace-client'
import { workspaceKeys, workspaceFileOptions, type WorkspaceSession } from '../../lib/workspace-queries'
import { isDirtyDraft, type FileDraft, type WorkspaceDraftState } from './editor-state'
import './diff-view.css'

export type DiffLine = {
  kind: 'equal' | 'added' | 'removed'
  text: string
  beforeLine: number | null
  afterLine: number | null
}
const splitLines = (value: string) => value.match(/[^\n]*\n|[^\n]+$/g) ?? []
/** Exact line text is preserved, including final-newline changes. Quadratic work is capped. */
export function diffLines(before: string, after: string): DiffLine[] {
  const a = splitLines(before),
    b = splitLines(after)
  let prefix = 0,
    suffix = 0
  while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) prefix++
  while (
    suffix < a.length - prefix &&
    suffix < b.length - prefix &&
    a[a.length - suffix - 1] === b[b.length - suffix - 1]
  )
    suffix++
  const output: DiffLine[] = []
  let left = 1,
    right = 1
  const emit = (kind: DiffLine['kind'], text: string) =>
    output.push({
      kind,
      text,
      beforeLine: kind === 'added' ? null : left++,
      afterLine: kind === 'removed' ? null : right++,
    })
  for (let i = 0; i < prefix; i++) emit('equal', a[i]!)
  const n = a.length - prefix - suffix,
    m = b.length - prefix - suffix
  if ((n + 1) * (m + 1) <= 250_000) {
    const lengths = new Uint32Array((n + 1) * (m + 1))
    for (let i = n - 1; i >= 0; i--)
      for (let j = m - 1; j >= 0; j--) {
        lengths[i * (m + 1) + j] =
          a[prefix + i] === b[prefix + j]
            ? 1 + lengths[(i + 1) * (m + 1) + j + 1]!
            : Math.max(lengths[(i + 1) * (m + 1) + j]!, lengths[i * (m + 1) + j + 1]!)
      }
    let i = 0,
      j = 0
    while (i < n || j < m) {
      if (i < n && j < m && a[prefix + i] === b[prefix + j]) {
        emit('equal', a[prefix + i]!)
        i++
        j++
      } else if (i < n && (j === m || lengths[(i + 1) * (m + 1) + j]! >= lengths[i * (m + 1) + j + 1]!))
        emit('removed', a[prefix + i++]!)
      else emit('added', b[prefix + j++]!)
    }
  } else {
    // Large unrelated sections are represented as replacements; no content is omitted.
    for (let i = prefix; i < a.length - suffix; i++) emit('removed', a[i]!)
    for (let i = prefix; i < b.length - suffix; i++) emit('added', b[i]!)
  }
  for (let i = a.length - suffix; i < a.length; i++) emit('equal', a[i]!)
  return output
}
export function diffSummary(lines: DiffLine[]) {
  return lines.reduce(
    (summary, line) => ({
      added: summary.added + Number(line.kind === 'added'),
      removed: summary.removed + Number(line.kind === 'removed'),
    }),
    { added: 0, removed: 0 },
  )
}

type DiffBlock = { key: number; lines: DiffLine[]; hidden: boolean }
function blocks(lines: DiffLine[]): DiffBlock[] {
  const result: DiffBlock[] = []
  for (let start = 0; start < lines.length;) {
    let end = start + 1
    while (end < lines.length && lines[end]?.kind === lines[start]?.kind) end++
    if (lines[start]?.kind === 'equal' && end - start > 8) {
      result.push(
        { key: start, lines: lines.slice(start, start + 3), hidden: false },
        { key: start + 3, lines: lines.slice(start + 3, end - 3), hidden: true },
        { key: end - 3, lines: lines.slice(end - 3, end), hidden: false },
      )
    } else result.push({ key: start, lines: lines.slice(start, end), hidden: false })
    start = end
  }
  return result
}
export function DiffView({
  before,
  after,
  beforeLabel = 'Before',
  afterLabel = 'After',
}: {
  before: string
  after: string
  beforeLabel?: string
  afterLabel?: string
}) {
  // A new comparison resets disclosure and large-diff pagination.
  return (
    <DiffContent
      key={before + '\u0000' + after}
      before={before}
      after={after}
      beforeLabel={beforeLabel}
      afterLabel={afterLabel}
    />
  )
}
function DiffContent({
  before,
  after,
  beforeLabel,
  afterLabel,
}: {
  before: string
  after: string
  beforeLabel: string
  afterLabel: string
}) {
  const lines = useMemo(() => diffLines(before, after), [before, after])
  const groups = useMemo(() => blocks(lines), [lines])
  const summary = diffSummary(lines)
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set())
  const [limit, setLimit] = useState(400)
  let displayed = 0
  const visibleGroups = []
  for (const group of groups) {
    const collapsed = group.hidden && !expanded.has(group.key)
    const visible = collapsed ? [] : group.lines.slice(0, Math.max(0, limit - displayed))
    displayed += visible.length
    visibleGroups.push({ ...group, collapsed, visible })
  }
  const remaining = visibleGroups.reduce(
    (count, group) => count + (group.collapsed ? 0 : group.lines.length - group.visible.length),
    0,
  )
  return (
    <section className='diff-view' aria-label={`${beforeLabel} compared with ${afterLabel}`}>
      <header className='diff-toolbar'>
        <span>
          {beforeLabel} → {afterLabel}
        </span>
        <span className='diff-counts'>
          <span className='diff-added-count'>+{summary.added} added</span>
          <span className='diff-removed-count'>−{summary.removed} removed</span>
        </span>
      </header>
      {before === after ? (
        <p className='diff-empty'>No text changes.</p>
      ) : (
        <>
          <div className='diff-lines' role='region' aria-label='Line changes' tabIndex={0}>
            {visibleGroups.map((group) => {
              if (group.collapsed)
                return (
                  <button
                    type='button'
                    key={group.key}
                    className='diff-expand'
                    onClick={() => setExpanded((current) => new Set([...current, group.key]))}
                  >
                    Show {group.lines.length} unchanged lines
                  </button>
                )
              return group.visible.map((line, index) => (
                <div key={`${group.key}-${index}`} className={`diff-line diff-line--${line.kind}`}>
                  <span className='diff-number' aria-hidden='true'>
                    {line.beforeLine}
                  </span>
                  <span className='diff-number' aria-hidden='true'>
                    {line.afterLine}
                  </span>
                  <span className='diff-marker' aria-label={line.kind}>
                    {line.kind === 'added' ? '+' : line.kind === 'removed' ? '−' : ' '}
                  </span>
                  <code>
                    {line.text.endsWith('\n') ? line.text.slice(0, -1) : line.text}
                    {!line.text.endsWith('\n') ? (
                      <span className='diff-no-newline'> ⏎ No newline at end of file</span>
                    ) : null}
                  </code>
                </div>
              ))
            })}
          </div>
          {remaining > 0 ? (
            <button type='button' className='diff-expand' onClick={() => setLimit((value) => value + 400)}>
              Show more lines ({remaining.toLocaleString()} remaining)
            </button>
          ) : null}
        </>
      )}
    </section>
  )
}

/** Explicitly reviewed conflict resolution only updates the local save precondition. */
export function ConflictReview({
  draft,
  current,
  loading,
  error,
  busy = false,
  canResolve,
  onResolve,
  onRetry,
  initiallyExpanded = false,
}: {
  draft: FileDraft
  current: WorkspaceFileContent | null
  loading: boolean
  error?: Error | null
  busy?: boolean
  canResolve: boolean
  onResolve: (draft: FileDraft) => void
  onRetry: () => void
  initiallyExpanded?: boolean
}) {
  const [expanded, setExpanded] = useState(initiallyExpanded)
  const [confirmed, setConfirmed] = useState(false)
  return (
    <section className='diff-conflict' aria-label={`Resolve conflict in ${draft.path}`}>
      <div className='diff-toolbar'>
        <p role='alert'>This file changed in the workspace. Your edits are preserved.</p>
        {!expanded ? (
          <button type='button' className='btn btn--outlined btn--small' onClick={() => setExpanded(true)}>
            Review conflict
          </button>
        ) : null}
      </div>
      {expanded ? (
        <>
          {error ? (
            <div className='diff-empty' role='alert'>
              {error.message}{' '}
              <button type='button' className='btn btn--outlined btn--small' onClick={onRetry}>
                Retry current file
              </button>
            </div>
          ) : loading ? (
            <p className='diff-empty' role='status'>
              Loading the current file…
            </p>
          ) : current && !current.editable ? (
            <p className='diff-empty'>
              The current file is binary. Discard your edits or save them under another name.
            </p>
          ) : (
            <>
              {!current ? (
                <p className='diff-empty'>
                  The file was deleted in the workspace. Keeping your edits will recreate it.
                </p>
              ) : null}
              <DiffView
                before={current?.content ?? ''}
                after={draft.content}
                beforeLabel='Current workspace file'
                afterLabel='My edits'
              />
              {canResolve ? (
                <div className='diff-conflict-actions'>
                  <label>
                    <input
                      type='checkbox'
                      checked={confirmed}
                      disabled={busy}
                      onChange={(event) => setConfirmed(event.target.checked)}
                    />
                    I reviewed the current file and want to keep my edits.
                  </label>
                  <button
                    type='button'
                    className='btn btn--outlined btn--small'
                    disabled={!confirmed || busy}
                    onClick={() =>
                      onResolve({ ...draft, hash: current?.hash ?? null, original: current?.content ?? '' })
                    }
                  >
                    Use my edits on current file
                  </button>
                  <p>This updates your draft. Review and save a version to publish it.</p>
                </div>
              ) : null}
            </>
          )}
        </>
      ) : null}
    </section>
  )
}

export function ChangesPanel({
  view,
  session,
  draftState,
}: {
  view: WorkspaceView
  session: WorkspaceSession
  draftState: WorkspaceDraftState
}) {
  const [selected, setSelected] = useState<string | null>(null)
  const paths = Array.from(
    new Set([
      ...(view.changes ?? []).map((change) => change.path),
      ...Object.values(draftState.drafts)
        .filter(isDirtyDraft)
        .map((draft) => draft.path),
    ]),
  ).toSorted()
  const path = selected && paths.includes(selected) ? selected : (paths[0] ?? '')
  const change = view.changes?.find((item) => item.path === path)
  const draft = draftState.drafts[path]
  const beforeHash = change ? change.beforeHash : (draft?.hash ?? null)
  const currentFile = view.files.find((file) => file.path === path)
  const afterHash = currentFile?.hash ?? null
  const after = useQuery({ ...workspaceFileOptions(view, session, path, null), enabled: !!path && !!currentFile })
  const currentHash = currentFile ? (after.data?.hash ?? currentFile.hash) : null
  const conflict = !!draft && draft.hash !== currentHash
  const before = useQuery({
    queryKey: [...workspaceKeys.scope(session), view.workspace.id, 'comparison', 'head', view.workspace.head, path],
    enabled: !!path && !!beforeHash && !conflict,
    queryFn: ({ signal }) =>
      workspaceRead<WorkspaceFileContent>(
        `/${encodeURIComponent(view.workspace.id)}/file?path=${encodeURIComponent(path)}&version=${encodeURIComponent(view.workspace.head!)}`,
        signal,
      ),
  })
  const status = change?.status ?? (draft?.hash === null ? 'added' : 'modified')
  const error = before.error ?? after.error
  const loading = (!!beforeHash && !before.data) || (!draft && !!afterHash && !after.data)
  const binary =
    (beforeHash && before.data && !before.data.editable) || (!draft && afterHash && after.data && !after.data.editable)
  return (
    <section className='diff-changes' aria-label='Project changes'>
      <nav className='diff-change-list' aria-label='Changed files'>
        {paths.map((name) => (
          <button
            type='button'
            key={name}
            aria-current={name === path ? 'true' : undefined}
            onClick={() => setSelected(name)}
          >
            <code>{name}</code>
            <span>
              {draftState.drafts[name] ? 'Edited locally' : view.changes?.find((item) => item.path === name)?.status}
            </span>
          </button>
        ))}
      </nav>
      <div className='diff-change-detail'>
        {!path ? (
          <p className='diff-empty'>No changes since the latest version.</p>
        ) : (
          <>
            <div className='diff-toolbar'>
              <code>{path}</code>
              <span>
                {status}
                {draft ? ' · Local edits' : ' · Workspace changes'}
              </span>
            </div>
            {conflict && draft ? (
              <ConflictReview
                key={JSON.stringify([view.workspace.id, path, currentHash, draft.hash])}
                draft={draft}
                current={currentFile ? (after.data ?? null) : null}
                loading={!!currentFile && (!after.data || after.isFetching)}
                error={after.error}
                canResolve={
                  view.isOwner &&
                  !!session &&
                  session.publicKey === view.workspace.ownerPublicKey &&
                  view.agentEnabled &&
                  view.task?.status !== 'running' &&
                  view.task?.status !== 'queued'
                }
                onResolve={draftState.setDraft}
                onRetry={() => {
                  void after.refetch()
                }}
                initiallyExpanded
              />
            ) : error ? (
              <p className='diff-empty' role='alert'>
                {error.message}
              </p>
            ) : loading ? (
              <p className='diff-empty' role='status'>
                Loading changes…
              </p>
            ) : binary ? (
              <p className='diff-empty'>Binary file changed. A text comparison is unavailable.</p>
            ) : (
              <DiffView
                before={beforeHash ? (before.data?.content ?? '') : ''}
                after={draft?.content ?? (afterHash ? (after.data?.content ?? '') : '')}
                beforeLabel='Latest version'
                afterLabel={draft ? 'Your edits' : 'Current files'}
              />
            )}
            {change?.beforeHash === change?.afterHash && change?.status === 'modified' ? (
              <p className='diff-empty'>File permissions changed.</p>
            ) : null}
          </>
        )}
      </div>
    </section>
  )
}
