'use client'

import { useQuery } from '@tanstack/react-query'
import { CaretRightIcon } from '@phosphor-icons/react/ssr'
import { useId, useState } from 'react'
import type { WorkspaceFile, WorkspaceVersion, WorkspaceView } from '../../lib/workspace-client'
import { workspaceFileOptions, workspaceViewOptions, type WorkspaceSession } from '../../lib/workspace-queries'
import { CopyButton } from '../copy-button'
import { PlayerLabel } from '../multiplayer/player-label'
import { formatBytes } from '../use-mkit'
import { DiffView } from './diff-view'
import './version-history.css'

export type VersionHistoryProps = {
  view: WorkspaceView
  session: WorkspaceSession
  busy: boolean
  canRestore: boolean
  onRestore: (version: WorkspaceVersion) => void
  onRemix: (version: WorkspaceVersion) => void
}

export type VersionFileChange = {
  path: string
  kind: 'added' | 'removed' | 'modified'
  before: WorkspaceFile | undefined
  after: WorkspaceFile | undefined
}

/** Compare actual snapshots, including removals and executable-bit changes. */
export function compareVersionFiles(before: WorkspaceFile[], after: WorkspaceFile[]): VersionFileChange[] {
  const previous = new Map(before.map((file) => [file.path, file]))
  const next = new Map(after.map((file) => [file.path, file]))
  const paths = new Set([...previous.keys(), ...next.keys()])
  return [...paths].toSorted().flatMap((path) => {
    const left = previous.get(path)
    const right = next.get(path)
    if (left && right && left.hash === right.hash && left.mode === right.mode) return []
    return [
      {
        path,
        kind: !left ? 'added' : !right ? 'removed' : 'modified',
        before: left,
        after: right,
      } satisfies VersionFileChange,
    ]
  })
}

export function VersionHistory(props: VersionHistoryProps) {
  if (!props.view.versions.length) return <p className='history-empty'>No saved versions yet.</p>
  return <HistoryBrowser key={props.view.workspace.id} {...props} />
}

function HistoryBrowser(props: VersionHistoryProps) {
  const { view } = props
  const [selected, setSelected] = useState<WorkspaceVersion>(
    () => view.versions.find((version) => version.hash === view.workspace.head) ?? view.versions[0]!,
  )

  return (
    <section className='history-panel' aria-label='Version history'>
      <aside className='history-timeline' aria-label='Saved versions'>
        <div className='history-list-heading'>
          <h3 className='ds-h3'>Saved versions</h3>
          <select
            className='history-mobile-select'
            aria-label='Saved version'
            value={selected.hash}
            onChange={(event) => {
              const version = view.versions.find((item) => item.hash === event.target.value)
              if (version) setSelected(version)
            }}
          >
            {view.versions.map((version) => (
              <option key={version.hash} value={version.hash}>
                {version.message}
                {version.hash === view.workspace.head ? ' · Latest' : ''}
              </option>
            ))}
          </select>
          {view.versions.length === 50 ? <p className='history-caption'>Most recent 50 versions</p> : null}
        </div>
        <ol className='history-list'>
          {view.versions.map((version) => (
            <li key={version.hash}>
              <button
                className='history-version'
                type='button'
                aria-pressed={selected.hash === version.hash}
                onClick={() => setSelected(version)}
              >
                <span className='history-version-message' title={version.message}>
                  {version.message}
                </span>
                <span className='history-version-meta'>
                  <VersionAuthor version={version} view={view} />
                  {version.hash === view.workspace.head ? <span className='history-latest'>Latest</span> : null}
                </span>
                <VersionTime timestamp={version.createdAt} />
              </button>
            </li>
          ))}
        </ol>
      </aside>
      <VersionDetail key={selected.hash} {...props} selected={selected} />
    </section>
  )
}

function VersionAuthor({ version, view }: { version: WorkspaceVersion; view: WorkspaceView }) {
  return version.signer === view.workspace.agentPublicKey ? (
    <span>nanocodex</span>
  ) : (
    <PlayerLabel pubkey={version.signer} />
  )
}

function VersionTime({ timestamp }: { timestamp: number }) {
  const date = new Date(timestamp)
  return (
    <time dateTime={date.toISOString()} title={date.toISOString()}>
      {new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)}
    </time>
  )
}

function VersionDetail({
  view,
  session,
  busy,
  canRestore,
  onRestore,
  onRemix,
  selected,
}: VersionHistoryProps & { selected: WorkspaceVersion }) {
  const [comparison, setComparison] = useState<'parent' | 'current'>('parent')
  const [metadataOpen, setMetadataOpen] = useState(false)
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const metadataId = useId()
  const current = comparison === 'current'
  const selectedQuery = useQuery(workspaceViewOptions(view.workspace.id, session, selected.hash))
  const referenceQuery = useQuery({
    ...workspaceViewOptions(view.workspace.id, session, current ? null : selected.parent),
    enabled: session !== undefined && (current || !!selected.parent),
  })
  const beforeView = current ? selectedQuery.data : selected.parent ? referenceQuery.data : undefined
  const afterView = current ? referenceQuery.data : selectedQuery.data
  const beforeVersion = current ? selected.hash : selected.parent
  const afterVersion = current ? null : selected.hash
  const needsReference = current || !!selected.parent
  const pending = selectedQuery.isPending || (needsReference && referenceQuery.isPending)
  const error = selectedQuery.error ?? (needsReference ? referenceQuery.error : null)
  const changes = !pending && !error && afterView ? compareVersionFiles(beforeView?.files ?? [], afterView.files) : []
  const selectedChange = changes.find((change) => change.path === selectedPath) ?? changes[0]
  const labels = current
    ? { before: 'Selected saved version', after: 'Current files' }
    : { before: selected.parent ? 'Parent version' : 'Before the first version', after: 'Selected saved version' }

  return (
    <div className='history-detail'>
      <header className='history-detail-heading'>
        <p className='history-caption'>Selected saved version</p>
        <h3 className='ds-h3'>{selected.message}</h3>
        <div className='history-hash'>
          <code title={selected.hash}>
            {selected.hash.slice(0, 7)}…{selected.hash.slice(-3)}
          </code>
          <span title='Copy full version hash'>
            <CopyButton text={selected.hash} label='Copy full version hash' />
          </span>
        </div>
        <p className='history-byline'>
          <VersionAuthor version={selected} view={view} />
          <span aria-hidden='true'> · </span>
          <VersionTime timestamp={selected.createdAt} />
        </p>
        <button
          className='history-disclosure'
          type='button'
          aria-expanded={metadataOpen}
          aria-controls={metadataId}
          onClick={() => setMetadataOpen(!metadataOpen)}
        >
          <CaretRightIcon size={12} aria-hidden='true' /> Version details
        </button>
        {metadataOpen ? (
          <dl className='history-metadata' id={metadataId}>
            <dt>Version</dt>
            <dd>
              <code>{selected.hash}</code>
            </dd>
            <div>
              <dt>Signer</dt>
              <dd>
                <code>{selected.signer}</code>
              </dd>
            </div>
            <div>
              <dt>Parent</dt>
              <dd>{selected.parent ? <code>{selected.parent}</code> : 'None — first saved version'}</dd>
            </div>
            <div>
              <dt>Source</dt>
              <dd>
                {view.workspace.source.repository}
                <code>{view.workspace.source.commitHash}</code>
              </dd>
            </div>
          </dl>
        ) : null}
      </header>

      <div className='history-comparison-toolbar'>
        <div className='history-segments' role='radiogroup' aria-label='Version comparison'>
          {(['parent', 'current'] as const).map((mode) => (
            <button
              key={mode}
              className='history-segment'
              type='button'
              role='radio'
              aria-checked={comparison === mode}
              tabIndex={comparison === mode ? 0 : -1}
              onClick={() => setComparison(mode)}
              onKeyDown={(event) => {
                if (['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) {
                  event.preventDefault()
                  const next =
                    event.key === 'Home'
                      ? 'parent'
                      : event.key === 'End'
                        ? 'current'
                        : mode === 'parent'
                          ? 'current'
                          : 'parent'
                  setComparison(next)
                  const buttons =
                    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="radio"]')
                  buttons?.[next === 'parent' ? 0 : 1]?.focus()
                }
              }}
            >
              {mode === 'parent' ? 'Changes in this version' : 'Compare with current files'}
            </button>
          ))}
        </div>
        {current ? (
          <p className='history-caption'>Changes from this saved version to the current workspace files.</p>
        ) : (
          <p className='history-caption'>
            {selected.parent
              ? 'Changes from the parent version to this saved version.'
              : 'Files added in the first saved version.'}
          </p>
        )}
      </div>

      {error ? (
        <div className='history-empty' role='alert'>
          <p>Could not load this version comparison.</p>
          <button
            className='btn btn--outlined btn--small'
            type='button'
            onClick={() => {
              void selectedQuery.refetch()
              if (needsReference) void referenceQuery.refetch()
            }}
          >
            Try again
          </button>
        </div>
      ) : pending ? (
        <p className='history-empty' role='status'>
          Loading saved files…
        </p>
      ) : !changes.length ? (
        <p className='history-empty'>No file changes between these versions.</p>
      ) : (
        <>
          <p className='history-change-counts'>
            {changes.filter((change) => change.kind === 'added').length} added ·{' '}
            {changes.filter((change) => change.kind === 'removed').length} removed ·{' '}
            {changes.filter((change) => change.kind === 'modified').length} modified
          </p>
          <div className='history-files'>
            <nav aria-label='Changed files' className='history-file-list'>
              {changes.map((change) => (
                <button
                  className='history-file'
                  type='button'
                  key={change.path}
                  aria-pressed={selectedChange?.path === change.path}
                  aria-label={`${change.path} ${change.kind === 'added' ? 'Added' : change.kind === 'removed' ? 'Removed' : 'Modified'}`}
                  onClick={() => setSelectedPath(change.path)}
                >
                  <code>{change.path}</code>
                  <span className={`history-change-kind history-change-${change.kind}`}>
                    {change.kind === 'added' ? 'Added' : change.kind === 'removed' ? 'Removed' : 'Modified'}
                  </span>
                </button>
              ))}
            </nav>
            {selectedChange && afterView ? (
              <VersionFileDetail
                key={JSON.stringify([
                  selectedChange.path,
                  beforeVersion,
                  afterVersion,
                  selectedChange.before?.hash,
                  selectedChange.after?.hash,
                ])}
                change={selectedChange}
                beforeView={beforeView}
                afterView={afterView}
                beforeVersion={beforeVersion}
                afterVersion={afterVersion}
                session={session}
                labels={labels}
              />
            ) : null}
          </div>
        </>
      )}
      <footer className='history-actions'>
        <span
          title={
            !canRestore
              ? 'Only the owner can restore while workspace execution is enabled and idle.'
              : busy
                ? 'Wait for the current action to finish.'
                : 'Create a new version containing these saved files.'
          }
        >
          <button
            className='btn btn--outlined btn--small'
            type='button'
            disabled={!canRestore || busy}
            onClick={() => onRestore(selected)}
          >
            Restore as new version
          </button>
        </span>
        <span
          title={
            !session
              ? 'Sign in to remix this version.'
              : busy
                ? 'Wait for the current action to finish.'
                : 'Create a separate workspace from these saved files.'
          }
        >
          <button
            className='btn btn--outlined btn--small'
            type='button'
            disabled={!session || busy}
            onClick={() => onRemix(selected)}
          >
            Remix this version
          </button>
        </span>
      </footer>
    </div>
  )
}

function VersionFileDetail({
  change,
  beforeView,
  afterView,
  beforeVersion,
  afterVersion,
  session,
  labels,
}: {
  change: VersionFileChange
  beforeView: WorkspaceView | undefined
  afterView: WorkspaceView
  beforeVersion: string | null
  afterVersion: string | null
  session: WorkspaceSession
  labels: { before: string; after: string }
}) {
  const beforeQuery = useQuery(
    workspaceFileOptions(beforeView ?? afterView, session, change.before ? change.path : '', beforeVersion),
  )
  const afterQuery = useQuery(workspaceFileOptions(afterView, session, change.after ? change.path : '', afterVersion))
  const pending = (change.before && beforeQuery.isPending) || (change.after && afterQuery.isPending)
  const error = (change.before && beforeQuery.error) || (change.after && afterQuery.error)
  const nonText =
    (change.before && beforeQuery.data?.editable === false) || (change.after && afterQuery.data?.editable === false)
  return (
    <section className='history-file-detail' aria-label={`Changes to ${change.path}`}>
      <h4 className='history-file-heading'>
        <code>{change.path}</code>
      </h4>
      {pending ? (
        <p className='history-empty' role='status'>
          Loading file comparison…
        </p>
      ) : error ? (
        <div className='history-empty' role='alert'>
          <p>Could not load this file comparison.</p>
          <button
            className='btn btn--outlined btn--small'
            type='button'
            onClick={() => {
              if (change.before) void beforeQuery.refetch()
              if (change.after) void afterQuery.refetch()
            }}
          >
            Try again
          </button>
        </div>
      ) : nonText ? (
        <div className='history-binary'>
          <p>This file cannot be compared as text.</p>
          <FileMetadata label={labels.before} file={change.before} />
          <FileMetadata label={labels.after} file={change.after} />
        </div>
      ) : (
        <>
          {change.before && change.after && change.before.mode !== change.after.mode ? (
            <p className='history-caption'>
              File permission changed from {change.before.mode === 'exec' ? 'executable' : 'regular'} to{' '}
              {change.after.mode === 'exec' ? 'executable' : 'regular'}.
            </p>
          ) : null}
          <DiffView
            before={change.before ? (beforeQuery.data?.content ?? '') : ''}
            after={change.after ? (afterQuery.data?.content ?? '') : ''}
            beforeLabel={labels.before}
            afterLabel={labels.after}
          />
        </>
      )}
    </section>
  )
}

function FileMetadata({ label, file }: { label: string; file: WorkspaceFile | undefined }) {
  return (
    <div className='history-file-metadata'>
      <h5>{label}</h5>
      {file ? (
        <>
          <p>
            {formatBytes(file.size)} · {file.mode === 'exec' ? 'Executable file' : 'Regular file'}
          </p>
          <code>{file.hash}</code>
        </>
      ) : (
        <p>File absent</p>
      )}
    </div>
  )
}
