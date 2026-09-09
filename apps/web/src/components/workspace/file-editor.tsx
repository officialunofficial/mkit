'use client'
import { useQuery } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { WorkspaceView } from '../../lib/workspace-client'
import { workspaceFileOptions, type WorkspaceSession } from '../../lib/workspace-queries'
import { isDirtyDraft, type WorkspaceDraftState } from './editor-state'
import { ConflictReview } from './diff-view'
import './file-editor.css'

export type FileEditorProps = {
  view: WorkspaceView
  session?: WorkspaceSession
  canEdit: boolean
  busy: boolean
  draftState: WorkspaceDraftState
  onReview: () => void
  readonlyNotice?: string
}

export function FileEditor({
  view,
  session = null,
  canEdit,
  busy,
  draftState,
  onReview,
  readonlyNotice,
}: FileEditorProps) {
  const [selected, setSelected] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [creating, setCreating] = useState(false)
  const [newPath, setNewPath] = useState('')
  const [error, setError] = useState<string | null>(null)
  const gutter = useRef<HTMLDivElement>(null)
  const paths = Array.from(
    new Set([...view.files.map((file) => file.path), ...Object.keys(draftState.drafts)]),
  ).toSorted()
  const path =
    selected && paths.includes(selected)
      ? selected
      : (paths.find((value) => /^readme(?:\.|$)/i.test(value)) ?? paths[0] ?? '')
  const local = draftState.drafts[path]
  const serverFile = view.files.find((entry) => entry.path === path)
  const query = useQuery({
    ...workspaceFileOptions(view, session, path, null),
    enabled: !!path && !!serverFile,
  })
  const file = local ?? (query.data ? { ...query.data, original: query.data.content } : null)
  const changed = !!local && isDirtyDraft(local)
  const editable = canEdit && !busy && !!file?.editable
  const currentHash = serverFile ? (query.data?.hash ?? serverFile.hash) : null
  const conflict = !!local && local.hash !== currentHash
  const matching = paths.filter((value) => value.toLowerCase().includes(search.toLowerCase()))
  return (
    <section className='editor-layout' aria-label='Files and editor'>
      <aside className='editor-explorer'>
        <div className='editor-explorer-heading'>
          <span>
            Files <span className='editor-muted'>{paths.length}</span>
          </span>
          {canEdit ? (
            <button
              type='button'
              className='btn btn--ghost btn--small'
              disabled={busy}
              onClick={() => setCreating((value) => !value)}
              aria-expanded={creating}
            >
              New file
            </button>
          ) : null}
        </div>
        <div className='editor-search'>
          <input
            type='search'
            aria-label='Search files'
            placeholder='Find a file…'
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>
        {creating ? (
          <form
            className='editor-new-file'
            onSubmit={(event) => {
              event.preventDefault()
              const value = newPath.trim()
              if (
                !value ||
                value.startsWith('/') ||
                value.split('/').some((part) => !part || part === '.' || part === '..') ||
                value.includes('\\') ||
                value.includes('\0')
              ) {
                setError('Use a relative file path, such as src/main.js.')
                return
              }
              if (!paths.includes(value))
                draftState.setDraft({ path: value, content: '', original: '', hash: null, editable: true })
              setSelected(value)
              setSearch('')
              setCreating(false)
              setNewPath('')
              setError(null)
            }}
          >
            <input
              aria-label='New file path'
              placeholder='src/main.js'
              value={newPath}
              onChange={(event) => setNewPath(event.target.value)}
            />
            <div>
              <button className='btn btn--outlined btn--small' disabled={busy || !newPath.trim()}>
                Create file
              </button>{' '}
              <button type='button' className='btn btn--ghost btn--small' onClick={() => setCreating(false)}>
                Cancel
              </button>
            </div>
          </form>
        ) : null}
        <nav aria-label='Project files' className='editor-file-list'>
          {matching.map((name) => {
            const draft = draftState.drafts[name]
            const modified = !!draft && isDirtyDraft(draft)
            const size = draft
              ? new TextEncoder().encode(draft.content).length
              : (view.files.find((entry) => entry.path === name)?.size ?? 0)
            return (
              <button
                key={name}
                type='button'
                className='editor-file-row'
                aria-current={path === name ? 'true' : undefined}
                aria-label={`${name}${modified ? ', modified' : ''}`}
                onClick={() => {
                  setSelected(name)
                  setError(null)
                }}
              >
                <span className='editor-file-name' title={name}>
                  {name}
                </span>
                <span className='editor-file-size'>
                  {modified ? (
                    <span title='Unsaved edits' aria-hidden='true'>
                      ●{' '}
                    </span>
                  ) : null}
                  {size.toLocaleString()} B
                </span>
              </button>
            )
          })}
          {!matching.length ? (
            <p className='editor-empty'>{paths.length ? 'No matching files.' : 'No files yet.'}</p>
          ) : null}
        </nav>
      </aside>
      <div className='editor-main'>
        <header className='editor-toolbar'>
          <div className='editor-path'>
            <code>{path || 'No file selected'}</code>
            {changed ? <span className='editor-muted'>{local?.hash === null ? 'New file' : 'Modified'}</span> : null}
          </div>
          {canEdit ? (
            <button
              type='button'
              className='btn btn--outlined btn--small'
              disabled={busy || !(draftState.dirty || view.changes?.length)}
              onClick={onReview}
            >
              Review changes
            </button>
          ) : null}
        </header>
        {readonlyNotice || !canEdit ? (
          <p className='editor-notice'>{readonlyNotice ?? 'Read-only project. Remix it to make changes.'}</p>
        ) : null}
        {conflict && local ? (
          <ConflictReview
            key={JSON.stringify([view.workspace.id, path, currentHash, local.hash])}
            draft={local}
            current={serverFile ? (query.data ?? null) : null}
            loading={!!serverFile && (!query.data || query.isFetching)}
            error={query.error}
            busy={busy}
            canResolve={canEdit}
            onResolve={draftState.setDraft}
            onRetry={() => {
              void query.refetch()
            }}
          />
        ) : null}
        {error || query.error ? (
          <p role='alert' className='editor-notice'>
            {error ?? query.error?.message}
          </p>
        ) : null}
        {file ? (
          <>
            <div className='editor-code'>
              <div className='editor-line-numbers' aria-hidden='true' ref={gutter}>
                {Array.from({ length: file.content.split('\n').length }, (_, index) => String(index + 1)).join('\n')}
              </div>
              <textarea
                aria-label='File content'
                wrap='off'
                spellCheck={false}
                autoCapitalize='off'
                autoCorrect='off'
                readOnly={!editable}
                value={file.content}
                onScroll={(event) => {
                  if (gutter.current) gutter.current.scrollTop = event.currentTarget.scrollTop
                }}
                onKeyDown={(event) => {
                  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 's') {
                    event.preventDefault()
                    if (canEdit && !busy) onReview()
                  }
                }}
                onChange={(event) => {
                  if (editable) draftState.setDraft({ ...file, path, content: event.target.value })
                }}
              />
            </div>
            <footer className='editor-footer'>
              <span>
                {file.editable
                  ? `${file.content.split('\n').length.toLocaleString()} lines · UTF-8`
                  : 'Binary file · text editing unavailable'}
              </span>
              {changed && canEdit ? (
                <button
                  type='button'
                  className='btn btn--ghost btn--small'
                  disabled={busy}
                  onClick={() => draftState.discard(path)}
                >
                  Discard file edits
                </button>
              ) : null}
            </footer>
          </>
        ) : (
          <p role='status' className='editor-empty'>
            {path ? 'Loading file…' : 'Create a file to start editing.'}
          </p>
        )}
      </div>
    </section>
  )
}
