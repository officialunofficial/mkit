'use client'
import * as Tabs from '@radix-ui/react-tabs'
import {
  ArrowsSplitIcon,
  CaretRightIcon,
  CheckCircleIcon,
  ClockCounterClockwiseIcon,
  CodeIcon,
  FloppyDiskIcon,
  GitDiffIcon,
  GlobeIcon,
  TerminalWindowIcon,
} from '@phosphor-icons/react/ssr'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { Link, useRouter } from 'waku'
import { mkit } from '../../lib/mkit'
import { remixWorkspace, workspaceWrite, type WorkspaceVersion, type WorkspaceView } from '../../lib/workspace-client'
import { workspaceKeys, workspaceListOptions, workspaceViewOptions } from '../../lib/workspace-queries'
import { useAuth } from '../auth-provider'
import { PlayerAvatar, PlayerLabel } from '../multiplayer/player-label'
import { AgentPanel } from './agent-panel'
import { useWorkspaceDrafts } from './editor-state'
import { FileEditor } from './file-editor'
import { ChangesPanel } from './diff-view'
import { WorkspaceTerminal } from './terminal'
import { VersionHistory } from './version-history'
import { WorkspaceDialog } from './workspace-dialog'
import { WorkspaceMenu } from './workspace-menu'
import './workspace.css'

type Dialog =
  | { kind: 'save' | 'details' | 'revoke' | 'conversation' | 'discard' }
  | { kind: 'restore'; version: WorkspaceVersion }
  | { kind: 'remix'; version?: WorkspaceVersion }
  | { kind: 'leave'; href: string }

export function CodingWorkspace() {
  const router = useRouter()
  const auth = useAuth()
  if (auth.session === undefined)
    return (
      <div className='ws-loading' role='status'>
        Loading workspace…
      </div>
    )
  const params = new URLSearchParams(router.query)
  const workspaceId = params.get('id')
  const sourceId = params.get('source')
  return (
    <WorkspaceContent
      key={JSON.stringify([workspaceId, sourceId, auth.session?.id, auth.session?.publicKey])}
      workspaceId={workspaceId}
      sourceId={sourceId}
    />
  )
}

function WorkspaceContent({ workspaceId, sourceId }: { workspaceId: string | null; sourceId: string | null }) {
  const auth = useAuth()
  const router = useRouter()
  const qc = useQueryClient()
  const viewQuery = useQuery(workspaceViewOptions(workspaceId ?? '', auth.session))
  const listQuery = useQuery({ ...workspaceListOptions(auth.session), enabled: !workspaceId })
  const view = viewQuery.data
  const workspaces = listQuery.data?.workspaces ?? []
  const drafts = useWorkspaceDrafts(JSON.stringify([auth.session?.id, auth.session?.publicKey, workspaceId]))
  const [tab, setTab] = useState('files')
  const [terminalOpen, setTerminalOpen] = useState(false)
  const [dialog, setDialog] = useState<Dialog | null>(null)
  const [message, setMessage] = useState('')
  const [notice, setNotice] = useState<string | null>(null)
  const mounted = useRef(true)
  useLayoutEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])
  useEffect(() => {
    if (!drafts.dirty) return
    const leave = (event: MouseEvent) => {
      if (
        event.defaultPrevented ||
        event.button !== 0 ||
        event.metaKey ||
        event.ctrlKey ||
        event.shiftKey ||
        event.altKey
      )
        return
      const link = event.target instanceof Element ? event.target.closest('a') : null
      if (!link || link.hasAttribute('download') || (link.target && link.target !== '_self')) return
      const url = new URL(link.href, location.href)
      if (
        !['http:', 'https:'].includes(url.protocol) ||
        (url.origin === location.origin && url.pathname === location.pathname && url.search === location.search)
      )
        return
      event.preventDefault()
      event.stopPropagation()
      setDialog({ kind: 'leave', href: url.href })
    }
    document.addEventListener('click', leave, true)
    return () => {
      document.removeEventListener('click', leave, true)
    }
  }, [drafts.dirty])
  const owner = !!view && view.isOwner && !!auth.session && view.workspace.ownerPublicKey === auth.session.publicKey
  const active = view?.task?.status === 'queued' || view?.task?.status === 'running'
  const mutation = useMutation({
    mutationKey: [...workspaceKeys.scope(auth.session), workspaceId, 'write'],
    gcTime: 0,
    scope: { id: JSON.stringify(workspaceKeys.scope(auth.session)) + workspaceId },
    mutationFn: async (request: { action: string; body: unknown; epoch: number }) => {
      const expectedKey = request.action === 'remix' ? auth.session?.publicKey : view?.workspace.ownerPublicKey
      const api = await mkit()
      const identity = await auth.ensureSigning(expectedKey)
      if (!mounted.current || auth.epoch() !== request.epoch)
        throw new Error('The workspace or identity changed. Try again.')
      const next =
        request.action === 'remix'
          ? await remixWorkspace(api, identity, request.body as Parameters<typeof remixWorkspace>[2])
          : await workspaceWrite<WorkspaceView>(
              api,
              identity,
              workspaceId!,
              `/${encodeURIComponent(workspaceId!)}/${request.action}`,
              request.body,
            )
      if (!mounted.current || auth.epoch() !== request.epoch)
        throw new Error('The workspace or identity changed. Try again.')
      const key = workspaceKeys.view(next.workspace.id, auth.session)
      await qc.cancelQueries({ queryKey: key })
      if (!mounted.current || auth.epoch() !== request.epoch)
        throw new Error('The workspace or identity changed. Try again.')
      qc.setQueryData<WorkspaceView>(key, (current) =>
        current && current.workspace.updatedAt > next.workspace.updatedAt ? current : next,
      )
      void qc.invalidateQueries({ queryKey: [...workspaceKeys.scope(auth.session), next.workspace.id, 'file'] })
      return next.workspace.id
    },
  })
  const busy = mutation.isPending || auth.pending
  const canEdit = owner && !active && !!view?.agentEnabled
  const draftEntries = Object.values(drafts.drafts)
  const changedPaths = new Set([
    ...(view?.changes ?? []).map((change) => change.path),
    ...draftEntries.map((draft) => draft.path),
  ])
  const changeCount = changedPaths.size
  const error = mutation.error?.message ?? viewQuery.error?.message ?? listQuery.error?.message
  const review = () => setTab('changes')
  const openSave = () => {
    setMessage('')
    mutation.reset()
    setDialog({ kind: 'save' })
  }
  async function write(action: string, body: unknown): Promise<boolean> {
    if (!workspaceId) return false
    try {
      await mutation.mutateAsync({ action, body, epoch: auth.epoch() })
      return mounted.current
    } catch {
      void qc.invalidateQueries({ queryKey: workspaceKeys.view(workspaceId, auth.session) })
      void qc.invalidateQueries({ queryKey: [...workspaceKeys.scope(auth.session), workspaceId, 'file'] })
      return false
    }
  }
  async function saveVersion() {
    if (!canEdit || !message.trim() || (!changeCount && !terminalOpen)) return
    if (
      await write('versions', {
        message: message.trim(),
        edits: draftEntries.map((draft) => ({ path: draft.path, content: draft.content, expectedHash: draft.hash })),
      })
    ) {
      drafts.clear()
      setDialog(null)
      setNotice('Version saved. All project changes are included.')
    }
  }
  async function remix(version?: WorkspaceVersion) {
    const source = workspaceId ?? sourceId
    try {
      const nextId = await mutation.mutateAsync({
        action: 'remix',
        epoch: auth.epoch(),
        body: source
          ? { kind: 'workspace', workspaceId: source, ...(version ? { commitHash: version.hash } : {}) }
          : { kind: 'demo' },
      })
      if (mounted.current) {
        drafts.clear()
        router.push(`/create?id=${encodeURIComponent(nextId)}`)
      }
    } catch {
      /* Inline mutation error preserves the current workspace and drafts. */
    }
  }
  const cancelDialog = () => {
    if (!busy) setDialog(null)
  }
  const footerCancel = (
    <button className='btn btn--outlined' disabled={busy} onClick={cancelDialog}>
      Cancel
    </button>
  )

  if (!workspaceId)
    return (
      <div className='ws-projects'>
        <header className='ws-projects-heading'>
          <div>
            <div className='ws-eyebrow'>mkit / create</div>
            <h1>{sourceId ? 'Create a remix' : 'Projects'}</h1>
            <p className='ws-note'>Public files. A working terminal. An agent that saves its work.</p>
          </div>
          <button className='btn btn--solid' disabled={!auth.session || busy} onClick={() => void remix()}>
            <ArrowsSplitIcon size={15} aria-hidden />
            {busy ? 'Creating…' : sourceId ? 'Remix this project' : 'Remix demo'}
          </button>
        </header>
        {!auth.session ? (
          <p className='ws-note'>
            Sign in using Account above to create a project. Public projects are open to explore.
          </p>
        ) : null}
        {error ? (
          <p className='ws-inline-error' role='alert'>
            {error}
          </p>
        ) : null}
        <div className='ws-project-list' aria-label='Public projects'>
          <div className='ws-project-list-heading'>
            <span>Project</span>
            <span>Owner</span>
            <span>Updated</span>
          </div>
          {workspaces.map((workspace) => (
            <Link to={`/create?id=${encodeURIComponent(workspace.id)}`} className='ws-project-row' key={workspace.id}>
              <span className='ws-project-title'>
                <CodeIcon size={16} aria-hidden />
                <strong>{workspace.title}</strong>
              </span>
              <span className='ws-inline'>
                <PlayerAvatar pubkey={workspace.ownerPublicKey} size={18} />
                <PlayerLabel pubkey={workspace.ownerPublicKey} />
              </span>
              <time dateTime={new Date(workspace.updatedAt).toISOString()}>
                {new Date(workspace.updatedAt).toLocaleDateString()}
              </time>
            </Link>
          ))}
          {!workspaces.length ? (
            <div className='ws-empty'>
              <h2>{listQuery.isPending ? 'Loading projects…' : 'Your next project starts here'}</h2>
              <p>Remix the demo to get a workspace with files, a terminal, and version history.</p>
            </div>
          ) : null}
        </div>
      </div>
    )
  if (!view)
    return (
      <div className='ws-loading' role='status'>
        {error ?? 'Loading workspace…'}
        {viewQuery.isError ? (
          <button className='btn btn--outlined btn--small' onClick={() => void viewQuery.refetch()}>
            Try again
          </button>
        ) : null}
      </div>
    )

  return (
    <div className='ws-workspace'>
      <header className='ws-project-header'>
        <nav aria-label='Workspace breadcrumb' className='ws-breadcrumb'>
          <Link to='/create'>Projects</Link>
          <CaretRightIcon size={12} aria-hidden />
          <span>{view.workspace.title}</span>
        </nav>
        <div className='ws-project-heading'>
          <div className='ws-project-identity'>
            <CodeIcon size={23} weight='light' aria-hidden />
            <div>
              <h1>{view.workspace.title}</h1>
              <div className='ws-project-meta'>
                <span className='ws-inline'>
                  <GlobeIcon size={12} aria-hidden />
                  Public
                </span>
                <span className='ws-inline'>
                  <PlayerAvatar pubkey={view.workspace.ownerPublicKey} size={16} />
                  <PlayerLabel pubkey={view.workspace.ownerPublicKey} />
                  {owner ? <span className='ws-you'>you</span> : null}
                </span>
              </div>
            </div>
          </div>
          <div className='ws-project-actions'>
            <button
              className='btn btn--outlined btn--small'
              disabled={!auth.session || busy}
              onClick={() => setDialog({ kind: 'remix' })}
            >
              <ArrowsSplitIcon size={14} aria-hidden />
              Remix
            </button>
            <WorkspaceMenu
              onDetails={() => setDialog({ kind: 'details' })}
              onRevoke={() => setDialog({ kind: 'revoke' })}
              canRevoke={owner && view.agentEnabled && !busy}
            />
          </div>
        </div>
      </header>
      {error && !dialog ? (
        <p className='ws-inline-error' role='alert'>
          {error}
        </p>
      ) : null}
      <div className={`ws-layout ${owner ? 'ws-layout--owner' : ''}`}>
        <section className='ws-main' aria-label='Project workbench'>
          <Tabs.Root value={tab} onValueChange={setTab}>
            <div className='ws-workbench-toolbar'>
              <Tabs.List className='ws-tabs' aria-label='Workspace views'>
                <Tabs.Trigger value='files'>
                  <CodeIcon size={14} aria-hidden />
                  Files<span className='ws-count'>{view.files.length}</span>
                </Tabs.Trigger>
                <Tabs.Trigger value='changes'>
                  <GitDiffIcon size={14} aria-hidden />
                  Changes<span className='ws-count'>{changeCount}</span>
                </Tabs.Trigger>
                <Tabs.Trigger value='versions'>
                  <ClockCounterClockwiseIcon size={14} aria-hidden />
                  History<span className='ws-count'>{view.versions.length}</span>
                </Tabs.Trigger>
              </Tabs.List>
              {owner ? (
                <button
                  className='btn btn--solid btn--small ws-save'
                  disabled={busy || !canEdit || (!changeCount && !terminalOpen)}
                  onClick={openSave}
                >
                  <FloppyDiskIcon size={13} aria-hidden />
                  Save version
                </button>
              ) : null}
            </div>
            <div className='ws-working-status'>
              <span className='ws-inline'>
                {changeCount ? <GitDiffIcon size={13} aria-hidden /> : <CheckCircleIcon size={13} aria-hidden />}
                {changeCount
                  ? `${changeCount} changed ${changeCount === 1 ? 'file' : 'files'}`
                  : 'No changes since latest version'}
                {draftEntries.length ? (
                  <span className='ws-browser-edits'>· {draftEntries.length} in browser</span>
                ) : null}
              </span>
              <button
                className='ws-head-link'
                onClick={() => setTab('versions')}
                title={view.workspace.head ?? 'No saved version'}
              >
                Latest{' '}
                <code>
                  {view.workspace.head ? `${view.workspace.head.slice(0, 7)}…${view.workspace.head.slice(-3)}` : '—'}
                </code>
              </button>
            </div>
            <Tabs.Content value='files' className='ws-tab-panel'>
              <FileEditor
                view={view}
                session={auth.session}
                canEdit={canEdit}
                busy={busy}
                draftState={drafts}
                onReview={review}
              />
              {!canEdit ? (
                <p className='ws-permission-note'>
                  {active
                    ? 'The agent is changing files. Editing resumes when it finishes.'
                    : owner
                      ? 'Agent access is disabled or expired. Remix a saved version to keep working.'
                      : 'You’re viewing a public project. Remix a saved version to make it your own.'}
                </p>
              ) : null}
            </Tabs.Content>
            <Tabs.Content value='changes' className='ws-tab-panel'>
              <ChangesPanel view={view} session={auth.session} draftState={drafts} />
              {draftEntries.length > 0 ? (
                <div className='ws-review-footer'>
                  <span>
                    {draftEntries.length} browser {draftEntries.length === 1 ? 'edit' : 'edits'} · kept while you browse
                    this workspace
                  </span>
                  <button
                    className='btn btn--ghost btn--small'
                    disabled={busy}
                    onClick={() => setDialog({ kind: 'discard' })}
                  >
                    Discard browser edits
                  </button>
                </div>
              ) : null}
            </Tabs.Content>
            <Tabs.Content value='versions' className='ws-tab-panel'>
              <VersionHistory
                view={view}
                session={auth.session}
                busy={busy}
                canRestore={canEdit && !drafts.dirty}
                onRestore={(version) => setDialog({ kind: 'restore', version })}
                onRemix={(version) => setDialog({ kind: 'remix', version })}
              />
            </Tabs.Content>
          </Tabs.Root>
          {owner ? (
            <section className='ws-terminal-disclosure'>
              <button
                className='ws-terminal-trigger'
                aria-expanded={terminalOpen}
                aria-controls='workspace-terminal'
                onClick={() => setTerminalOpen(!terminalOpen)}
              >
                <span className='ws-inline'>
                  <CaretRightIcon size={13} className={terminalOpen ? 'ws-caret--open' : ''} aria-hidden />
                  <TerminalWindowIcon size={14} aria-hidden />
                  Terminal
                </span>
                <span>{active ? 'Paused during task' : terminalOpen ? 'Hide terminal' : 'Open a shell'}</span>
              </button>
              {terminalOpen ? (
                <div id='workspace-terminal'>
                  {active || !view.agentEnabled ? (
                    <p className='ws-permission-note'>
                      {active
                        ? 'The terminal is paused while nanocodex runs. It opens again when the task finishes.'
                        : 'Workspace execution is disabled. Remix a saved version to use a terminal again.'}
                    </p>
                  ) : (
                    <WorkspaceTerminal workspaceId={view.workspace.id} />
                  )}
                  <p className='ws-terminal-note'>
                    Terminal changes update working files. Save a version to add them to history.
                  </p>
                </div>
              ) : null}
            </section>
          ) : null}
        </section>
        {owner ? (
          <AgentPanel
            view={view}
            busy={busy}
            draftCount={draftEntries.length}
            onRun={(prompt) => write('tasks', { prompt })}
            onStop={() => void write('cancel', {})}
            onReview={review}
            onNewConversation={() => setDialog({ kind: 'conversation' })}
          />
        ) : null}
      </div>
      <footer className='ws-footer'>
        <span className='ws-inline'>
          <ArrowsSplitIcon size={12} aria-hidden />
          Remixed from{' '}
          {view.workspace.source.workspaceId ? (
            <Link to={`/create?id=${encodeURIComponent(view.workspace.source.workspaceId)}`}>another project</Link>
          ) : (
            <Link to='/multiplayer'>the demo repository</Link>
          )}
          <code title={view.workspace.source.commitHash}>
            {view.workspace.source.commitHash.slice(0, 7)}…{view.workspace.source.commitHash.slice(-3)}
          </code>
        </span>
        <span role='status'>{notice ?? 'Saved versions are public and signed'}</span>
      </footer>

      {dialog?.kind === 'save' ? (
        <WorkspaceDialog
          title='Save a project version'
          onClose={cancelDialog}
          footer={
            <>
              {footerCancel}
              <button
                className='btn btn--solid'
                disabled={busy || !canEdit || !message.trim() || (!changeCount && !terminalOpen)}
                onClick={() => void saveVersion()}
              >
                {busy ? 'Saving…' : 'Save version'}
              </button>
            </>
          }
        >
          <p>
            {changeCount
              ? `Save all ${changeCount} changed ${changeCount === 1 ? 'file' : 'files'} together as one version.`
              : 'Capture the current working files as one version.'}
          </p>
          <ul className='ws-save-files'>
            {[...changedPaths].map((path) => (
              <li key={path}>
                <code>{path}</code>
                <span>{drafts.drafts[path] ? 'Browser edit' : 'Working file'}</span>
              </li>
            ))}
          </ul>
          <label className='ws-field'>
            Version message
            <input
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              placeholder='What changed, and why?'
              maxLength={200}
              disabled={busy}
            />
          </label>
          <p className='ws-note'>
            Includes browser edits and changes from the terminal. The project signer creates the version after your
            authorization.
          </p>
          {terminalOpen ? (
            <p className='ws-note'>
              The terminal is captured when you save. Recent terminal changes may not appear in this list yet.
            </p>
          ) : null}
          {error ? (
            <button
              className='btn btn--outlined btn--small'
              onClick={() => {
                setDialog(null)
                setTab('changes')
              }}
            >
              Review conflicts
            </button>
          ) : null}
          {error ? (
            <p className='ws-inline-error' role='alert'>
              {error}
            </p>
          ) : null}
        </WorkspaceDialog>
      ) : null}
      {dialog?.kind === 'restore' ? (
        <WorkspaceDialog
          title='Restore as a new version?'
          onClose={cancelDialog}
          footer={
            <>
              {footerCancel}
              <button
                className='btn btn--solid'
                disabled={busy || !canEdit || drafts.dirty}
                onClick={() => {
                  void write('restore', { versionHash: dialog.version.hash }).then((ok) => {
                    if (ok) {
                      setDialog(null)
                      setTab('files')
                      setNotice('Restored as a new version. Earlier history is preserved.')
                    }
                  })
                }}
              >
                {busy ? 'Restoring…' : 'Restore as new version'}
              </button>
            </>
          }
        >
          <p>
            Replace all current project files with <strong>{dialog.version.message}</strong>.
          </p>
          <code className='ws-full-hash'>{dialog.version.hash}</code>
          <p>This creates a new version after the latest one. Your saved history remains available.</p>
          {changeCount ? <p className='ws-warning-text'>{changeCount} current file changes will be replaced.</p> : null}
          {drafts.dirty ? <p className='ws-inline-error'>Save or discard browser edits before restoring.</p> : null}
          {error ? (
            <p className='ws-inline-error' role='alert'>
              {error}
            </p>
          ) : null}
        </WorkspaceDialog>
      ) : null}
      {dialog?.kind === 'remix' ? (
        <WorkspaceDialog
          title='Create a remix'
          onClose={cancelDialog}
          footer={
            <>
              {footerCancel}
              <button
                className='btn btn--solid'
                disabled={busy || !auth.session || drafts.dirty}
                onClick={() => void remix(dialog.version)}
              >
                {busy ? 'Creating…' : 'Create remix'}
              </button>
            </>
          }
        >
          <p>
            Create a separate public project from{' '}
            {dialog.version ? <strong>{dialog.version.message}</strong> : 'the latest saved version'}.
          </p>
          <code className='ws-full-hash'>{dialog.version?.hash ?? view.workspace.head}</code>
          <p>The new project has its own files, history, terminal, and agent. This project stays as it is.</p>
          {changeCount ? <p className='ws-warning-text'>Current changes are not part of that saved version.</p> : null}
          {drafts.dirty ? (
            <p className='ws-note'>Save or discard your browser edits before leaving for the new remix.</p>
          ) : null}
          {error ? (
            <p className='ws-inline-error' role='alert'>
              {error}
            </p>
          ) : null}
        </WorkspaceDialog>
      ) : null}
      {dialog?.kind === 'conversation' ? (
        <WorkspaceDialog
          title='Start a new conversation?'
          onClose={cancelDialog}
          footer={
            <>
              {footerCancel}
              <button
                className='btn btn--solid'
                disabled={busy || active}
                onClick={() => {
                  void write('conversation', {}).then((ok) => {
                    if (ok) setDialog(null)
                  })
                }}
              >
                Start new conversation
              </button>
            </>
          }
        >
          <p>
            Clear the current conversation and the agent’s conversation context. Files and saved versions stay in this
            project.
          </p>
          <p className='ws-note'>Cleared messages cannot be recovered.</p>
          {error ? (
            <p className='ws-inline-error' role='alert'>
              {error}
            </p>
          ) : null}
        </WorkspaceDialog>
      ) : null}
      {dialog?.kind === 'revoke' ? (
        <WorkspaceDialog
          title='Revoke agent access?'
          onClose={cancelDialog}
          footer={
            <>
              {footerCancel}
              <button
                className='btn btn--solid'
                disabled={busy}
                onClick={() => {
                  void write('revoke', {}).then((ok) => {
                    if (ok) setDialog(null)
                  })
                }}
              >
                Revoke access
              </button>
            </>
          }
        >
          <p>Stop execution and disable the agent, terminal, file saves, and new versions in this workspace.</p>
          <p>
            Files and history remain readable. To work again, you’ll need to remix a saved version into a new workspace.
          </p>
          {error ? (
            <p className='ws-inline-error' role='alert'>
              {error}
            </p>
          ) : null}
        </WorkspaceDialog>
      ) : null}
      {dialog?.kind === 'discard' || dialog?.kind === 'leave' ? (
        <WorkspaceDialog
          title={dialog.kind === 'leave' ? 'Leave with unsaved edits?' : 'Discard browser edits?'}
          onClose={cancelDialog}
          footer={
            <>
              {footerCancel}
              <button
                className='btn btn--solid'
                onClick={() => {
                  const href = dialog.kind === 'leave' ? dialog.href : null
                  drafts.clear()
                  setDialog(null)
                  if (href) location.assign(href)
                }}
              >
                {dialog.kind === 'leave' ? 'Discard edits & leave' : 'Discard browser edits'}
              </button>
            </>
          }
        >
          <p>
            {draftEntries.length} browser {draftEntries.length === 1 ? 'edit has' : 'edits have'} not been saved.
            Discarding cannot be undone.
          </p>
          <p>Working files and saved versions are unaffected.</p>
        </WorkspaceDialog>
      ) : null}
      {dialog?.kind === 'details' ? (
        <WorkspaceDialog
          title='Project details'
          onClose={cancelDialog}
          footer={
            <button className='btn btn--outlined' onClick={cancelDialog}>
              Done
            </button>
          }
        >
          <dl className='ws-details'>
            <dt>Visibility</dt>
            <dd>Public files and saved versions. Conversation and terminal are owner-only.</dd>
            <dt>Owner</dt>
            <dd>
              <PlayerLabel pubkey={view.workspace.ownerPublicKey} />
              <code>{view.workspace.ownerPublicKey}</code>
            </dd>
            <dt>Project</dt>
            <dd>
              <code>{view.workspace.id}</code>
            </dd>
            <dt>Version signer</dt>
            <dd>
              <code>{view.workspace.agentPublicKey}</code>
            </dd>
            <dt>Agent authorization</dt>
            <dd>
              {view.agentEnabled ? 'Active' : 'Disabled or expired'}
              {view.grant ? ` · expires ${new Date(view.grant.grant.expiresAt).toLocaleString()}` : ''}
            </dd>
            <dt>Created</dt>
            <dd>{new Date(view.workspace.createdAt).toLocaleString()}</dd>
          </dl>
        </WorkspaceDialog>
      ) : null}
    </div>
  )
}
