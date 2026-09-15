'use client'

import {
  ArrowUpIcon,
  CheckCircleIcon,
  CircleIcon,
  RobotIcon,
  StopIcon,
  WarningCircleIcon,
} from '@phosphor-icons/react/ssr'
import { useLayoutEffect, useRef, useState } from 'react'
import type { WorkspaceView } from '../../lib/workspace-client'
import { PlayerAvatar, PlayerLabel } from '../multiplayer/player-label'

export function AgentPanel({
  view,
  busy,
  draftCount,
  onRun,
  onStop,
  onReview,
  onNewConversation,
}: {
  view: WorkspaceView
  busy: boolean
  draftCount: number
  onRun: (prompt: string) => Promise<boolean>
  onStop: () => void
  onReview: () => void
  onNewConversation: () => void
}) {
  const [prompt, setPrompt] = useState('')
  const [following, setFollowing] = useState(true)
  const feed = useRef<HTMLDivElement>(null)
  const active = view.task?.status === 'queued' || view.task?.status === 'running'
  const state = active ? view.task!.status : !view.agentEnabled ? 'disabled' : (view.task?.status ?? 'ready')
  const status = {
    queued: 'Queued',
    running: 'Working',
    completed: 'Completed',
    failed: 'Task failed',
    cancelled: 'Stopped',
    disabled: 'Access disabled',
    ready: 'Ready',
  }[state]
  const StatusIcon = state === 'completed' ? CheckCircleIcon : state === 'failed' ? WarningCircleIcon : CircleIcon
  useLayoutEffect(() => {
    if (following && feed.current) feed.current.scrollTop = feed.current.scrollHeight
  }, [view.messages, following])
  const submit = async () => {
    if (!prompt.trim() || active || busy || draftCount || !view.agentEnabled) return
    const submitted = prompt
    if (await onRun(prompt.trim())) setPrompt((current) => (current === submitted ? '' : current))
  }
  return (
    <aside className='ws-agent' aria-label='Coding agent'>
      <header className='ws-panel-heading'>
        <div className='ws-inline'>
          <RobotIcon size={16} aria-hidden />
          <h2>nanocodex</h2>
        </div>
        <span className={`ws-status ${state === 'failed' ? 'ws-error-text' : ''}`} role='status'>
          <StatusIcon size={13} aria-hidden />
          {status}
        </span>
      </header>
      <div className='ws-agent-context'>
        <span>Works on current files</span>
        <button
          className='btn btn--ghost btn--small'
          disabled={busy || active || !view.messages.length}
          onClick={onNewConversation}
        >
          New conversation
        </button>
      </div>
      <div
        className='ws-messages'
        ref={feed}
        tabIndex={0}
        role='region'
        aria-label='Agent conversation'
        onScroll={() => {
          const element = feed.current
          if (element) setFollowing(element.scrollHeight - element.scrollTop - element.clientHeight < 48)
        }}
      >
        {view.messages.length ? (
          view.messages.map((message) => (
            <article className={`ws-message ws-message--${message.role}`} key={message.id}>
              <div className='ws-message-speaker'>
                {message.role === 'user' ? (
                  <>
                    <PlayerAvatar pubkey={view.workspace.ownerPublicKey} size={16} />
                    <PlayerLabel pubkey={view.workspace.ownerPublicKey} />
                  </>
                ) : (
                  <>
                    <RobotIcon size={14} aria-hidden />
                    <span>{message.role === 'assistant' ? 'nanocodex' : 'Workspace'}</span>
                  </>
                )}
                <time
                  dateTime={new Date(message.createdAt).toISOString()}
                  title={new Date(message.createdAt).toLocaleString()}
                >
                  {new Date(message.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </time>
              </div>
              <p>{message.text}</p>
            </article>
          ))
        ) : (
          <div className='ws-agent-empty'>
            <RobotIcon size={28} weight='light' aria-hidden />
            <h3>What are we building?</h3>
            <p>Ask for a change, a fix, or an explanation. Completed tasks save a project version.</p>
            <div className='ws-suggestions'>
              {['Explain this project', 'Find something to improve'].map((suggestion) => (
                <button className='btn btn--outlined btn--small' key={suggestion} onClick={() => setPrompt(suggestion)}>
                  {suggestion}
                  <ArrowUpIcon size={12} aria-hidden />
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
      {!following && view.messages.length > 0 ? (
        <button className='btn btn--outlined btn--small ws-latest' onClick={() => setFollowing(true)}>
          Latest messages ↓
        </button>
      ) : null}
      {view.task?.error ? (
        <p className='ws-inline-error' role='alert'>
          {view.task.error}
        </p>
      ) : null}
      <form
        className='ws-composer'
        onSubmit={(event) => {
          event.preventDefault()
          void submit()
        }}
      >
        {draftCount > 0 ? (
          <div className='ws-draft-notice'>
            <span>
              {draftCount} browser {draftCount === 1 ? 'edit' : 'edits'} to save first
            </span>
            <button type='button' onClick={onReview}>
              Review edits
            </button>
          </div>
        ) : null}
        <textarea
          aria-label='Ask nanocodex'
          placeholder='Describe the next change…'
          value={prompt}
          onChange={(event) => setPrompt(event.target.value)}
          disabled={busy || active || !view.agentEnabled}
          onKeyDown={(event) => {
            if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
              event.preventDefault()
              void submit()
            }
          }}
        />
        <div className='ws-composer-actions'>
          <span>{active ? 'Keeps working if you leave' : '⌘ / Ctrl + Enter'}</span>
          {active ? (
            <button type='button' className='btn btn--outlined btn--small' disabled={busy} onClick={onStop}>
              <StopIcon size={13} aria-hidden />
              Stop task
            </button>
          ) : (
            <button
              className='btn btn--solid btn--small'
              disabled={busy || !prompt.trim() || !!draftCount || !view.agentEnabled}
            >
              Run task
              <ArrowUpIcon size={13} aria-hidden />
            </button>
          )}
        </div>
        {!view.agentEnabled ? (
          <p className='ws-note'>
            Agent access is disabled or expired. Remix a saved version to continue in a new workspace.
          </p>
        ) : null}
      </form>
    </aside>
  )
}
