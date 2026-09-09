// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { ChangesPanel, DiffView, diffLines, diffSummary } from './diff-view'
import type { WorkspaceView } from '../../lib/workspace-client'
import { useWorkspaceDrafts } from './editor-state'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})
it.each([
  ['', 'new\n'],
  ['old\n', ''],
  ['a\nb\nc\n', 'a\nnew\nb\nc\n'],
  ['same\nold\nend', 'same\nnew\nend'],
  ['a', 'a\n'],
  ['\n\na\n', '\na\n'],
  ['a\r\nb\r\n', 'a\nb\n'],
])('reconstructs both exact files from its diff, including newline changes', (before, after) => {
  const lines = diffLines(before, after)
  expect(
    lines
      .filter((line) => line.kind !== 'added')
      .map((line) => line.text)
      .join(''),
  ).toBe(before)
  expect(
    lines
      .filter((line) => line.kind !== 'removed')
      .map((line) => line.text)
      .join(''),
  ).toBe(after)
})
it('identifies an insertion without marking subsequent unchanged lines as replacements', () => {
  const lines = diffLines('a\nb\nc\n', 'a\ninserted\nb\nc\n')
  expect(diffSummary(lines)).toEqual({ added: 1, removed: 0 })
  expect(lines.find((line) => line.text === 'b\n')).toMatchObject({ kind: 'equal', beforeLine: 2, afterLine: 3 })
})
it('bounds large unrelated comparisons while preserving all file contents', () => {
  const before = Array.from({ length: 1500 }, (_, i) => `old ${i}\n`).join('')
  const after = Array.from({ length: 1500 }, (_, i) => `new ${i}\n`).join('')
  const lines = diffLines(before, after)
  expect(diffSummary(lines)).toEqual({ added: 1500, removed: 1500 })
  expect(
    lines
      .filter((line) => line.kind !== 'added')
      .map((line) => line.text)
      .join(''),
  ).toBe(before)
  expect(
    lines
      .filter((line) => line.kind !== 'removed')
      .map((line) => line.text)
      .join(''),
  ).toBe(after)
})
it('collapses unchanged context and lets the reader reveal it', () => {
  const common = Array.from({ length: 20 }, (_, i) => `context ${i}\n`).join('')
  render(<DiffView before={common + 'old\n'} after={common + 'new\n'} />)
  expect(screen.queryByText('context 10')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Show 14 unchanged lines' }))
  expect(screen.getByText('context 10')).toBeInTheDocument()
  expect(screen.getByText('+1 added')).toBeInTheDocument()
  expect(screen.getByText('−1 removed')).toBeInTheDocument()
})
it('limits initial rendering of large changed sections and reveals more on demand', () => {
  const content = Array.from({ length: 600 }, (_, i) => `new ${i}\n`).join('')
  render(<DiffView before='' after={content} />)
  expect(screen.queryByText('new 599')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Show more lines (200 remaining)' }))
  expect(screen.getByText('new 599')).toBeInTheDocument()
})
it('compares local edits against HEAD even when the workspace also contains agent changes', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string) => {
      const historical = input.includes('version=')
      return new Response(
        JSON.stringify({
          path: 'main.js',
          content: historical ? 'head\n' : 'working\n',
          hash: historical ? 'head-hash' : 'working-hash',
          editable: true,
        }),
      )
    }),
  )
  const view: WorkspaceView = {
    workspace: {
      id: 'abc',
      title: 'Project',
      ownerPublicKey: 'owner',
      agentPublicKey: 'agent',
      source: { kind: 'demo', repository: 'demo', commitHash: 'origin' },
      head: 'head-version',
      public: true,
      createdAt: 1,
      updatedAt: 1,
    },
    files: [{ path: 'main.js', size: 6, mode: 'blob', hash: 'working-hash' }],
    changes: [{ path: 'main.js', status: 'modified', beforeHash: 'head-hash', afterHash: 'working-hash' }],
    versions: [],
    messages: [],
    task: null,
    isOwner: true,
    grant: null,
    agentEnabled: true,
  }
  function Harness() {
    const drafts = useWorkspaceDrafts()
    return (
      <>
        <button
          onClick={() =>
            drafts.setDraft({
              path: 'main.js',
              content: 'local\n',
              original: 'working\n',
              hash: 'working-hash',
              editable: true,
            })
          }
        >
          Edit
        </button>
        <ChangesPanel view={view} session={null} draftState={drafts} />
      </>
    )
  }
  const component = render(
    <QueryClientProvider client={client}>
      <Harness />
    </QueryClientProvider>,
  )
  fireEvent.click(screen.getByRole('button', { name: 'Edit' }))
  expect(await screen.findByText('local')).toBeInTheDocument()
  expect(screen.getByText('head')).toBeInTheDocument()
  expect(screen.getByRole('region', { name: 'Latest version compared with Your edits' })).toBeInTheDocument()
  expect(vi.mocked(fetch).mock.calls.some(([url]) => String(url).includes('version=head-version'))).toBe(true)
  component.unmount()
  client.clear()
})

it('shows a selected conflict against current content and returns to HEAD comparison after explicit resolution', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string) => {
      const historical = input.includes('version=')
      return new Response(
        JSON.stringify({
          path: 'main.js',
          content: historical ? 'Saved version\n' : 'Current author edits\n',
          hash: historical ? 'head-hash' : 'current-hash',
          editable: true,
        }),
      )
    }),
  )
  const view: WorkspaceView = {
    workspace: {
      id: 'abc',
      title: 'Project',
      ownerPublicKey: 'owner',
      agentPublicKey: 'agent',
      source: { kind: 'demo', repository: 'demo', commitHash: 'origin' },
      head: 'head-version',
      public: true,
      createdAt: 1,
      updatedAt: 1,
    },
    files: [{ path: 'main.js', size: 6, mode: 'blob', hash: 'current-hash' }],
    changes: [{ path: 'main.js', status: 'modified', beforeHash: 'head-hash', afterHash: 'current-hash' }],
    versions: [],
    messages: [],
    task: null,
    isOwner: true,
    grant: null,
    agentEnabled: true,
  }
  function Harness() {
    const drafts = useWorkspaceDrafts()
    return (
      <>
        <button
          onClick={() =>
            drafts.setDraft({
              path: 'main.js',
              content: 'My local edits\n',
              original: 'Older working content\n',
              hash: 'older-hash',
              editable: true,
            })
          }
        >
          Load draft
        </button>
        <ChangesPanel view={view} session={{ id: 'owner-session', publicKey: 'owner' }} draftState={drafts} />
      </>
    )
  }
  const component = render(
    <QueryClientProvider client={client}>
      <Harness />
    </QueryClientProvider>,
  )
  fireEvent.click(screen.getByRole('button', { name: 'Load draft' }))
  expect(
    await screen.findByRole('region', { name: 'Current workspace file compared with My edits' }),
  ).toBeInTheDocument()
  expect(screen.getByText('Current author edits')).toBeInTheDocument()
  expect(screen.getByText('My local edits')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Use my edits on current file' })).toBeDisabled()
  fireEvent.click(screen.getByRole('checkbox', { name: 'I reviewed the current file and want to keep my edits.' }))
  fireEvent.click(screen.getByRole('button', { name: 'Use my edits on current file' }))
  expect(await screen.findByRole('region', { name: 'Latest version compared with Your edits' })).toBeInTheDocument()
  expect(screen.getByText('My local edits')).toBeInTheDocument()
  component.unmount()
  client.clear()
})
