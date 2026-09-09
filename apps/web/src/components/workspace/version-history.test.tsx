// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import type { WorkspaceFile, WorkspaceVersion, WorkspaceView } from '../../lib/workspace-client'
import { workspaceKeys } from '../../lib/workspace-queries'
import { VersionHistory, compareVersionFiles } from './version-history'

vi.mock('../multiplayer/player-label', () => ({
  PlayerLabel: ({ pubkey }: { pubkey: string }) => <span>{pubkey}</span>,
}))
vi.mock('./diff-view', () => ({
  DiffView: ({
    before,
    after,
    beforeLabel,
    afterLabel,
  }: {
    before: string
    after: string
    beforeLabel?: string
    afterLabel?: string
  }) => (
    <section aria-label='Text comparison'>
      <span>{beforeLabel}</span>
      <pre>{before}</pre>
      <span>{afterLabel}</span>
      <pre>{after}</pre>
    </section>
  ),
}))

const session = { id: 'session', publicKey: 'owner' }
const old: WorkspaceVersion = {
  hash: 'old',
  treeHash: 'old-tree',
  parent: null,
  message: 'Initial files',
  signer: 'owner',
  createdAt: 1_700_000_000_000,
}
const latest: WorkspaceVersion = {
  hash: 'latest',
  treeHash: 'latest-tree',
  parent: 'old',
  message: 'Update project',
  signer: 'agent',
  createdAt: 1_700_000_060_000,
}
const file = (path: string, hash: string, mode: 'blob' | 'exec' = 'blob'): WorkspaceFile => ({
  path,
  hash,
  size: 8,
  mode,
})
const originalFiles = [file('removed.txt', 'removed'), file('changed.txt', 'before'), file('same.txt', 'same')]
const savedFiles = [file('added.txt', 'added'), file('changed.txt', 'after'), file('same.txt', 'same')]
const live: WorkspaceView = {
  workspace: {
    id: 'project',
    title: 'Project',
    ownerPublicKey: 'owner',
    agentPublicKey: 'agent',
    source: { kind: 'demo', repository: 'demo', commitHash: 'source' },
    head: 'latest',
    createdAt: old.createdAt,
    updatedAt: latest.createdAt,
    public: true,
  },
  files: savedFiles,
  changes: [],
  versions: [latest, old],
  messages: [],
  task: null,
  isOwner: true,
  grant: null,
  agentEnabled: true,
}
let client: QueryClient
let fetcher: ReturnType<typeof vi.fn>
const restore = vi.fn()
const remix = vi.fn()

function wrap({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}
function show(view = live, canRestore = true) {
  return render(
    <VersionHistory
      view={view}
      session={session}
      busy={false}
      canRestore={canRestore}
      onRestore={restore}
      onRemix={remix}
    />,
    { wrapper: wrap },
  )
}
beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  vi.clearAllMocks()
  fetcher = vi.fn(async (input: string | URL | Request) => {
    const url = new URL(
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
      'http://localhost',
    )
    const version = url.searchParams.get('version')
    const path = url.searchParams.get('path')
    if (path)
      return new Response(
        JSON.stringify({
          path,
          hash: version ?? 'current',
          content: `${version ?? 'current'}:${path}`,
          editable: true,
        }),
      )
    return new Response(
      JSON.stringify({
        ...live,
        files: version === 'old' ? originalFiles : version === 'latest' ? savedFiles : [file('current.txt', 'current')],
      }),
    )
  })
  vi.stubGlobal('fetch', fetcher)
})
afterEach(() => {
  cleanup()
  client.clear()
  vi.unstubAllGlobals()
})

it('derives added, removed, modified, and permission-only changes from file hashes', () => {
  const changes = compareVersionFiles(
    [...originalFiles, file('script.sh', 'script')],
    [...savedFiles, file('script.sh', 'script', 'exec')],
  )
  expect(changes.map(({ path, kind }) => [path, kind])).toEqual([
    ['added.txt', 'added'],
    ['changed.txt', 'modified'],
    ['removed.txt', 'removed'],
    ['script.sh', 'modified'],
  ])
})

it('compares selected snapshot with its parent and loads added/deleted files only where they exist', async () => {
  show()
  await screen.findByRole('button', { name: 'added.txt Added' })
  expect(await screen.findByText('latest:added.txt')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'removed.txt Removed' }))
  expect(await screen.findByText('old:removed.txt')).toBeInTheDocument()
  expect(
    fetcher.mock.calls.some(
      ([url]) => String(url).includes('path=removed.txt') && String(url).includes('version=latest'),
    ),
  ).toBe(false)
  expect(
    fetcher.mock.calls.some(([url]) => String(url).includes('path=added.txt') && String(url).includes('version=old')),
  ).toBe(false)
  expect(client.getQueryData(workspaceKeys.view('project', session, 'latest'))).toBeDefined()
  expect(client.getQueryData(workspaceKeys.view('project', session, 'old'))).toBeDefined()
})

it('selects history without changing the current head or invoking restore/remix', async () => {
  show()
  fireEvent.click(screen.getByRole('button', { name: /Initial files/ }))
  await screen.findByRole('heading', { name: 'Initial files' })
  expect(live.workspace.head).toBe('latest')
  expect(restore).not.toHaveBeenCalled()
  expect(remix).not.toHaveBeenCalled()
  expect(screen.getByText('Latest')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Remix this version' }))
  expect(remix).toHaveBeenCalledWith(old)
})

it('compares selected saved files with current files when requested', async () => {
  show()
  fireEvent.click(screen.getByRole('radio', { name: 'Compare with current files' }))
  const currentFile = await screen.findByRole('button', { name: 'current.txt Added' })
  fireEvent.click(currentFile)
  expect(await screen.findByText('current:current.txt')).toBeInTheDocument()
  expect(within(screen.getByRole('region', { name: 'Text comparison' })).getByText('Current files')).toBeInTheDocument()
  expect(client.getQueryData(workspaceKeys.view('project', session, null))).toBeDefined()
  expect(fetcher.mock.calls.some(([url]) => String(url).endsWith('/file?path=current.txt'))).toBe(true)
})

it('honors the restore guard and never treats binary content as an empty text diff', async () => {
  fetcher.mockImplementation(async (input: string) => {
    const url = new URL(input, 'http://localhost')
    if (url.searchParams.has('path'))
      return new Response(JSON.stringify({ path: 'added.txt', hash: 'binary', content: '', editable: false }))
    return new Response(
      JSON.stringify({
        ...live,
        files: url.searchParams.get('version') === 'old' ? [] : [file('added.txt', 'binary')],
      }),
    )
  })
  show(live, false)
  expect(screen.getByRole('button', { name: 'Restore as new version' })).toBeDisabled()
  expect(await screen.findByText('This file cannot be compared as text.')).toBeInTheDocument()
  expect(screen.queryByRole('region', { name: 'Text comparison' })).not.toBeInTheDocument()
  expect(screen.getByText('binary')).toBeInTheDocument()
})

it('keeps an explicitly selected snapshot when a new version arrives', async () => {
  const mounted = show()
  fireEvent.click(screen.getByRole('button', { name: /Initial files/ }))
  await screen.findByRole('heading', { name: 'Initial files' })
  const next = { ...latest, hash: 'next', message: 'New latest' }
  mounted.rerender(
    <VersionHistory
      view={{ ...live, workspace: { ...live.workspace, head: 'next' }, versions: [next, ...live.versions] }}
      session={session}
      busy={false}
      canRestore
      onRestore={restore}
      onRemix={remix}
    />,
  )
  await waitFor(() => expect(screen.getByRole('heading', { name: 'Initial files' })).toBeInTheDocument())
  expect(screen.getByRole('button', { name: /Initial files/ })).toHaveAttribute('aria-pressed', 'true')
})
