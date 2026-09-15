// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { CodingWorkspace } from './workspace'
import { workspaceRead, workspaceWrite, type WorkspaceView } from '../../lib/workspace-client'
import { useWorkspaceDraftStore } from '../../lib/workspace-draft-store'
import { workspaceKeys } from '../../lib/workspace-queries'

const auth = vi.hoisted(() => ({
  session: { id: 'session-one', publicKey: 'owner', expiresAt: 9999999999999 } as {
    id: string
    publicKey: string
    expiresAt: number
  } | null,
  pending: false,
  ensureSigning: vi.fn(),
  generation: 0,
  epoch: () => auth.generation,
}))
const api = vi.hoisted(() => ({}))
vi.mock('../auth-provider', () => ({ useAuth: () => auth }))
vi.mock('waku', () => ({
  useRouter: () => ({ query: location.search, push: (url: string) => history.pushState({}, '', url) }),
  Link: ({ to, children, ...props }: { to: string; children: React.ReactNode }) => (
    <a href={to} {...props}>
      {children}
    </a>
  ),
}))
vi.mock('../../lib/mkit', async (original) => ({
  ...(await original<typeof import('../../lib/mkit')>()),
  mkit: async () => api,
}))
vi.mock('./file-editor', () => ({ FileEditor: () => <p>Files</p> }))
vi.mock('./terminal', () => ({ WorkspaceTerminal: () => <p>Owner terminal</p> }))
vi.mock('../../lib/workspace-client', async (original) => ({
  ...(await original<typeof import('../../lib/workspace-client')>()),
  workspaceRead: vi.fn(),
  workspaceWrite: vi.fn(),
}))
const publicView: WorkspaceView = {
  workspace: {
    id: 'abc',
    title: 'Project',
    ownerPublicKey: 'owner',
    agentPublicKey: 'agent',
    source: { kind: 'demo', repository: 'demo', commitHash: 'origin' },
    head: 'head',
    public: true,
    createdAt: 1,
    updatedAt: 1,
  },
  files: [],
  changes: [],
  versions: [],
  messages: [],
  task: null,
  isOwner: false,
  grant: null,
  agentEnabled: true,
}

let client: QueryClient
beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  history.replaceState({}, '', '/create?id=abc')
  auth.session = { id: 'session-one', publicKey: 'owner', expiresAt: 9999999999999 }
  auth.generation = 0
  auth.ensureSigning.mockResolvedValue({
    seedHex: 'private-signing-material',
    ed25519PubkeyHex: 'owner',
    ephemeral: false,
  })
})
afterEach(() => {
  cleanup()
  useWorkspaceDraftStore.getState().clearAll()
  client.clear()
  vi.resetAllMocks()
})
function mount() {
  return render(<CodingWorkspace />, {
    wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>,
  })
}
const ownerView: WorkspaceView = {
  ...publicView,
  isOwner: true,
  messages: [{ id: 'hello', role: 'assistant', text: 'Ready when you are.', createdAt: 1 }],
}

it('restores owner reads and terminal from the shared session without opening or deleting a workspace session', async () => {
  vi.mocked(workspaceRead).mockResolvedValue(ownerView)
  mount()
  await openTerminal()
  expect(auth.ensureSigning).not.toHaveBeenCalled()
  expect(workspaceWrite).not.toHaveBeenCalled()
})

it('isolates a late anonymous read from a newly authenticated owner query', async () => {
  auth.session = null
  let finish!: (value: WorkspaceView) => void
  vi.mocked(workspaceRead).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve
      }),
  )
  const component = mount()
  await waitFor(() => expect(workspaceRead).toHaveBeenCalledOnce())
  const signal = vi.mocked(workspaceRead).mock.calls[0]?.[1]
  auth.session = { id: 'session-two', publicKey: 'owner', expiresAt: 9999999999999 }
  auth.generation++
  vi.mocked(workspaceRead).mockResolvedValue(ownerView)
  component.rerender(<CodingWorkspace />)
  await openTerminal()
  expect(signal?.aborted).toBe(true)
  await act(async () => {
    finish(publicView)
  })
  expect(screen.getByText('Owner terminal')).toBeInTheDocument()
})

it.each(['running', 'revoked'] as const)('does not connect the terminal when execution is %s', async (state) => {
  vi.mocked(workspaceRead).mockResolvedValue({
    ...ownerView,
    agentEnabled: state !== 'revoked',
    task: state === 'running' ? { id: 'task', prompt: 'private', status: 'running', createdAt: 1 } : null,
  })
  mount()
  fireEvent.click(await screen.findByRole('button', { name: /^Terminal/ }))
  await screen.findByText(
    state === 'running' ? /terminal is paused while nanocodex runs/ : /Workspace execution is disabled/,
  )
  expect(screen.queryByText('Owner terminal')).not.toBeInTheDocument()
  if (state === 'running') expect(screen.getByRole('button', { name: 'New conversation' })).toBeDisabled()
})

it('signs a write on demand, preserves unsent prompt, and keeps seed out of the real mutation cache', async () => {
  const old = { ...ownerView, messages: [{ id: 'old', role: 'user' as const, text: 'Previous task', createdAt: 1 }] }
  vi.mocked(workspaceRead).mockResolvedValue(old)
  vi.mocked(workspaceWrite).mockResolvedValue({ ...ownerView, workspace: { ...ownerView.workspace, updatedAt: 2 } })
  mount()
  fireEvent.change(await screen.findByLabelText('Ask nanocodex'), { target: { value: 'Retry this request' } })
  await startConversation()
  await waitFor(() => expect(screen.queryByText('Previous task')).not.toBeInTheDocument())
  expect(auth.ensureSigning).toHaveBeenCalledWith('owner')
  expect(workspaceWrite).toHaveBeenCalledWith(
    api,
    expect.objectContaining({ seedHex: 'private-signing-material' }),
    'abc',
    '/abc/conversation',
    {},
  )
  expect(screen.getByLabelText('Ask nanocodex')).toHaveValue('Retry this request')
  expect(client.getMutationCache().getAll()).toHaveLength(1)
  expect(
    JSON.stringify(
      client
        .getMutationCache()
        .getAll()
        .map((m) => m.state),
    ),
  ).not.toContain('private-signing-material')
})

it('cancels an old poll before applying a successful mutation', async () => {
  vi.mocked(workspaceRead).mockResolvedValue(ownerView)
  vi.mocked(workspaceWrite).mockResolvedValue({
    ...ownerView,
    workspace: { ...ownerView.workspace, title: 'Updated project', updatedAt: 2 },
  })
  mount()
  await openTerminal()
  let finish!: (value: WorkspaceView) => void
  vi.mocked(workspaceRead).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve
      }),
  )
  void client.refetchQueries({ queryKey: workspaceKeys.view('abc', auth.session) })
  await waitFor(() => expect(workspaceRead).toHaveBeenCalledTimes(2))
  await startConversation()
  await screen.findByRole('heading', { name: 'Updated project' })
  await act(async () => {
    finish(publicView)
  })
  expect(screen.getByRole('heading', { name: 'Updated project' })).toBeInTheDocument()
  expect(screen.getByText('Owner terminal')).toBeInTheDocument()
})

it('does not apply a late write from workspace A to workspace B and resets its local prompt', async () => {
  const b = { ...ownerView, workspace: { ...ownerView.workspace, id: 'def', title: 'Project B' } }
  vi.mocked(workspaceRead).mockImplementation(async (path) => (path?.startsWith('/def') ? b : ownerView))
  let finish!: (value: WorkspaceView) => void
  vi.mocked(workspaceWrite).mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve
      }),
  )
  const component = mount()
  fireEvent.change(await screen.findByLabelText('Ask nanocodex'), { target: { value: 'A draft' } })
  await startConversation()
  await waitFor(() => expect(workspaceWrite).toHaveBeenCalledOnce())
  history.pushState({}, '', '/create?id=def')
  component.rerender(<CodingWorkspace />)
  await screen.findByRole('heading', { name: 'Project B' })
  expect(screen.getByLabelText('Ask nanocodex')).toHaveValue('')
  await act(async () => {
    finish(ownerView)
  })
  expect(screen.getByRole('heading', { name: 'Project B' })).toBeInTheDocument()
})

it('rejects a write whose passkey prompt finishes after the session changes', async () => {
  vi.mocked(workspaceRead).mockResolvedValue(ownerView)
  let finish!: (value: unknown) => void
  auth.ensureSigning.mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve
      }),
  )
  const component = mount()
  await startConversation()
  await waitFor(() => expect(auth.ensureSigning).toHaveBeenCalledOnce())
  auth.session = null
  auth.generation++
  vi.mocked(workspaceRead).mockResolvedValue(publicView)
  component.rerender(<CodingWorkspace />)
  await act(async () => {
    finish({ seedHex: 'old-secret', ed25519PubkeyHex: 'owner', ephemeral: false })
  })
  expect(workspaceWrite).not.toHaveBeenCalled()
  expect(screen.queryByText('Owner terminal')).not.toBeInTheDocument()
})

it('retains a newer poll over an older write response and returns only the workspace id to the mutation cache', async () => {
  vi.mocked(workspaceRead).mockResolvedValue(ownerView)
  let finish!: (value: WorkspaceView) => void
  vi.mocked(workspaceWrite).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve
      }),
  )
  const component = mount()
  await startConversation()
  await waitFor(() => expect(workspaceWrite).toHaveBeenCalledOnce())
  const latest = {
    ...ownerView,
    workspace: { ...ownerView.workspace, title: 'Latest project', updatedAt: 3 },
  }
  vi.mocked(workspaceRead).mockResolvedValue(latest)
  await act(async () => {
    await client.refetchQueries({ queryKey: workspaceKeys.view('abc', auth.session) })
  })
  await screen.findByRole('heading', { name: 'Latest project' })
  await act(async () => {
    finish({
      ...ownerView,
      workspace: { ...ownerView.workspace, updatedAt: 2 },
      messages: [{ id: 'private', role: 'user', text: 'Private server conversation', createdAt: 2 }],
    })
  })
  expect(screen.getByRole('heading', { name: 'Latest project' })).toBeInTheDocument()
  const mutation = client.getMutationCache().getAll()[0]
  expect(mutation?.state.data).toBe('abc')
  expect(JSON.stringify(mutation?.state)).not.toContain('Private server conversation')
  component.unmount()
  await waitFor(() => expect(client.getMutationCache().getAll()).toHaveLength(0))
})

async function openTerminal() {
  const button = await screen.findByRole('button', { name: /^Terminal/ })
  if (button.getAttribute('aria-expanded') !== 'true') fireEvent.click(button)
  return screen.findByText('Owner terminal')
}
async function startConversation() {
  fireEvent.click(await screen.findByRole('button', { name: 'New conversation' }))
  fireEvent.click(await screen.findByRole('button', { name: 'Start new conversation' }))
}

it.each([false, true])('saves drafts and working changes together; failure=%s', async (fail) => {
  const scope = JSON.stringify(['session-one', 'owner', 'abc'])
  useWorkspaceDraftStore.getState().setDraft(scope, {
    path: 'draft.txt',
    content: 'edited',
    original: 'before',
    hash: 'original-hash',
    editable: true,
  })
  vi.mocked(workspaceRead).mockResolvedValue({
    ...ownerView,
    changes: [{ path: 'terminal.txt', status: 'added', beforeHash: null, afterHash: 'new-hash' }],
  })
  if (fail) vi.mocked(workspaceWrite).mockRejectedValue(new Error('File changed; review your edits'))
  else vi.mocked(workspaceWrite).mockResolvedValue(ownerView)
  mount()
  fireEvent.click(await screen.findByRole('button', { name: 'Save version' }))
  expect(screen.getByText('draft.txt')).toBeInTheDocument()
  expect(screen.getByText('terminal.txt')).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Version message'), { target: { value: 'One coherent change' } })
  const dialog = screen.getByRole('dialog')
  fireEvent.click(
    Array.from(dialog.querySelectorAll('button')).find((button) => button.textContent === 'Save version')!,
  )
  await waitFor(() => expect(workspaceWrite).toHaveBeenCalledOnce())
  expect(vi.mocked(workspaceWrite).mock.calls[0]).toEqual(
    expect.arrayContaining([
      '/abc/versions',
      {
        message: 'One coherent change',
        edits: [{ path: 'draft.txt', content: 'edited', expectedHash: 'original-hash' }],
      },
    ]),
  )
  if (fail) {
    await screen.findByText('File changed; review your edits')
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(useWorkspaceDraftStore.getState().scopes.get(scope)?.['draft.txt']?.content).toBe('edited')
  } else {
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(useWorkspaceDraftStore.getState().scopes.has(scope)).toBe(false)
  }
})

it('keeps the terminal disconnected until explicitly opened', async () => {
  vi.mocked(workspaceRead).mockResolvedValue(ownerView)
  mount()
  await screen.findByRole('button', { name: /^Terminal/ })
  expect(screen.queryByText('Owner terminal')).not.toBeInTheDocument()
})
