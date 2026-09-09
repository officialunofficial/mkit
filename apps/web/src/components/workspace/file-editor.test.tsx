// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useLayoutEffect, useState } from 'react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { FileEditor } from './file-editor'
import { useWorkspaceDrafts, type WorkspaceDraftState } from './editor-state'
import type { WorkspaceView } from '../../lib/workspace-client'

const view: WorkspaceView = {
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
  files: [
    { path: 'README.md', mode: 'blob', size: 10, hash: 'readme-hash' },
    { path: 'main.js', mode: 'blob', size: 10, hash: 'main-hash' },
  ],
  changes: [],
  versions: [],
  messages: [],
  task: null,
  isOwner: true,
  grant: null,
  agentEnabled: true,
}
let client: QueryClient
let state: WorkspaceDraftState
const review = vi.fn()
beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  review.mockReset()
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string) => {
      const path = new URL(input, 'https://mkit.sh').searchParams.get('path')
      return new Response(
        JSON.stringify({
          path,
          content: path === 'README.md' ? 'Read me\nSecond line\n' : 'console.log(1)\n',
          hash: path === 'README.md' ? 'readme-hash' : 'main-hash',
          editable: true,
        }),
      )
    }),
  )
})
afterEach(() => {
  cleanup()
  client.clear()
  vi.unstubAllGlobals()
})
function Harness({ current = view, canEdit = true }: { current?: WorkspaceView; canEdit?: boolean }) {
  const drafts = useWorkspaceDrafts()
  useLayoutEffect(() => {
    state = drafts
  }, [drafts])
  const [open, setOpen] = useState(true)
  return (
    <>
      <button onClick={() => setOpen((value) => !value)}>Toggle files panel</button>
      {open ? (
        <FileEditor
          view={current}
          session={{ id: 'session', publicKey: 'owner' }}
          busy={false}
          canEdit={canEdit}
          draftState={drafts}
          onReview={review}
        />
      ) : (
        <p>Another panel</p>
      )}
    </>
  )
}
function mount(current = view, canEdit = true) {
  return render(<Harness current={current} canEdit={canEdit} />, {
    wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>,
  })
}
it('opens README by default, filters the file list, and selects a matching file', async () => {
  mount()
  await waitFor(() => expect(screen.getByLabelText('File content')).toHaveValue('Read me\nSecond line\n'))
  expect(screen.getByRole('button', { name: 'README.md' })).toHaveAttribute('aria-current', 'true')
  fireEvent.change(screen.getByLabelText('Search files'), { target: { value: 'main' } })
  expect(screen.queryByRole('button', { name: 'README.md' })).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'main.js' }))
  await waitFor(() => expect(screen.getByLabelText('File content')).toHaveValue('console.log(1)\n'))
})
it('keeps independent drafts and original hashes across file and panel switches', async () => {
  mount()
  await screen.findByLabelText('File content')
  fireEvent.change(screen.getByLabelText('File content'), { target: { value: 'Readme edits' } })
  fireEvent.click(screen.getByRole('button', { name: 'main.js' }))
  await waitFor(() => expect(screen.getByLabelText('File content')).toHaveValue('console.log(1)\n'))
  fireEvent.change(screen.getByLabelText('File content'), { target: { value: 'Code edits' } })
  fireEvent.click(screen.getByRole('button', { name: 'Toggle files panel' }))
  fireEvent.click(screen.getByRole('button', { name: 'Toggle files panel' }))
  expect(screen.getByLabelText('File content')).toHaveValue('Readme edits')
  expect(state.drafts['README.md']).toMatchObject({
    content: 'Readme edits',
    original: 'Read me\nSecond line\n',
    hash: 'readme-hash',
  })
  expect(state.drafts['main.js']).toMatchObject({ content: 'Code edits', hash: 'main-hash' })
})
it('preserves a conflicting draft and its precondition when the server changes', async () => {
  const component = mount()
  await screen.findByLabelText('File content')
  fireEvent.change(screen.getByLabelText('File content'), { target: { value: 'My edits' } })
  component.rerender(
    <Harness
      current={{
        ...view,
        workspace: { ...view.workspace, updatedAt: 2 },
        files: view.files.map((file) => (file.path === 'README.md' ? { ...file, hash: 'other-version' } : file)),
      }}
    />,
  )
  expect(screen.getByRole('alert')).toHaveTextContent('Your edits are preserved')
  expect(screen.getByLabelText('File content')).toHaveValue('My edits')
  expect(state.drafts['README.md']?.hash).toBe('readme-hash')
  fireEvent.click(screen.getByRole('button', { name: 'Review changes' }))
  expect(review).toHaveBeenCalledOnce()
})
it.each(['ctrlKey', 'metaKey'])('opens review with %s+S without writing a file', async (key) => {
  mount()
  const editor = await screen.findByLabelText('File content')
  fireEvent.change(editor, { target: { value: 'Draft' } })
  fireEvent.keyDown(editor, { key: 's', [key]: true })
  expect(review).toHaveBeenCalledOnce()
  expect(vi.mocked(fetch).mock.calls.every(([, options]) => !options?.method || options.method === 'GET')).toBe(true)
})
it('creates an empty file as a dirty draft without requesting a nonexistent server file', async () => {
  mount()
  await screen.findByLabelText('File content')
  expect(screen.queryByLabelText('New file path')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'New file' }))
  fireEvent.change(screen.getByLabelText('New file path'), { target: { value: 'src/empty.js' } })
  fireEvent.click(screen.getByRole('button', { name: 'Create file' }))
  expect(screen.getByLabelText('File content')).toHaveValue('')
  expect(state.dirty).toBe(true)
  expect(state.drafts['src/empty.js']).toMatchObject({ hash: null, content: '' })
  expect(screen.getByRole('button', { name: 'Review changes' })).toBeEnabled()
  expect(vi.mocked(fetch).mock.calls.some(([url]) => String(url).includes('empty.js'))).toBe(false)
  fireEvent.click(screen.getByRole('button', { name: 'Discard file edits' }))
  expect(state.dirty).toBe(false)
  expect(screen.queryByRole('button', { name: /src\/empty.js/ })).not.toBeInTheDocument()
})
it('cancels a previous file request and ignores its late response after selection changes', async () => {
  let finish!: (response: Response) => void
  vi.mocked(fetch).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve
      }),
  )
  mount()
  await waitFor(() => expect(fetch).toHaveBeenCalledOnce())
  const oldSignal = vi.mocked(fetch).mock.calls[0]?.[1]?.signal
  fireEvent.click(screen.getByRole('button', { name: 'main.js' }))
  await waitFor(() => expect(screen.getByLabelText('File content')).toHaveValue('console.log(1)\n'))
  expect(oldSignal?.aborted).toBe(true)
  await act(async () => {
    finish(
      new Response(JSON.stringify({ path: 'README.md', content: 'Late readme', hash: 'readme-hash', editable: true })),
    )
  })
  expect(screen.getByLabelText('File content')).toHaveValue('console.log(1)\n')
})
it('renders public files read-only without write controls or keyboard mutation', async () => {
  mount(view, false)
  const editor = await screen.findByLabelText('File content')
  expect(editor).toHaveAttribute('readonly')
  expect(screen.queryByRole('button', { name: 'New file' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Review changes' })).not.toBeInTheDocument()
  fireEvent.keyDown(editor, { key: 's', ctrlKey: true })
  expect(review).not.toHaveBeenCalled()
})

it('reloads current file content after a terminal changes its hash without changing workspace updatedAt', async () => {
  const component = mount()
  await screen.findByLabelText('File content')
  vi.mocked(fetch).mockResolvedValue(
    new Response(
      JSON.stringify({ path: 'README.md', content: 'Terminal edits', hash: 'terminal-hash', editable: true }),
    ),
  )
  component.rerender(
    <Harness
      current={{
        ...view,
        files: view.files.map((file) => (file.path === 'README.md' ? { ...file, hash: 'terminal-hash' } : file)),
      }}
    />,
  )
  await waitFor(() => expect(screen.getByLabelText('File content')).toHaveValue('Terminal edits'), { timeout: 1000 })
})

it('requires explicit conflict review before adopting the current hash while preserving my content', async () => {
  const component = mount()
  await screen.findByLabelText('File content')
  fireEvent.change(screen.getByLabelText('File content'), { target: { value: 'My chosen edits\n' } })
  vi.mocked(fetch).mockImplementation(
    async () =>
      new Response(
        JSON.stringify({ path: 'README.md', content: 'Other author edits\n', hash: 'current-hash', editable: true }),
      ),
  )
  component.rerender(
    <Harness
      current={{
        ...view,
        files: view.files.map((file) => (file.path === 'README.md' ? { ...file, hash: 'current-hash' } : file)),
      }}
    />,
  )
  expect(state.drafts['README.md']?.hash).toBe('readme-hash')
  expect(screen.queryByRole('button', { name: 'Use my edits on current file' })).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Review conflict' }))
  await screen.findByText('Other author edits')
  expect(screen.getByRole('button', { name: 'Use my edits on current file' })).toBeDisabled()
  expect(state.drafts['README.md']?.hash).toBe('readme-hash')
  fireEvent.click(screen.getByRole('checkbox', { name: 'I reviewed the current file and want to keep my edits.' }))
  fireEvent.click(screen.getByRole('button', { name: 'Use my edits on current file' }))
  expect(state.drafts['README.md']).toMatchObject({
    hash: 'current-hash',
    original: 'Other author edits\n',
    content: 'My chosen edits\n',
  })
  expect(screen.getByLabelText('File content')).toHaveValue('My chosen edits\n')
  expect(screen.queryByRole('button', { name: 'Review conflict' })).not.toBeInTheDocument()
  expect(vi.mocked(fetch).mock.calls.every(([, options]) => !options?.method || options.method === 'GET')).toBe(true)
})

it('requires a fresh conflict review if the current file changes while confirmation is open', async () => {
  const component = mount()
  await screen.findByLabelText('File content')
  fireEvent.change(screen.getByLabelText('File content'), { target: { value: 'My edits\n' } })
  const showVersion = (hash: string, content: string) => {
    vi.mocked(fetch).mockImplementation(
      async () => new Response(JSON.stringify({ path: 'README.md', hash, content, editable: true })),
    )
    component.rerender(
      <Harness
        current={{ ...view, files: view.files.map((file) => (file.path === 'README.md' ? { ...file, hash } : file)) }}
      />,
    )
  }
  showVersion('second-hash', 'Second version\n')
  fireEvent.click(screen.getByRole('button', { name: 'Review conflict' }))
  await screen.findByText('Second version')
  fireEvent.click(screen.getByRole('checkbox', { name: 'I reviewed the current file and want to keep my edits.' }))
  expect(screen.getByRole('button', { name: 'Use my edits on current file' })).toBeEnabled()
  showVersion('third-hash', 'Third version\n')
  expect(screen.queryByRole('button', { name: 'Use my edits on current file' })).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Review conflict' }))
  await screen.findByText('Third version')
  expect(
    screen.getByRole('checkbox', { name: 'I reviewed the current file and want to keep my edits.' }),
  ).not.toBeChecked()
  expect(screen.getByRole('button', { name: 'Use my edits on current file' })).toBeDisabled()
  expect(state.drafts['README.md']).toMatchObject({ content: 'My edits\n', hash: 'readme-hash' })
})

it('detects a newly fetched conflict even before the workspace metadata poll catches up', async () => {
  mount()
  await screen.findByLabelText('File content')
  fireEvent.change(screen.getByLabelText('File content'), { target: { value: 'My edits' } })
  vi.mocked(fetch).mockImplementation(
    async () =>
      new Response(
        JSON.stringify({ path: 'README.md', content: 'Latest server file', hash: 'newer-hash', editable: true }),
      ),
  )
  await act(async () => {
    await client.invalidateQueries({ queryKey: ['workspaces', 'session', 'owner', 'abc', 'file'] })
  })
  fireEvent.click(await screen.findByRole('button', { name: 'Review conflict' }))
  await screen.findByText('Latest server file')
  expect(state.drafts['README.md']).toMatchObject({ hash: 'readme-hash', content: 'My edits' })
})

it('keeps a locally edited filename when the server deletes it and explicitly prepares recreation', async () => {
  const component = mount()
  await screen.findByLabelText('File content')
  fireEvent.change(screen.getByLabelText('File content'), { target: { value: 'Keep this file' } })
  component.rerender(<Harness current={{ ...view, files: view.files.filter((file) => file.path !== 'README.md') }} />)
  expect(screen.getByLabelText('File content')).toHaveValue('Keep this file')
  fireEvent.click(screen.getByRole('button', { name: 'Review conflict' }))
  expect(
    screen.getByText('The file was deleted in the workspace. Keeping your edits will recreate it.'),
  ).toBeInTheDocument()
  fireEvent.click(screen.getByRole('checkbox', { name: 'I reviewed the current file and want to keep my edits.' }))
  fireEvent.click(screen.getByRole('button', { name: 'Use my edits on current file' }))
  expect(state.drafts['README.md']).toMatchObject({
    path: 'README.md',
    hash: null,
    original: '',
    content: 'Keep this file',
  })
  expect(state.dirty).toBe(true)
})
