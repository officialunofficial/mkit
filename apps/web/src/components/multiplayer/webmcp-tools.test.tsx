// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, cleanup, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { useIdentityStore } from '../../lib/identity-store'
import { mkit } from '../../lib/mkit'
import type { WebMcpModelContext, WebMcpTool } from '../../lib/webmcp'
import { MultiplayerDemo } from '../multiplayer-demo'
import { renderSuspended } from '../test-support'

/** A minimal in-memory `document.modelContext` that records every registered tool, keyed by name. */
function installFakeModelContext(): Map<string, WebMcpTool> {
  const tools = new Map<string, WebMcpTool>()
  const modelContext: WebMcpModelContext = {
    async registerTool(tool, options) {
      tools.set(tool.name, tool)
      options?.signal?.addEventListener('abort', () => tools.delete(tool.name))
    },
    async getTools() {
      return [...tools.values()]
    },
    async executeTool(tool, args, options) {
      return tool.execute(args, { signal: options?.signal ?? new AbortController().signal })
    },
    addEventListener() {},
    removeEventListener() {},
  }
  document.modelContext = modelContext
  return tools
}

function jsonOf(result: { content: Array<{ type: 'text'; text: string }> }): unknown {
  return JSON.parse(result.content[0]!.text)
}

async function renderDemo() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const result = await renderSuspended(
    <QueryClientProvider client={client}>
      <MultiplayerDemo />
    </QueryClientProvider>,
    mkit(),
  )
  // Wait for the seeded mock backend's first paint: the selected branch row is
  // the only element with `aria-pressed="true"`, so this is unambiguous even
  // while `ComposeDisabled`'s inert `<option value="main">main</option>` is
  // also on screen (plain `findByText('main')` matches both).
  await screen.findByRole('button', { pressed: true })
  return result
}

describe('WebMcpTools (multiplayer demo)', () => {
  let tools: Map<string, WebMcpTool>

  beforeEach(() => {
    useIdentityStore.getState().reset()
    tools = installFakeModelContext()
  })
  afterEach(() => {
    document.modelContext = undefined
    cleanup()
  })

  it('registers the full mkit tool set with object input schemas', async () => {
    await renderDemo()
    const names = [...tools.keys()]
    expect(names).toEqual(
      expect.arrayContaining([
        'mkit_get_identity',
        'mkit_list_branches',
        'mkit_get_commit_log',
        'mkit_get_commit',
        'mkit_select_branch',
        'mkit_push_commit',
        'mkit_remix_commit',
        'mkit_branch_commit',
      ]),
    )
    for (const tool of tools.values()) {
      expect(tool.inputSchema.type).toBe('object')
      expect(tool.description.length).toBeGreaterThan(0)
    }
  })

  it('mkit_get_identity reports locked before an identity is unlocked', async () => {
    await renderDemo()
    const result = await tools.get('mkit_get_identity')!.execute({}, { signal: new AbortController().signal })
    expect(jsonOf(result)).toMatchObject({ unlocked: false })
  })

  it('mkit_list_branches sees the seeded "main" branch', async () => {
    await renderDemo()
    const result = await tools.get('mkit_list_branches')!.execute({}, { signal: new AbortController().signal })
    expect(result.isError).toBeFalsy()
    const parsed = jsonOf(result) as { branches: Array<{ name: string }> }
    expect(parsed.branches.some((b) => b.name === 'main')).toBe(true)
  })

  it('mkit_get_commit_log lists the seeded commits on main', async () => {
    await renderDemo()
    const result = await tools
      .get('mkit_get_commit_log')!
      .execute({ ref: 'main' }, { signal: new AbortController().signal })
    const parsed = jsonOf(result) as { ref: string; commits: Array<{ message: string }> }
    expect(parsed.ref).toBe('main')
    expect(parsed.commits.length).toBeGreaterThan(0)
  })

  it('mkit_push_commit refuses to sign while locked', async () => {
    await renderDemo()
    const result = await tools
      .get('mkit_push_commit')!
      .execute({ message: 'agent push' }, { signal: new AbortController().signal })
    expect(result.isError).toBe(true)
    expect(result.content[0]!.text).toMatch(/unlock/i)
  })

  it('mkit_push_commit signs and pushes once unlocked, visible in a later commit-log read', async () => {
    await renderDemo()
    // Unlocking updates the store outside of a React event handler — flush inside
    // `act` so `WebMcpTools`' re-render (and its latest-state effect) commits
    // before the tool call below reads `seedHex`.
    await act(async () => {
      useIdentityStore.getState().unlock({ seedHex: 'aa'.repeat(32), ed25519PubkeyHex: 'bb'.repeat(32) })
      await Promise.resolve()
    })

    const pushResult = await tools
      .get('mkit_push_commit')!
      .execute({ message: 'agent push', ref: 'main' }, { signal: new AbortController().signal })
    expect(pushResult.isError).toBeFalsy()
    expect(pushResult.content[0]!.text).toMatch(/Pushed commit/)

    const logResult = await tools
      .get('mkit_get_commit_log')!
      .execute({ ref: 'main' }, { signal: new AbortController().signal })
    const parsed = jsonOf(logResult) as { commits: Array<{ message: string }> }
    expect(parsed.commits.some((c) => c.message === 'agent push')).toBe(true)
  })

  it('mkit_select_branch drives the visible branch selection', async () => {
    await renderDemo()
    // The seeded demo data includes a `feature` branch (see MockRepoBackend's FOREIGN_REFS).
    const result = await tools
      .get('mkit_select_branch')!
      .execute({ ref: 'feature' }, { signal: new AbortController().signal })
    expect(result.isError).toBeFalsy()
    expect(await screen.findByText(/“feature”/)).toBeInTheDocument()
  })
})
