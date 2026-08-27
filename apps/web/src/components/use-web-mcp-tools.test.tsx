// @vitest-environment jsdom
import { render } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { webMcpText, type WebMcpModelContext, type WebMcpTool } from '../lib/webmcp'
import { useWebMcpTools } from './use-web-mcp-tools'

const TOOL: WebMcpTool = {
  name: 'a-tool',
  description: 'a tool',
  inputSchema: { type: 'object', properties: {} },
  execute: async () => webMcpText('ok'),
}

function Registrar({ tools }: { tools: WebMcpTool[] }) {
  useWebMcpTools(tools)
  return null
}

afterEach(() => {
  document.modelContext = undefined
})

describe('useWebMcpTools', () => {
  it('registers every tool in the list on mount', () => {
    const registered: string[] = []
    document.modelContext = {
      registerTool: async (tool: WebMcpTool) => {
        registered.push(tool.name)
      },
    } as unknown as WebMcpModelContext

    render(<Registrar tools={[TOOL]} />)
    expect(registered).toEqual(['a-tool'])
  })

  it('unregisters (aborts) every tool on unmount', () => {
    const aborted: string[] = []
    document.modelContext = {
      registerTool: async (tool: WebMcpTool, options?: { signal?: AbortSignal }) => {
        options?.signal?.addEventListener('abort', () => aborted.push(tool.name))
      },
    } as unknown as WebMcpModelContext

    const { unmount } = render(<Registrar tools={[TOOL]} />)
    expect(aborted).toEqual([])
    unmount()
    expect(aborted).toEqual(['a-tool'])
  })
})
