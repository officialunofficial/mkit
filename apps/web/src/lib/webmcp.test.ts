// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  isWebMcpSupported,
  registerWebMcpTool,
  webMcpError,
  webMcpText,
  type WebMcpModelContext,
  type WebMcpTool,
} from './webmcp'

const NOOP_TOOL: WebMcpTool = {
  name: 'noop',
  description: 'does nothing',
  inputSchema: { type: 'object', properties: {} },
  execute: async () => webMcpText('ok'),
}

afterEach(() => {
  document.modelContext = undefined
})

describe('isWebMcpSupported', () => {
  it('is false when document.modelContext is absent', () => {
    expect(isWebMcpSupported()).toBe(false)
  })

  it('is true once document.modelContext is present', () => {
    document.modelContext = {} as WebMcpModelContext
    expect(isWebMcpSupported()).toBe(true)
  })
})

describe('webMcpText / webMcpError', () => {
  it('wraps text as a non-error content result', () => {
    expect(webMcpText('hi')).toEqual({ content: [{ type: 'text', text: 'hi' }] })
  })

  it('wraps a message as an isError result', () => {
    expect(webMcpError('nope')).toEqual({ content: [{ type: 'text', text: 'nope' }], isError: true })
  })
})

describe('registerWebMcpTool', () => {
  it('is a no-op that still returns a safe unregister when unsupported', () => {
    const unregister = registerWebMcpTool(NOOP_TOOL)
    expect(() => unregister()).not.toThrow()
  })

  it('calls registerTool with the tool and an AbortSignal', () => {
    const registerTool = vi.fn().mockResolvedValue(undefined)
    document.modelContext = { registerTool } as unknown as WebMcpModelContext
    registerWebMcpTool(NOOP_TOOL)
    expect(registerTool).toHaveBeenCalledTimes(1)
    const [tool, options] = registerTool.mock.calls[0]!
    expect(tool).toBe(NOOP_TOOL)
    expect(options.signal).toBeInstanceOf(AbortSignal)
    expect(options.signal.aborted).toBe(false)
  })

  it('aborts the signal passed to registerTool when the returned unregister is called', () => {
    const registerTool = vi.fn().mockResolvedValue(undefined)
    document.modelContext = { registerTool } as unknown as WebMcpModelContext
    const unregister = registerWebMcpTool(NOOP_TOOL)
    const { signal } = registerTool.mock.calls[0]![1]
    unregister()
    expect(signal.aborted).toBe(true)
  })

  it('swallows a rejected registerTool call rather than throwing', async () => {
    document.modelContext = {
      registerTool: vi.fn().mockRejectedValue(new Error('boom')),
    } as unknown as WebMcpModelContext
    expect(() => registerWebMcpTool(NOOP_TOOL)).not.toThrow()
    // Let the swallowed rejection's microtask settle before the test ends.
    await Promise.resolve()
    await Promise.resolve()
  })
})
