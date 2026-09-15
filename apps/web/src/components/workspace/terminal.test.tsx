// @vitest-environment jsdom
import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { WorkspaceTerminal } from './terminal'

const addon = vi.hoisted(() => ({
  connect: vi.fn(),
  dispose: vi.fn(),
  options: null as null | { onStateChange: (state: string, error?: Error) => void },
}))
vi.mock('@xterm/xterm', () => ({
  Terminal: class {
    loadAddon() {}
    open() {}
    dispose() {}
  },
}))
vi.mock('@xterm/addon-fit', () => ({
  FitAddon: class {
    fit() {}
  },
}))
vi.mock('@cloudflare/sandbox/xterm', () => ({
  SandboxAddon: class {
    constructor(options: NonNullable<typeof addon.options>) {
      addon.options = options
    }
    connect = addon.connect
    dispose = addon.dispose
  },
}))
beforeEach(() => {
  vi.useFakeTimers()
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      disconnect() {}
    },
  )
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
  addon.options = null
})
async function mount() {
  const result = render(<WorkspaceTerminal workspaceId='abc' />)
  await act(async () => {
    await vi.dynamicImportSettled()
    await vi.advanceTimersByTimeAsync(0)
  })
  expect(addon.connect).toHaveBeenCalledTimes(1)
  return result
}
it('retries a dropped terminal connection without a manual click', async () => {
  await mount()
  act(() => addon.options!.onStateChange('connected'))
  act(() => addon.options!.onStateChange('disconnected'))
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1000)
  })
  expect(addon.connect).toHaveBeenCalledTimes(2)
})
it('does not reopen the terminal after its owner view unmounts', async () => {
  const view = await mount()
  act(() => addon.options!.onStateChange('disconnected'))
  view.unmount()
  await act(async () => {
    await vi.advanceTimersByTimeAsync(30000)
  })
  expect(addon.connect).toHaveBeenCalledTimes(1)
})
it('stops after three failed retries and leaves the manual reconnect available', async () => {
  await mount()
  for (const delay of [1000, 2000, 4000]) {
    act(() => addon.options!.onStateChange('disconnected'))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(delay)
    })
  }
  expect(addon.connect).toHaveBeenCalledTimes(4)
  act(() => addon.options!.onStateChange('disconnected'))
  await act(async () => {
    await vi.advanceTimersByTimeAsync(30000)
  })
  expect(addon.connect).toHaveBeenCalledTimes(4)
  expect(screen.getByRole('status').textContent).toContain('Select Reconnect')
  expect(screen.getByRole('button', { name: 'Reconnect' })).toBeDefined()
})
