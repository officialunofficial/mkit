// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { VirtualFeed } from './virtual-feed'

const messages = (start: number, count: number) =>
  Array.from({ length: count }, (_, i) => ({ key: `message-${start + i}` }))
const row = (item: { key: string }) => <p>{item.key}</p>
const feed = (items: { key: string }[]) => <VirtualFeed items={items} renderItem={row} emptyContent={<p>Loading</p>} />
const originalScrollTo = HTMLElement.prototype.scrollTo
let hidden = false
const heights = new Map<Element, number>()
const resizeCallbacks = new Map<Element, () => void>()
const scrollTo = vi.fn(function (this: HTMLElement, options?: ScrollToOptions | number, y?: number) {
  this.scrollTop = Math.max(
    0,
    Math.min((typeof options === 'number' ? y : options?.top) ?? 0, this.scrollHeight - this.clientHeight),
  )
  queueMicrotask(() => this.dispatchEvent(new Event('scroll')))
})

beforeEach(() => {
  vi.useFakeTimers()
  hidden = false
  heights.clear()
  resizeCallbacks.clear()
  vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() => (hidden ? 'hidden' : 'visible'))
  // jsdom has no layout. Supply geometry, but use the real TanStack virtualizer,
  // its row measurement, observers, and scroll reconciliation.
  vi.spyOn(HTMLElement.prototype, 'offsetHeight', 'get').mockImplementation(function (this: HTMLElement) {
    return heights.get(this) ?? (this.hasAttribute('data-index') ? 56 : 384)
  })
  vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockReturnValue(600)
  vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(384)
  vi.spyOn(HTMLElement.prototype, 'scrollHeight', 'get').mockImplementation(function (this: HTMLElement) {
    return Math.max(384, Number.parseFloat((this.firstElementChild as HTMLElement)?.style.height || '0'))
  })
  vi.stubGlobal(
    'ResizeObserver',
    class {
      private targets = new Set<Element>()
      constructor(
        private callback: (
          entries: { target: Element; borderBoxSize: { blockSize: number; inlineSize: number }[] }[],
        ) => void,
      ) {}
      observe(element: Element) {
        this.targets.add(element)
        resizeCallbacks.set(element, () =>
          this.callback([
            { target: element, borderBoxSize: [{ blockSize: heights.get(element) ?? 56, inlineSize: 600 }] },
          ]),
        )
      }
      unobserve(element: Element) {
        this.targets.delete(element)
        resizeCallbacks.delete(element)
      }
      disconnect() {
        for (const element of this.targets) resizeCallbacks.delete(element)
        this.targets.clear()
      }
    },
  )
  vi.stubGlobal('requestAnimationFrame', (cb: FrameRequestCallback) => setTimeout(() => cb(performance.now()), 16))
  vi.stubGlobal('cancelAnimationFrame', clearTimeout)
  HTMLElement.prototype.scrollTo = scrollTo
  scrollTo.mockClear()
})
afterEach(() => {
  cleanup()
  HTMLElement.prototype.scrollTo = originalScrollTo
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})
const settle = async () => {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(200)
  })
}
const visibility = (value: boolean) =>
  act(() => {
    hidden = value
    document.dispatchEvent(new Event('visibilitychange'))
  })

it('does not animate background arrivals or resume catch-up', async () => {
  const view = render(feed(messages(0, 100)))
  await settle()
  scrollTo.mockClear()
  visibility(true)
  view.rerender(feed(messages(0, 110)))
  await settle()
  visibility(false)
  window.dispatchEvent(new Event('focus'))
  view.rerender(feed(messages(0, 120)))
  await settle()
  expect(scrollTo.mock.calls.some(([options]) => typeof options === 'object' && options.behavior === 'smooth')).toBe(
    false,
  )
  const viewport = screen.getByRole('region', { name: 'Lobby activity' })
  expect(viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight).toBeLessThanOrEqual(1)
})

it('keeps a reader in history when messages arrive across tab resume', async () => {
  const view = render(feed(messages(0, 100)))
  await settle()
  const viewport = screen.getByRole('region', { name: 'Lobby activity' })
  fireEvent.scroll(viewport, { target: { scrollTop: 1120 } })
  await settle()
  visibility(true)
  view.rerender(feed(messages(0, 110)))
  visibility(false)
  view.rerender(feed(messages(0, 120)))
  await settle()
  expect(viewport.scrollTop).toBe(1120)
  expect(screen.getByRole('button', { name: /Latest/ })).toBeVisible()
})

it('renders only a bounded window of a long feed', async () => {
  const view = render(feed(messages(0, 10_000)))
  await settle()
  expect(view.container.querySelectorAll('[data-index]').length).toBeLessThan(30)
  expect(screen.getByText('message-9999')).toBeInTheDocument()
})

it('anchors the same message when older history is prepended', async () => {
  const view = render(feed(messages(20, 100)))
  await settle()
  const viewport = screen.getByRole('region', { name: 'Lobby activity' })
  fireEvent.scroll(viewport, { target: { scrollTop: 1124 } })
  await settle()
  view.rerender(feed(messages(0, 120)))
  await settle()
  expect(viewport.scrollTop).toBe(2244)
})

it('starts at the latest message after asynchronous initial loading', async () => {
  const view = render(feed([]))
  await settle()
  view.rerender(feed(messages(0, 100)))
  await settle()
  const viewport = screen.getByRole('region', { name: 'Lobby activity' })
  expect(viewport.scrollTop).toBe(viewport.scrollHeight - viewport.clientHeight)
})

it('jumps immediately to latest on request and follows subsequent arrivals', async () => {
  const view = render(feed(messages(0, 100)))
  await settle()
  const viewport = screen.getByRole('region', { name: 'Lobby activity' })
  fireEvent.scroll(viewport, { target: { scrollTop: 1120 } })
  await settle()
  fireEvent.click(screen.getByRole('button', { name: /Latest/ }))
  await settle()
  view.rerender(feed(messages(0, 110)))
  await settle()
  expect(viewport.scrollTop).toBe(viewport.scrollHeight - viewport.clientHeight)
  expect(screen.queryByRole('button', { name: /Latest/ })).not.toBeInTheDocument()
})

it('stays pinned when a measured row grows after an image or reaction loads', async () => {
  const view = render(feed(messages(0, 100)))
  await settle()
  const viewport = screen.getByRole('region', { name: 'Lobby activity' })
  const lastRow = view.container.querySelector('[data-index="99"]')!
  act(() => {
    heights.set(lastRow, 180)
    resizeCallbacks.get(lastRow)!()
  })
  await settle()
  expect(viewport.scrollTop).toBe(viewport.scrollHeight - viewport.clientHeight)
})

it('preserves the visible row when a measured row above it grows', async () => {
  const view = render(feed(messages(0, 100)))
  await settle()
  const viewport = screen.getByRole('region', { name: 'Lobby activity' })
  fireEvent.scroll(viewport, { target: { scrollTop: 1124 } })
  await settle()
  // Finish scrolling before the late measurement; the virtualizer avoids
  // fighting active backward scrolling.
  fireEvent(viewport, new Event('scrollend'))
  const above = view.container.querySelector('[data-index="19"]')!
  act(() => {
    heights.set(above, 112)
    resizeCallbacks.get(above)!()
  })
  await settle()
  expect(viewport.scrollTop).toBe(1180)
})
