// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { InfoTip } from './multiplayer/info-tip'
import { ModalLayer, TopLayer } from './top-layer'
const active = new Set<HTMLElement>()
const showPopover = vi.fn(function (this: HTMLElement) {
  expect(this.isConnected).toBe(true)
  expect(this.getAttribute('popover')).toBe('manual')
  this.style.display = 'block' // jsdom cannot apply the native :popover-open state.
  active.add(this)
})
const hidePopover = vi.fn(function (this: HTMLElement) {
  this.style.removeProperty('display')
  active.delete(this)
})
beforeEach(() => {
  active.clear()
  vi.clearAllMocks()
  Object.defineProperty(HTMLElement.prototype, 'showPopover', { configurable: true, value: showPopover })
  Object.defineProperty(HTMLElement.prototype, 'hidePopover', { configurable: true, value: hidePopover })
})
afterEach(() => {
  cleanup()
  Reflect.deleteProperty(HTMLElement.prototype, 'showPopover')
  Reflect.deleteProperty(HTMLElement.prototype, 'hidePopover')
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')
})
describe('TopLayer', () => {
  it('opens one native host, keeps it open on updates, and removes it on unmount', () => {
    const { rerender, unmount } = render(
      <TopLayer>
        <button>Panel action</button>
      </TopLayer>,
    )
    expect(showPopover).toHaveBeenCalledTimes(1)
    expect(active.size).toBe(1)
    rerender(
      <TopLayer>
        <button>Updated action</button>
      </TopLayer>,
    )
    expect(showPopover).toHaveBeenCalledTimes(1)
    unmount()
    expect(hidePopover).toHaveBeenCalledTimes(1)
    expect(active.size).toBe(0)
  })
  it('leaves content usable when the browser lacks the Popover API', () => {
    Reflect.deleteProperty(HTMLElement.prototype, 'showPopover')
    Reflect.deleteProperty(HTMLElement.prototype, 'hidePopover')
    render(
      <TopLayer>
        <button>Fallback action</button>
      </TopLayer>,
    )
    expect(screen.getByRole('button', { name: 'Fallback action' })).toBeVisible()
    expect(document.querySelector('[popover]')).toBeNull()
  })
  it('keeps Radix dismissal and focus restoration while removing the native host', async () => {
    render(<InfoTip label='About rooms'>Room details</InfoTip>)
    const trigger = screen.getByRole('button', { name: 'About rooms' })
    trigger.focus()
    fireEvent.click(trigger)
    await screen.findByRole('dialog')
    expect(active.size).toBe(1)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(active.size).toBe(0)
    expect(trigger).toHaveFocus()
  })
})

describe('ModalLayer', () => {
  it('opens a modal, closes it on unmount, and restores the original focus', () => {
    const showModal = vi.fn(function (this: HTMLDialogElement) {
      this.setAttribute('open', '')
    })
    const close = vi.fn(function (this: HTMLDialogElement) {
      this.removeAttribute('open')
    })
    Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value: showModal })
    Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value: close })
    const trigger = document.createElement('button')
    document.body.append(trigger)
    trigger.focus()
    const { unmount } = render(
      <ModalLayer label='Commit details' onClose={() => {}}>
        <button>Close details</button>
      </ModalLayer>,
    )
    expect(showModal).toHaveBeenCalledTimes(1)
    screen.getByRole('button', { name: 'Close details' }).focus()
    unmount()
    expect(close).toHaveBeenCalledTimes(1)
    expect(trigger).toHaveFocus()
    trigger.remove()
  })

  it('keeps nested popovers inside the modal rather than the inert document body', async () => {
    render(
      <ModalLayer label='Commit details' onClose={() => {}}>
        <InfoTip label='About commits'>Details help</InfoTip>
      </ModalLayer>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'About commits' }))
    const help = await screen.findByText('Details help')
    expect(help.closest('dialog')).toBe(screen.getByRole('dialog', { name: 'Commit details' }))
  })

  it('requests dismissal on Escape or backdrop click, but not content clicks', () => {
    const onClose = vi.fn()
    render(
      <ModalLayer label='Commit details' onClose={onClose}>
        <button>Inside</button>
      </ModalLayer>,
    )
    const dialog = screen.getByRole('dialog', { name: 'Commit details' })
    fireEvent.click(screen.getByRole('button', { name: 'Inside' }))
    expect(onClose).not.toHaveBeenCalled()
    fireEvent.click(dialog)
    expect(onClose).toHaveBeenCalledTimes(1)
    const cancel = new Event('cancel', { cancelable: true })
    fireEvent(dialog, cancel)
    expect(cancel.defaultPrevented).toBe(true)
    expect(onClose).toHaveBeenCalledTimes(2)
  })
})
