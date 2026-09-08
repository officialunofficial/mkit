'use client'

import { createContext, type ReactNode, useContext, useLayoutEffect, useRef, useState } from 'react'

const OverlayContainer = createContext<HTMLElement | undefined>(undefined)

/** Keep portals inside a native modal so its content remains interactive. */
export function useOverlayContainer() {
  return useContext(OverlayContainer)
}

/** Native stacking for nonmodal overlays. The caller owns focus and dismissal. */
export function TopLayer({ children }: { children: ReactNode }) {
  const host = useRef<HTMLDivElement>(null)
  useLayoutEffect(() => {
    const element = host.current
    if (!element || typeof element.showPopover !== 'function') return
    element.setAttribute('popover', 'manual')
    element.showPopover()
    return () => {
      element.hidePopover()
      element.removeAttribute('popover')
    }
  }, [])

  return (
    <div
      ref={host}
      style={{
        position: 'fixed',
        inset: 0,
        margin: 0,
        padding: 0,
        border: 0,
        width: '100%',
        height: '100%',
        maxWidth: 'none',
        maxHeight: 'none',
        overflow: 'visible',
        background: 'transparent',
        color: 'inherit',
        pointerEvents: 'none',
      }}
    >
      <div style={{ display: 'contents', pointerEvents: 'auto' }}>{children}</div>
    </div>
  )
}

/** A full-viewport modal host. Mount only while the drawer or dialog is open. */
export function ModalLayer({
  label,
  onClose,
  className,
  children,
}: {
  label: string
  onClose: () => void
  className?: string
  children: ReactNode
}) {
  const [element, setElement] = useState<HTMLDialogElement | null>(null)
  useLayoutEffect(() => {
    if (!element) return
    const previous = document.activeElement
    if (typeof element.showModal === 'function') element.showModal()
    else element.setAttribute('open', '')
    return () => {
      if (typeof element.close === 'function') element.close()
      else element.removeAttribute('open')
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus()
    }
  }, [element])
  return (
    <OverlayContainer value={element ?? undefined}>
      <dialog
        ref={setElement}
        aria-label={label}
        className={`modal-layer ${className ?? ''}`}
        onCancel={(event) => {
          event.preventDefault()
          onClose()
        }}
        onClick={(event) => {
          if (event.target === event.currentTarget) onClose()
        }}
        style={{
          position: 'fixed',
          inset: 0,
          margin: 0,
          padding: 0,
          border: 0,
          width: '100%',
          height: '100%',
          maxWidth: 'none',
          maxHeight: 'none',
          background: 'transparent',
          color: 'inherit',
        }}
      >
        {children}
      </dialog>
    </OverlayContainer>
  )
}
