'use client'
import { XIcon } from '@phosphor-icons/react/ssr'
import type { ReactNode } from 'react'
import { ModalLayer } from '../top-layer'

export function WorkspaceDialog({
  title,
  onClose,
  children,
  footer,
}: {
  title: string
  onClose: () => void
  children: ReactNode
  footer: ReactNode
}) {
  return (
    <ModalLayer label={title} onClose={onClose}>
      <div className='ws-dialog'>
        <header>
          <h2>{title}</h2>
          <button type='button' className='btn btn--ghost btn--small' aria-label='Close dialog' onClick={onClose}>
            <XIcon size={16} aria-hidden />
          </button>
        </header>
        <div className='ws-dialog-body'>{children}</div>
        <footer>{footer}</footer>
      </div>
    </ModalLayer>
  )
}
