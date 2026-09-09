// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { useWorkspaceDraftStore } from '../lib/workspace-draft-store'
import { Account } from './account'

const auth = vi.hoisted(() => ({
  session: undefined as undefined | null | { id: string; publicKey: string; expiresAt: number },
  pending: true,
  busy: false,
  status: null as string | null,
  hasPasskey: true,
  unlocked: false,
  embeddedBrowserWarning: null,
  onCreate: vi.fn(),
  onUnlock: vi.fn(),
  signOut: vi.fn(),
  lockSigning: vi.fn(),
}))
vi.mock('./auth-provider', () => ({ useAuth: () => auth }))
vi.mock('./multiplayer/player-label', () => ({
  OwnPlayerName: () => <span>Remembered player</span>,
  PlayerLabel: () => <span>Remembered player</span>,
  PlayerAvatar: () => null,
}))

beforeEach(() => {
  Object.assign(auth, { session: undefined, pending: true, busy: false, status: null, unlocked: false })
  vi.clearAllMocks()
  useWorkspaceDraftStore.getState().clearAll()
})
afterEach(cleanup)

it('waits for session restoration before offering account creation', async () => {
  const view = render(<Account />)
  expect(screen.getByRole('region', { name: 'Account' })).toHaveAttribute('data-auth-status', 'loading')
  expect(screen.queryByRole('button', { name: 'Create passkey identity' })).not.toBeInTheDocument()
  auth.pending = false
  auth.session = null
  view.rerender(<Account />)
  expect(screen.getByRole('button', { name: 'Sign in' })).toBeEnabled()
  expect(screen.queryByRole('button', { name: 'Create a passkey' })).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
  expect(screen.getByRole('button', { name: 'Create a passkey' })).toBeEnabled()
})

it('remembers the signed-in player while signing is locked and delegates explicit unlock', async () => {
  auth.pending = false
  auth.session = { id: 'session', publicKey: 'ab'.repeat(32), expiresAt: Date.now() + 1000 }
  render(<Account />)
  await userEvent.click(screen.getByRole('button', { name: 'Account' }))
  const account = screen.getByRole('region', { name: 'Account' })
  expect(account).toHaveAttribute('data-auth-status', 'signed-in')
  expect(account).toHaveAttribute('data-signing-status', 'locked')
  expect(account).toHaveAttribute('data-public-key', auth.session.publicKey)
  expect(screen.getByText('Remembered player')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Create passkey identity' })).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Unlock signing' }))
  expect(auth.onUnlock).toHaveBeenCalledOnce()
})

it('keeps lock-signing and sign-out as distinct shared actions', async () => {
  auth.pending = false
  auth.session = { id: 'session', publicKey: 'ab'.repeat(32), expiresAt: Date.now() + 1000 }
  auth.unlocked = true
  render(<Account />)
  await userEvent.click(screen.getByRole('button', { name: 'Account' }))
  await userEvent.click(screen.getByRole('button', { name: 'Lock signing' }))
  expect(auth.lockSigning).toHaveBeenCalledOnce()
  expect(auth.signOut).not.toHaveBeenCalled()
  await userEvent.click(screen.getByRole('button', { name: 'Sign out' }))
  expect(auth.signOut).toHaveBeenCalledOnce()
})

it('protects drafts from sign-out and leaves them intact when canceled', async () => {
  auth.pending = false
  auth.session = { id: 'session', publicKey: 'ab'.repeat(32), expiresAt: Date.now() + 1000 }
  useWorkspaceDraftStore.getState().setDraft('session:workspace', {
    path: 'README.md',
    content: 'edited',
    original: '',
    hash: null,
    editable: true,
  })
  render(<Account />)
  await userEvent.click(screen.getByRole('button', { name: 'Account' }))
  await userEvent.click(screen.getByRole('button', { name: /^Sign out$/ }))
  expect(screen.getByRole('dialog', { name: 'Sign out and discard edits?' })).toBeInTheDocument()
  expect(auth.signOut).not.toHaveBeenCalled()
  await userEvent.click(screen.getByRole('button', { name: 'Keep editing' }))
  expect(screen.queryByRole('dialog', { name: 'Sign out and discard edits?' })).not.toBeInTheDocument()
  expect(useWorkspaceDraftStore.getState().scopes.size).toBe(1)
  expect(auth.signOut).not.toHaveBeenCalled()
  await userEvent.click(screen.getByRole('button', { name: /^Sign out$/ }))
  await userEvent.click(screen.getByRole('button', { name: 'Sign out and discard' }))
  expect(auth.signOut).toHaveBeenCalledOnce()
})
