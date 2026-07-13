// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { useIdentityStore } from '../lib/identity-store'
import { mkit } from '../lib/mkit'
import { MultiplayerDemo } from './multiplayer-demo'
import { renderSuspended } from './test-support'

function renderDemo() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return renderSuspended(
    <QueryClientProvider client={client}>
      <MultiplayerDemo />
    </QueryClientProvider>,
    mkit(),
  )
}

describe('MultiplayerDemo', () => {
  beforeEach(() => {
    useIdentityStore.getState().reset()
  })
  afterEach(cleanup)

  it('renders the locked identity panel and the repository workspace (mock offline backend)', async () => {
    await renderDemo()

    // Locked state (no identity/passkey yet): the create/unlock actions.
    expect(screen.getByRole('button', { name: /Create passkey identity/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Unlock existing passkey/ })).toBeInTheDocument()

    // The repo browser (branches panel) renders against the seeded mock backend
    // even while signed out — `main` is always present.
    expect(await screen.findByText('main')).toBeInTheDocument()
  })

  it('shows the disabled compose placeholder while signed out', async () => {
    await renderDemo()
    expect(screen.getByRole('button', { name: /Create passkey identity/ })).toBeInTheDocument()
    // ComposeDisabled's placeholder nudges the signed-out visitor to unlock before posting.
    expect(await screen.findByPlaceholderText(/Create or unlock an identity/)).toBeInTheDocument()
  })
})
