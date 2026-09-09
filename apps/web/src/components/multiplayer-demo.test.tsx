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

  it('renders the repository workspace without duplicating the shared account controls', async () => {
    await renderDemo()

    expect(screen.queryByRole('button', { name: /Create passkey identity/ })).not.toBeInTheDocument()

    // The repo browser (branches panel) renders against the seeded mock backend
    // even while signed out — `main` is always present.
    expect(await screen.findByText('main')).toBeInTheDocument()
  })

  it('shows the disabled compose placeholder while signed out', async () => {
    await renderDemo()
    expect(await screen.findByPlaceholderText(/Unlock signing in Account/)).toBeInTheDocument()
  })
})
