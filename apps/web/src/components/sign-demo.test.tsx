// @vitest-environment jsdom
import { cleanup, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { mkit } from '../lib/mkit'
import { SignDemo } from './sign-demo'
import { renderSuspended } from './test-support'

describe('SignDemo', () => {
  afterEach(cleanup)

  it('renders the signing identity and lets alice sign a message', async () => {
    await renderSuspended(<SignDemo />, mkit())

    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sign' })).toBeInTheDocument()

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Sign' }))

    // Once signed, the message locks and the live verifier appears, verified by
    // default (unmodified received text, alice's own key).
    expect(await screen.findByText(/Signed by alice/)).toBeInTheDocument()
    expect(await screen.findByText(/Verified/)).toBeInTheDocument()
  })

  it('flags tampering when the received message is edited', async () => {
    await renderSuspended(<SignDemo />, mkit())
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Sign' }))

    const received = await screen.findByLabelText('Received message')
    await user.clear(received)
    await user.type(received, 'a completely different message')

    expect(await screen.findByText(/Tampered/)).toBeInTheDocument()
  })
})
