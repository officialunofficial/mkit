// @vitest-environment jsdom
import { cleanup, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { mkit } from '../lib/mkit'
import { PushDemo } from './push-demo'
import { renderSuspended } from './test-support'

describe('PushDemo', () => {
  afterEach(cleanup)

  it('starts on step 1 (whole file, not yet chunked)', async () => {
    await renderSuspended(<PushDemo />, mkit())
    expect(screen.getByText('Start with a large file')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Chunk it/ })).toBeInTheDocument()
  })

  it('walks through chunk → edit → push as the user clicks next', async () => {
    await renderSuspended(<PushDemo />, mkit())
    const user = userEvent.setup()

    await user.click(screen.getByRole('button', { name: /Chunk it/ }))
    expect(await screen.findByText('Split it into chunks')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /Edit a byte/ }))
    expect(await screen.findByText('Change one byte')).toBeInTheDocument()
    expect(screen.getByLabelText('Byte to flip')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /Push it/ }))
    expect(await screen.findByText('Push only what changed')).toBeInTheDocument()
    // The comparison bars — git sends the whole file, mkit sends a delta.
    expect(screen.getByText(/git resends the whole file/)).toBeInTheDocument()
    expect(screen.getByText(/mkit sends only a delta of the changed chunk/)).toBeInTheDocument()
  })
})
