// @vitest-environment jsdom
import { cleanup, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { mkit } from '../lib/mkit'
import { AttestDemo } from './attest-demo'
import { renderSuspended } from './test-support'

describe('AttestDemo', () => {
  afterEach(cleanup)

  it('renders a verified attestation by default (untampered claim/subject/signer)', async () => {
    await renderSuspended(<AttestDemo />, mkit())
    expect(screen.getByText(/attests/)).toBeInTheDocument()
    expect(screen.getByText('Verified ✓')).toBeInTheDocument()
    expect(screen.getByText('Ready ✓')).toBeInTheDocument()
  })

  it('flags the attestation as not verified once the claim is tampered', async () => {
    await renderSuspended(<AttestDemo />, mkit())
    const user = userEvent.setup()

    const claim = screen.getByLabelText('Claim')
    await user.clear(claim)
    // `{`/`}` are special-key syntax to user-event's `type` — double them to
    // type the literal characters (https://testing-library.com/docs/user-event/keyboard).
    await user.type(claim, '{{"reviewed":false}}')

    expect(await screen.findByText('Not verified ✗')).toBeInTheDocument()
    expect(screen.getByText(/The claim was changed after signing\./)).toBeInTheDocument()
  })

  it('flags the attestation as not verified when checked against the wrong signer', async () => {
    await renderSuspended(<AttestDemo />, mkit())
    const user = userEvent.setup()

    expect(screen.getByText('Verified ✓')).toBeInTheDocument()
    // Two <select>s in order: "About commit" then "Verify with".
    const selects = screen.getAllByRole('combobox')
    await user.selectOptions(selects[1] as HTMLSelectElement, 'mallory')

    expect(await screen.findByText('Not verified ✗')).toBeInTheDocument()
    expect(screen.getByText(/Signed by alice, not mallory\./)).toBeInTheDocument()
  })
})
