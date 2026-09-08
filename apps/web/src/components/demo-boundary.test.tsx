// @vitest-environment jsdom
import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import { DemoBoundary } from './demo-boundary'

afterEach(cleanup)

it('keeps the supplied loading layout through suspension and replaces it when ready', async () => {
  let ready = false
  let resolve!: () => void
  const pending = new Promise<void>((done) => {
    resolve = done
  })
  function Content() {
    if (!ready) throw pending
    return <button>Loaded demo</button>
  }
  const ui = () => (
    <DemoBoundary fallback={<div role='status'>Loading the lobby</div>}>
      <Content />
    </DemoBoundary>
  )
  const view = render(ui())
  expect(screen.getByRole('status')).toHaveTextContent('Loading the lobby')
  expect(screen.queryByRole('button')).toBeNull()
  await act(async () => {
    ready = true
    resolve()
    await pending
  })
  view.rerender(ui())
  expect(screen.getByRole('button', { name: 'Loaded demo' })).toBeInTheDocument()
  expect(screen.queryByRole('status')).toBeNull()
})
