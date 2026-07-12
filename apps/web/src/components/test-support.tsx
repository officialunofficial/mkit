// Test-only helper shared by the demo-component render tests
// (*-demo.test.tsx). Not a test file itself — no assertions live here.

import { act, render, type RenderResult } from '@testing-library/react'
import { type ReactElement, Suspense } from 'react'

/**
 * Renders `ui` inside a `<Suspense>` boundary and waits for `settle` (typically `mkit()`, the wasm module promise every
 * demo suspends on via `use()`) before forcing a fresh render pass.
 *
 * WHY the extra step: React's Suspense "ping" retry — the internal mechanism that automatically re-renders a suspended
 * boundary once the thrown promise resolves — does not fire in this jsdom + vitest test environment (reproduced with a
 * bare `use()` on a plain `setTimeout` promise, independent of wasm or any app code; a real browser is unaffected, so
 * this is a test-environment limitation, not a product bug). Re-invoking `rerender` with the same tree once `settle`
 * has resolved forces React to re-evaluate `use()`, which then reads the already-fulfilled promise's cached value
 * synchronously instead of suspending again.
 */
export async function renderSuspended(ui: ReactElement, settle: Promise<unknown>): Promise<RenderResult> {
  const result = render(<Suspense fallback={<p>Loading…</p>}>{ui}</Suspense>)
  await settle
  await act(async () => {
    // A freshly-built element (not the same reference passed to `render`) —
    // forces React to re-evaluate `use()` rather than bail out early on an
    // unchanged element.
    result.rerender(<Suspense fallback={<p>Loading…</p>}>{ui}</Suspense>)
    await Promise.resolve()
  })
  return result
}
