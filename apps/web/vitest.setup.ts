import '@testing-library/jest-dom/vitest'
import { configure } from '@testing-library/dom'
import { registerNodeInit } from './src/lib/mkit.node'

registerNodeInit()

// Each test file gets its own module registry, so the wasm module is read off
// disk and compiled fresh per file (registerNodeInit above) — a cold compile
// occasionally runs past RTL's default 1000ms `findBy*`/`waitFor` timeout.
// Widen it globally rather than passing `{ timeout }` at every call site.
configure({ asyncUtilTimeout: 15_000 })

// jsdom has no ResizeObserver; @radix-ui/react-scroll-area (used inside the
// multiplayer demo's repo log) observes size on mount. A no-op stub is enough
// for a render/interaction smoke test — nothing here asserts on actual
// scroll-thumb sizing.
if (typeof window !== 'undefined' && typeof window.ResizeObserver === 'undefined') {
  class ResizeObserverStub {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  window.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver
}
