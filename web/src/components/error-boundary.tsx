'use client'

import { Component, type ErrorInfo, type ReactNode } from 'react'

type ErrorBoundaryProps = {
  children: ReactNode
  /** Optional override for the fallback UI; receives the error and a retry callback. */
  fallback?: (error: Error, reset: () => void) => ReactNode
}

type ErrorBoundaryState = { error: Error | null }

/**
 * Catches render-time errors thrown by its subtree — most importantly the wasm-init failure that `use(mkit())`
 * (components/use-mkit.ts) throws when the module can't load. Without this, that error propagates to the root and the
 * demo renders blank. React has no hook form of an error boundary, so this stays a class component by necessity.
 *
 * Pairs with `<DemoBoundary>` (Suspense for the _loading_ state); this handles the _failed_ state.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surface in the console so it shows up in Cloudflare Worker logs / devtools
    // rather than failing silently.
    console.error('ErrorBoundary caught:', error, info.componentStack)
  }

  reset = () => {
    this.setState({ error: null })
  }

  render() {
    const { error } = this.state
    if (error === null) return this.props.children
    if (this.props.fallback) return this.props.fallback(error, this.reset)
    return <DefaultFallback error={error} reset={this.reset} />
  }
}

function DefaultFallback({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <div role='alert' className='space-y-3 rounded-md border border-hairline p-4'>
      <p className='text-sm font-medium text-fg'>This demo failed to load.</p>
      <p className='max-w-prose text-sm text-muted'>
        The mkit WebAssembly module couldn&rsquo;t start in your browser. Reloading usually fixes it; if it keeps
        happening, your browser may be blocking WebAssembly.
      </p>
      {error.message ? <p className='font-mono text-xs break-words text-subtle'>{error.message}</p> : null}
      <button
        type='button'
        onClick={reset}
        className='-mx-2 inline-block px-2 py-2 text-sm underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
      >
        Try again
      </button>
    </div>
  )
}
