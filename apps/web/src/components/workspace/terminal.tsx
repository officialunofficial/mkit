'use client'
import { useEffect, useRef, useState } from 'react'
import { WORKSPACE_API } from '../../lib/workspace-client'

export function WorkspaceTerminal({ workspaceId }: { workspaceId: string }) {
  const container = useRef<HTMLDivElement>(null)
  const [status, setStatus] = useState('Connecting…')
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    let disposed = false
    let cleanup = () => {}
    let retryTimer: ReturnType<typeof setTimeout> | undefined
    let retries = 0
    async function open() {
      const [{ Terminal }, { FitAddon }, { SandboxAddon }] = await Promise.all([
        import('@xterm/xterm'),
        import('@xterm/addon-fit'),
        import('@cloudflare/sandbox/xterm'),
        import('@xterm/xterm/css/xterm.css'),
      ])
      if (disposed || !container.current) return
      const terminal = new Terminal({
        fontFamily: '"DM Mono", monospace',
        fontSize: 13,
        cursorBlink: true,
        convertEol: true,
        theme: { background: '#171717', foreground: '#f5f5f5' },
      })
      const fit = new FitAddon()
      const addon = new SandboxAddon({
        reconnect: false,
        getWebSocketUrl: ({ origin }) => `${origin}${WORKSPACE_API}/${encodeURIComponent(workspaceId)}/terminal`,
        onStateChange: (state, error) => {
          if (disposed) return
          if (state === 'connected') {
            retries = 0
            clearTimeout(retryTimer)
            retryTimer = undefined
          }
          setStatus(error?.message ?? state)
          if (state === 'disconnected' && !retryTimer && retries < 3) {
            const delay = 1000 * 2 ** retries++
            setStatus('Connection interrupted. Reconnecting…')
            retryTimer = setTimeout(() => {
              retryTimer = undefined
              if (!disposed) addon.connect({ sandboxId: workspaceId })
            }, delay)
          }
        },
      })
      terminal.loadAddon(fit)
      terminal.loadAddon(addon)
      terminal.open(container.current)
      fit.fit()
      const observer = new ResizeObserver(() => fit.fit())
      observer.observe(container.current)
      cleanup = () => {
        observer.disconnect()
        addon.dispose()
        terminal.dispose()
      }
      addon.connect({ sandboxId: workspaceId })
    }
    void open().catch((error: unknown) => {
      if (!disposed) setStatus(error instanceof Error ? error.message : 'Terminal connection failed.')
    })
    return () => {
      disposed = true
      clearTimeout(retryTimer)
      cleanup()
    }
  }, [workspaceId, attempt])
  return (
    <section className='data-frame overflow-hidden' aria-label='Terminal'>
      <div className='flex items-center justify-between gap-3 p-3'>
        <h2 className='ds-h3'>Terminal</h2>
        <span className='text-xs text-muted' role='status'>
          {status === 'disconnected' ? 'Disconnected. Select Reconnect to open a terminal.' : status}
        </span>
        <button
          className='btn btn--outlined btn--small'
          onClick={() => {
            setStatus('Connecting…')
            setAttempt((a) => a + 1)
          }}
        >
          Reconnect
        </button>
      </div>
      <div ref={container} className='h-72 bg-[#171717] p-2' />
    </section>
  )
}
