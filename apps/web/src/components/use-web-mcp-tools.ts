import { useEffect } from 'react'
import { registerWebMcpTool, type WebMcpTool } from '../lib/webmcp'

/**
 * Register `tools` against `document.modelContext` (see `lib/webmcp.ts`) for the calling component's lifetime,
 * unregistering on unmount. A no-op everywhere WebMCP isn't supported.
 *
 * `tools` should be a stable array (e.g. from `useMemo` with an empty/near-empty dependency list): each identity change
 * re-registers every tool, and `execute` closures should instead read live state through refs so the tool set itself
 * never needs to change across renders.
 */
export function useWebMcpTools(tools: readonly WebMcpTool[]): void {
  useEffect(() => {
    const unregister = tools.map(registerWebMcpTool)
    return () => {
      for (const u of unregister) u()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tools])
}
