'use client'

import { Agentation } from 'agentation'

/**
 * Dev-only annotation toolbar (https://agentation.com). Lets you click elements on the page and leave notes that a
 * coding agent picks up via the local agentation MCP server (default port 4747; override with VITE_AGENTATION_ENDPOINT
 * in .env.local, e.g. when viewing the dev server from another machine or running multiple MCP servers). Tree-shaken
 * out of production builds by the DEV guard.
 */
export function AgentationToolbar() {
  if (!import.meta.env.DEV) return null
  const endpoint = (import.meta.env.VITE_AGENTATION_ENDPOINT as string | undefined) ?? 'http://localhost:4747'
  return <Agentation endpoint={endpoint} />
}
