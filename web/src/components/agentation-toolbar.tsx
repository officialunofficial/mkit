'use client'

import { Agentation } from 'agentation'

/**
 * Dev-only annotation toolbar (https://agentation.com). Lets you click elements on the page and leave notes that a
 * coding agent picks up via the local agentation MCP server on port 4747. Tree-shaken out of production builds by the
 * DEV guard.
 */
export function AgentationToolbar() {
  if (!import.meta.env.DEV) return null
  return <Agentation endpoint='http://localhost:4747' />
}
