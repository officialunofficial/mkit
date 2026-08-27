// WebMCP (https://github.com/webmachinelearning/webmcp) integration — a thin, feature-detected wrapper around the
// proposed `document.modelContext` browser API. WebMCP lets a page register tools an in-page or browser-embedded AI
// agent can discover and invoke directly, sharing the page's live state instead of re-scraping the DOM or replicating
// server logic behind a separate backend integration.
//
// No polyfill is bundled: where a browser or extension hasn't implemented the API, `document.modelContext` is simply
// absent, and every function here degrades to a documented no-op — registering a tool costs nothing and calling
// `isWebMcpSupported()` first is never required.

/** One content block of a tool result — WebMCP mirrors MCP's `{ type: 'text', text }` shape. */
export type WebMcpContentBlock = { type: 'text'; text: string }

/** The value a tool's `execute` resolves to, per the WebMCP tool-result shape. */
export type WebMcpToolResult = {
  content: WebMcpContentBlock[]
  /** Set when the tool ran but failed in a way the agent should see as an error, not a crash. */
  isError?: boolean
}

/** A JSON Schema object describing a tool's input — passed straight through to `registerTool`. */
export type WebMcpInputSchema = {
  type: 'object'
  properties: Record<string, unknown>
  required?: string[]
}

/**
 * One WebMCP tool declaration, as passed to `document.modelContext.registerTool`. `execute` uses method-shorthand
 * syntax (not a property typed as a function) so TypeScript checks its `args` parameter bivariantly — a concrete tool
 * can declare the exact args its schema promises (e.g. `{ hash: string }`) while still satisfying `WebMcpTool[]`, the
 * same way DOM event-handler methods do.
 */
export type WebMcpTool<Args = Record<string, unknown>> = {
  name: string
  description: string
  inputSchema: WebMcpInputSchema
  execute(args: Args, options: { signal: AbortSignal }): Promise<WebMcpToolResult>
}

/** The subset of the proposed `document.modelContext` interface this module drives. */
export interface WebMcpModelContext {
  registerTool: (tool: WebMcpTool, options?: { signal?: AbortSignal }) => Promise<void>
  getTools: (options?: { fromOrigins?: string[] }) => Promise<WebMcpTool[]>
  executeTool: (
    tool: WebMcpTool,
    args: Record<string, unknown>,
    options?: { signal?: AbortSignal },
  ) => Promise<WebMcpToolResult>
  addEventListener: (type: 'toolchange', listener: () => void) => void
  removeEventListener: (type: 'toolchange', listener: () => void) => void
}

declare global {
  interface Document {
    /** Present only in browsers/extensions implementing the WebMCP proposal — absent everywhere else. */
    modelContext?: WebMcpModelContext | undefined
  }
}

/** Whether this browser (or an installed extension) implements `document.modelContext`. */
export function isWebMcpSupported(): boolean {
  return typeof document !== 'undefined' && !!document.modelContext
}

/** Wrap plain text as a successful tool result. */
export function webMcpText(text: string): WebMcpToolResult {
  return { content: [{ type: 'text', text }] }
}

/**
 * Wrap plain text as a failed tool result (`isError: true`) — for an expected failure the agent should read, not a
 * thrown exception.
 */
export function webMcpError(message: string): WebMcpToolResult {
  return { content: [{ type: 'text', text: message }], isError: true }
}

/**
 * Register one tool against `document.modelContext`, if present. Returns an unregister function that's always safe to
 * call — a no-op both where the API isn't supported and after it's already been called. Registration failures (e.g. a
 * page navigating away mid-call) have no user-facing surface, so they're swallowed rather than thrown into the caller.
 */
export function registerWebMcpTool(tool: WebMcpTool): () => void {
  const modelContext = typeof document !== 'undefined' ? document.modelContext : undefined
  if (!modelContext) return () => {}
  const controller = new AbortController()
  void modelContext.registerTool(tool, { signal: controller.signal }).catch(() => {})
  return () => controller.abort()
}
