'use client'

// WebMCP (https://github.com/webmachinelearning/webmcp) tool surface for the multiplayer repo demo. Registers
// `document.modelContext` tools that let an in-page or browser-embedded agent read the room's branches and commit
// history, and — once the visitor has unlocked an identity — push, remix, or branch on their behalf. Every write tool
// goes through the SAME backend + signing hooks as the Compose/RepoLog UI (`usePushCommit`, `useDerive`), so an
// agent's actions and the visitor's clicks produce identical, indistinguishable signed commits. Only `mkit_select_branch`
// drives the visible branch/commit selection (mirroring a click on a branch row) — the write tools deliberately don't,
// since that selection doubles as Compose's push-target field and a write tool succeeding mid-edit would otherwise
// silently discard a branch name the visitor is still typing.
//
// Renders nothing. A sibling of the panels it mirrors, not a wrapper around them, so tool registration doesn't couple
// into their render trees. The tool list is registered ONCE (stable across renders): every `execute` reads current
// room/identity/backend state through a ref kept fresh each render, so re-renders never churn the registration (which
// would otherwise fire a `toolchange` event on every keystroke) and a write tool that's called while the identity is
// locked, or before the backend has loaded, fails with the same explanatory message the UI shows instead of just
// disappearing from the tool list.

import { type QueryClient, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useRef } from 'react'
import { useIdentityStore } from '../../lib/identity-store'
import {
  CasConflictError,
  type CommitLogEntry,
  IdentityLockedError,
  repoKeys,
  usePushCommit,
  useRepoBackend,
  type RepoBackend,
} from '../../lib/repo-api'
import { webMcpError, webMcpText, type WebMcpTool } from '../../lib/webmcp'
import { useMkit } from '../use-mkit'
import { useWebMcpTools } from '../use-web-mcp-tools'
import { useDerive } from './compose'
import { CAS_CONFLICT_COPY, IDENTITY_LOCKED_COPY, errMsg } from './shared'

type MkitApi = ReturnType<typeof useMkit>
type PushCommit = ReturnType<typeof usePushCommit>
type Derive = ReturnType<typeof useDerive>

/** Everything a tool's `execute` needs, read fresh off a ref each call so the tools themselves never need to change. */
type Latest = {
  room: string
  api: MkitApi
  backend: RepoBackend | null
  seedHex: string | null
  pubkeyHex: string | null
  push: PushCommit
  derive: Derive
  selectedRef: string
  onSelectRef: (ref: string) => void
  onSelectCommit: (hash: string | null) => void
  /**
   * The SAME QueryClient RefsPanel/RepoLog/Compose read. Reads that share a query key with those hooks (an object by
   * hash, a branch's head, a limit-suffixed commit-log page) go through this via `fetchQuery` instead of `backend.*`
   * directly, so a tool call and the visible UI dedupe requests and stay one cache the WebSocket keeps live-patched —
   * not two independent reads of the same room. `mkit_list_branches` is the one exception: `useRefs`' cache holds
   * paginated `useInfiniteQuery` pages, a different shape than the flat list this tool returns, so sharing that key
   * would corrupt the branches panel's cache rather than warm it — it still calls `backend.listRefs` directly.
   */
  queryClient: QueryClient
}

const DEFAULT_LOG_LIMIT = 20
const DEFAULT_REFS_LIMIT = 50

/**
 * Map a write-tool failure to the same copy the Compose/RepoLog UI shows for the identical error, via `humanizeError`
 * for anything else — so a WebMCP-facing error never disagrees with the UI's, and never leaks raw technical detail.
 */
function mapWriteError(e: unknown): string {
  if (e instanceof CasConflictError) return CAS_CONFLICT_COPY
  if (e instanceof IdentityLockedError) return IDENTITY_LOCKED_COPY
  return errMsg(e)
}

/**
 * One decoded commit/remix, shaped for a tool result — mirrors `CommitDetail`'s decode, minus the JSX. Decodes the
 * object bytes exactly once (`object_kind` then the matching decoder), unlike `CommitDetail`'s own copy of this logic
 * which currently decodes twice.
 *
 * Fetches the raw bytes through `queryClient`, under the exact key/staleTime `useObject` uses — objects are
 * content-addressed and immutable, so a hash `CommitDetail` (or an earlier tool call) already resolved is served
 * straight from cache, with no network round-trip and no risk of ever seeing stale bytes for it.
 */
async function describeCommit(
  api: MkitApi,
  backend: RepoBackend,
  queryClient: QueryClient,
  room: string,
  hash: string,
) {
  const bytes = await queryClient.fetchQuery({
    queryKey: repoKeys.object(room, hash),
    queryFn: () => backend.getObject(room, hash),
    staleTime: Number.POSITIVE_INFINITY,
    gcTime: Number.POSITIVE_INFINITY,
  })
  if (!bytes) return null
  let kind: string
  try {
    kind = api.object_kind(bytes)
  } catch {
    return null
  }
  if (kind !== 'commit' && kind !== 'remix') return null
  const isRemix = kind === 'remix'
  const info = isRemix ? api.remix_decode(bytes) : api.commit_decode(bytes)
  const parents: string[] = []
  for (let i = 0; i < info.parent_count; i++) {
    const p = info.parent(i)
    if (p) parents.push(p)
  }
  const sources: Array<{ upstreamIdHex: string; commitHashHex: string }> = []
  if (isRemix) {
    const remixInfo = info as ReturnType<MkitApi['remix_decode']>
    for (let i = 0; i < remixInfo.source_count; i++) {
      const s = remixInfo.source(i)
      if (s) sources.push({ upstreamIdHex: s.upstream_id_hex, commitHashHex: s.commit_hash_hex })
    }
  }
  return {
    hash,
    kind,
    message: info.message,
    signerHex: info.signer_hex,
    timestamp: Number(info.timestamp),
    treeHex: info.tree_hex,
    signatureHex: info.signature_hex,
    parents,
    sources,
  }
}

/** Build the fixed WebMCP tool set once. Every `execute` dereferences `latest.current` — never a render-scoped value. */
function buildTools(latest: { current: Latest }): WebMcpTool[] {
  return [
    {
      name: 'mkit_get_identity',
      description:
        "Report whether this browser tab has an unlocked signing identity, and its public key. Write tools (push/remix/branch) fail with a clear error when locked — call this first if you're unsure.",
      inputSchema: { type: 'object', properties: {} },
      async execute() {
        const l = latest.current
        return webMcpText(
          JSON.stringify({ unlocked: !!l.seedHex, pubkeyHex: l.pubkeyHex, room: l.room, selectedRef: l.selectedRef }),
        )
      },
    },
    {
      name: 'mkit_list_branches',
      description: 'List branches (refs) in the shared mkit repository, each with the commit hash its head points at.',
      inputSchema: {
        type: 'object',
        properties: {
          prefix: { type: 'string', description: 'Only list branches whose name starts with this prefix.' },
          limit: { type: 'number', description: `Max branches to return (default ${DEFAULT_REFS_LIMIT}).` },
        },
      },
      async execute(args: { prefix?: string; limit?: number }) {
        const l = latest.current
        const backend = l.backend
        if (!backend) return webMcpError('The repository backend is not ready yet. Try again in a moment.')
        const limit = args.limit ?? DEFAULT_REFS_LIMIT
        // `listRefs`'s pageSize<=0 means "unpaginated: return everything" (its legacy default), the opposite of what
        // a caller-supplied `limit: 0` means here — short-circuit before that page-size sentinel kicks in.
        if (limit <= 0) return webMcpText(JSON.stringify({ total: 0, branches: [] }))
        try {
          const page = await backend.listRefs(l.room, args.prefix, { pageSize: limit })
          return webMcpText(
            JSON.stringify({
              total: page.total,
              branches: page.refs.map((r) => ({ name: r.name, head: r.objectIdHex })),
            }),
          )
        } catch (e) {
          return webMcpError(errMsg(e))
        }
      },
    },
    {
      name: 'mkit_get_commit_log',
      description: 'List recent commits (newest first) on one branch of the shared mkit repository.',
      inputSchema: {
        type: 'object',
        properties: {
          ref: { type: 'string', description: 'Branch name (default "main").' },
          limit: { type: 'number', description: `Max commits to return (default ${DEFAULT_LOG_LIMIT}).` },
        },
      },
      async execute(args: { ref?: string; limit?: number }) {
        const l = latest.current
        const backend = l.backend
        if (!backend) return webMcpError('The repository backend is not ready yet. Try again in a moment.')
        const ref = args.ref?.trim() || 'main'
        const limit = args.limit ?? DEFAULT_LOG_LIMIT
        try {
          // `useCommitLog` keys an uncapped read as `repoKeys.log(room, ref)` and a capped one (e.g. the lobby feed) as
          // that same key plus the limit — this tool always passes a limit, so it always uses the suffixed form. That
          // keeps it from ever writing a truncated result under the bare key an uncapped RepoLog reader relies on, while
          // still sharing the WS-invalidation path: `repoKeys.log(room, ref)` is a PREFIX of this key, and
          // `useRepoEvents`'s push-driven `invalidateQueries` matches by prefix, so a push refreshes this cache entry
          // too.
          const entries: CommitLogEntry[] = await l.queryClient.fetchQuery({
            queryKey: [...repoKeys.log(l.room, ref), limit],
            queryFn: () => backend.commitLog(l.room, ref, { limit }),
          })
          return webMcpText(
            JSON.stringify({
              ref,
              commits: entries.map((e) => ({
                hash: e.hash,
                message: e.message,
                author: e.authorPubkey,
                createdAt: e.createdAt,
                kind: e.kind ?? 'commit',
              })),
            }),
          )
        } catch (e) {
          return webMcpError(errMsg(e))
        }
      },
    },
    {
      name: 'mkit_get_commit',
      description: 'Fetch and decode one commit or remix by hash: its message, signer, timestamp, tree, and parents.',
      inputSchema: {
        type: 'object',
        properties: { hash: { type: 'string', description: 'The commit or remix hash (hex).' } },
        required: ['hash'],
      },
      async execute(args: { hash: string }) {
        const l = latest.current
        const backend = l.backend
        if (!backend) return webMcpError('The repository backend is not ready yet. Try again in a moment.')
        if (!args.hash?.trim()) return webMcpError('A commit hash is required.')
        try {
          const info = await describeCommit(l.api, backend, l.queryClient, l.room, args.hash.trim())
          if (!info) return webMcpError(`No commit found for hash ${args.hash}.`)
          return webMcpText(JSON.stringify(info))
        } catch (e) {
          return webMcpError(e instanceof Error ? e.message : String(e))
        }
      },
    },
    {
      name: 'mkit_select_branch',
      description: "Select a branch in the demo's UI — the commit log panel follows it. Does not change any data.",
      inputSchema: {
        type: 'object',
        properties: { ref: { type: 'string', description: 'Branch name to select.' } },
        required: ['ref'],
      },
      async execute(args: { ref: string }) {
        const l = latest.current
        if (!args.ref?.trim()) return webMcpError('A branch name is required.')
        l.onSelectRef(args.ref.trim())
        l.onSelectCommit(null)
        return webMcpText(`Selected branch "${args.ref.trim()}".`)
      },
    },
    {
      name: 'mkit_push_commit',
      description:
        'Build, sign, and push a new commit with the given message onto a branch (default: the currently selected branch, or "main"). Requires an unlocked identity — call mkit_get_identity first if unsure.',
      inputSchema: {
        type: 'object',
        properties: {
          message: { type: 'string', description: 'The commit message to sign.' },
          ref: { type: 'string', description: 'Target branch name (default: the selected branch, else "main").' },
        },
        required: ['message'],
      },
      async execute(args: { message: string; ref?: string }) {
        const before = latest.current
        if (!args.message?.trim()) return webMcpError('A commit message is required.')
        if (!before.seedHex)
          return webMcpError('Unlock an identity in this tab before pushing — the tool needs a signing key.')
        const backend = before.backend
        if (!backend) return webMcpError('The repository backend is not ready yet. Try again in a moment.')
        const targetRef = args.ref?.trim() || before.selectedRef || 'main'
        try {
          // Same key `useRef` reads (Compose/RefsPanel), so a concurrent identical read dedupes against theirs and this
          // fetch's result lands in the same cache entry they're subscribed to.
          const parentHash =
            (await before.queryClient.fetchQuery({
              queryKey: repoKeys.ref(before.room, targetRef),
              queryFn: () => backend.getRef(before.room, targetRef),
            })) ?? ''
          // Re-read the live state after the `await` above (a real network round-trip against the wasm backend) rather
          // than trusting `before`: if the identity got locked while that call was in flight, this bails out instead of
          // signing with a seed the visitor no longer intends to have in memory.
          const l = latest.current
          if (!l.seedHex)
            return webMcpError('Unlock an identity in this tab before pushing — the tool needs a signing key.')
          const tree = l.api.tree_encode('[]')
          const nowSecs = BigInt(Math.floor(Date.now() / 1000))
          const commit = l.api.commit_encode_and_sign(tree.hash_hex, parentHash, args.message, nowSecs, l.seedHex)
          await l.push.mutateAsync({
            api: l.api,
            seedHex: l.seedHex,
            room: l.room,
            ref: targetRef,
            commitBytes: commit.bytes,
            commitHash: commit.hash_hex,
            message: args.message,
            parentHash,
          })
          return webMcpText(`Pushed commit ${commit.hash_hex} to "${targetRef}".`)
        } catch (e) {
          return webMcpError(mapWriteError(e))
        }
      },
    },
    {
      name: 'mkit_remix_commit',
      description:
        'Remix a commit: sign a new remix object recording it as the source (attribution carried in the object) and push it onto a fresh "forks/…" branch. Requires an unlocked identity.',
      inputSchema: {
        type: 'object',
        properties: { hash: { type: 'string', description: 'The commit hash to remix.' } },
        required: ['hash'],
      },
      async execute(args: { hash: string }) {
        const l = latest.current
        const hash = args.hash?.trim()
        if (!hash) return webMcpError('A commit hash is required.')
        if (!l.seedHex) return webMcpError('Unlock an identity in this tab before remixing.')
        const backend = l.backend
        if (!backend) return webMcpError('The repository backend is not ready yet. Try again in a moment.')
        try {
          // The UI only ever calls remix()/branch() with a hash it already fetched and decoded; a WebMCP caller can
          // pass anything, so confirm the object actually exists before recording it as a signed remix source.
          if (!(await backend.getObject(l.room, hash))) return webMcpError(`No commit found for hash ${hash}.`)
          const ref = await l.derive.remix(hash)
          if (!ref) return webMcpError('Could not remix that commit — the repository backend is not ready yet.')
          return webMcpText(`Remixed ${hash} onto new branch "${ref}".`)
        } catch (e) {
          return webMcpError(mapWriteError(e))
        }
      },
    },
    {
      name: 'mkit_branch_commit',
      description:
        'Branch off a commit: create a new "b/…" branch pointing at it, with no attribution recorded (like `git branch`). Requires an unlocked identity.',
      inputSchema: {
        type: 'object',
        properties: { hash: { type: 'string', description: 'The commit hash to branch from.' } },
        required: ['hash'],
      },
      async execute(args: { hash: string }) {
        const l = latest.current
        const hash = args.hash?.trim()
        if (!hash) return webMcpError('A commit hash is required.')
        if (!l.seedHex) return webMcpError('Unlock an identity in this tab before branching.')
        const backend = l.backend
        if (!backend) return webMcpError('The repository backend is not ready yet. Try again in a moment.')
        try {
          // Same existence guard as mkit_remix_commit: the UI's Branch button only ever fires on an already-fetched
          // real commit, but a WebMCP caller can pass anything.
          if (!(await backend.getObject(l.room, hash))) return webMcpError(`No commit found for hash ${hash}.`)
          const ref = await l.derive.branch(hash)
          if (!ref) return webMcpError('Could not branch that commit — the repository backend is not ready yet.')
          return webMcpText(`Branched ${hash} onto new branch "${ref}".`)
        } catch (e) {
          return webMcpError(mapWriteError(e))
        }
      },
    },
  ]
}

export function WebMcpTools({
  room,
  selectedRef,
  onSelectRef,
  onSelectCommit,
}: {
  room: string
  selectedRef: string
  onSelectRef: (ref: string) => void
  onSelectCommit: (hash: string | null) => void
}) {
  const api = useMkit()
  const backend = useRepoBackend()
  const seedHex = useIdentityStore((s) => (s.unlocked ? s.seedHex : null))
  const pubkeyHex = useIdentityStore((s) => (s.unlocked ? s.ed25519PubkeyHex : null))
  const push = usePushCommit()
  const derive = useDerive(api, room, seedHex)
  const queryClient = useQueryClient()

  const latest = useRef<Latest>({
    room,
    api,
    backend,
    seedHex,
    pubkeyHex,
    push,
    derive,
    selectedRef,
    onSelectRef,
    onSelectCommit,
    queryClient,
  })
  useEffect(() => {
    latest.current = {
      room,
      api,
      backend,
      seedHex,
      pubkeyHex,
      push,
      derive,
      selectedRef,
      onSelectRef,
      onSelectCommit,
      queryClient,
    }
  })

  // Built once (stable identity for the component's lifetime): every `execute` reads `latest.current`, so the tool
  // objects themselves never need to change and registration never churns.
  // biome-ignore lint/correctness/useExhaustiveDependencies: intentionally stable — see the module doc comment.
  const tools = useMemo(() => buildTools(latest), [])
  useWebMcpTools(tools)

  return null
}
