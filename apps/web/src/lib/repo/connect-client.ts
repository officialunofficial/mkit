// Real ConnectRPC reads for `mkit.repo.v1.RepoService`, generated types — no
// hand-mirrored request/response shapes.
//
// Every UNAUTHENTICATED read (GetRef, ListRefs, GetObject, ListCommits,
// ListMessages, ListReactions) goes straight over fetch via
// `@connectrpc/connect-web` + the generated `RepoService` client, instead of
// the wasm ConnectRPC client's buffered Fetch transport. Writes stay on the
// wasm client (`rust/crates/mkit-repo-client`) because they need the BLAKE3
// digest + Ed25519 signature computed wasm-side and attached as the
// `X-*` envelope headers (see `envelope.ts` / the repo-worker README's "The
// write envelope" section) — this module has no signing capability and MUST
// NOT be used for writes.
//
// `WatchRefs` stays on the raw `/watch/<room>` WebSocket (`subscribeRoom` in
// `backend.ts`) — Connect server-streaming isn't converted here, see
// apps/repo-worker README §"WatchRefs / streaming".

import { createClient } from '@connectrpc/connect'
import { createConnectTransport } from '@connectrpc/connect-web'
import { RepoService } from 'mkit-repo-proto'
import { bytesToHex, hexToBytes } from '../../components/use-mkit'
import type { ChatMessageEntry, ReactionEntry, RefEntry } from './backend'

export type RepoConnectClient = ReturnType<typeof createClient<typeof RepoService>>

/** Build a typed `RepoService` Connect client bound to `baseUrl` (JSON wire format, matching the server's default). */
export function createRepoConnectClient(baseUrl: string): RepoConnectClient {
  return createClient(RepoService, createConnectTransport({ baseUrl }))
}

/** Hex-encode a proto `bytes` field, or `''` for an empty/absent one (mirrors the wasm client's convention). */
function hex(bytes: Uint8Array | undefined): string {
  return bytes && bytes.length > 0 ? bytesToHex(bytes) : ''
}

// ---------------------------------------------------------------------------
// Read-call wrappers: generated message -> the app's existing hex-string
// shapes (same shapes `RepoBackend` has always exposed; only the wire layer
// producing them changed). Kept here, not inlined into `WasmRepoBackend`, so
// the generated-message field names (and the `bigint` seconds/millis fields)
// are handled in exactly one place.
// ---------------------------------------------------------------------------

/** GetRef — current object id the ref points at (hex), or `null` if the ref doesn't exist. */
export async function getRef(client: RepoConnectClient, room: string, name: string): Promise<string | null> {
  const res = await client.getRef({ room, name })
  return res.exists ? hex(res.objectId) : null
}

/** GetObject — raw object bytes, or `null` if absent. */
export async function getObject(client: RepoConnectClient, room: string, objectId: string): Promise<Uint8Array | null> {
  const res = await client.getObject({ room, objectId: hexToBytes(objectId) })
  return res.found ? res.bytes : null
}

/** ListRefs — refs in the room, optionally filtered by name prefix. */
export async function listRefs(client: RepoConnectClient, room: string, prefix = ''): Promise<RefEntry[]> {
  const res = await client.listRefs({ room, prefix })
  return res.refs.map((r) => ({ name: r.name, objectIdHex: hex(r.objectId) }))
}

/** ListMessages — recent room messages, oldest-first, capped by `limit`. */
export async function listMessages(client: RepoConnectClient, room: string, limit = 50): Promise<ChatMessageEntry[]> {
  const res = await client.listMessages({ room, limit })
  return res.messages.map((m) => ({
    messageIdHex: hex(m.messageId),
    authorPubkeyHex: hex(m.authorPubkey),
    text: m.text,
    createdAt: Number(m.createdAt),
    seq: Number(m.seq),
  }))
}

/** ListReactions — every reaction in the room (client aggregates). */
export async function listReactions(client: RepoConnectClient, room: string): Promise<ReactionEntry[]> {
  const res = await client.listReactions({ room })
  return res.reactions.map((r) => ({ targetIdHex: r.targetId, emoji: r.emoji, authorPubkeyHex: hex(r.authorPubkey) }))
}

/**
 * ListCommits — one page of the server-side first-parent walk, mapped straight to a `CommitLogEntry`-shaped record (no
 * object bytes, no decode — `sources` comes from `parseSourcesJson`, applied by the caller to avoid a cycle here).
 */
export async function listCommits(
  client: RepoConnectClient,
  room: string,
  ref: string,
  startIdHex: string,
  pageSize: number,
): Promise<{
  commits: Array<{
    hash: string
    parent: string
    authorPubkeyHex: string
    message: string
    createdAtUnix: number
    kind: string
    sourcesJson: string
  }>
  nextCursorHex: string
}> {
  const res = await client.listCommits({ room, ref, startId: hexToBytes(startIdHex), pageSize })
  return {
    commits: res.commits.map((c) => ({
      hash: c.hash,
      parent: c.parent,
      authorPubkeyHex: c.authorPubkey,
      message: c.message,
      createdAtUnix: Number(c.createdAtUnix),
      kind: c.kind,
      sourcesJson: c.sourcesJson,
    })),
    nextCursorHex: res.nextCursor,
  }
}
