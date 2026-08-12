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

/**
 * True if `bytes` begins with the gzip magic number (`0x1f 0x8b`) — mirrors `mkit-repo-client`'s `is_gzip`
 * (`rust/crates/mkit-repo-client/src/transport.rs`). Exported for tests.
 */
export function isGzip(bytes: Uint8Array): boolean {
  return bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b
}

/**
 * A Cloudflare Workers quirk (already documented and worked around once, in `mkit-repo-client`'s wasm transport — see
 * that crate's `transport.rs` doc comment): repo-worker's `connectrpc` gzip-compresses any response over 1 KiB and
 * correctly sets `Content-Encoding: gzip` when it does (`connectrpc::service` — verified server-side), but somewhere
 * between there and this client the header gets stripped while the body stays gzip-compressed — so a spec-compliant
 * client (this one) never decompresses it and fails trying to parse gzip bytes as JSON.
 *
 * Unlike the Rust `connectrpc` crate (which has ITS OWN protocol-level gzip decompressor and only needed the header
 * re-asserted to trigger it), `@connectrpc/connect-web`'s unary JSON transport has no such fallback — it relies
 * entirely on the browser's transport-level auto-decompression, which only fires for a `Response` that came directly
 * off the wire (not one reconstructed in JS). So this wrapper does the decompression itself, via the standard
 * `DecompressionStream` API (supported in every modern browser and in Cloudflare Workers/workerd) — not just re-declare
 * the header.
 *
 * Sniffs the gzip magic number rather than trusting any response header, exactly like the Rust workaround: correct
 * regardless of whether the (already-broken) `Content-Encoding` header is present, absent, or lying.
 */
export async function gzipAwareFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const res = await fetch(input, init)
  const bytes = new Uint8Array(await res.arrayBuffer())
  if (!isGzip(bytes)) {
    // Not gzip — reconstruct a fresh Response over the SAME bytes (the
    // original body was already consumed by `arrayBuffer()` above) rather
    // than assuming the caller can re-read a consumed body.
    return new Response(bytes, { status: res.status, statusText: res.statusText, headers: res.headers })
  }
  const decompressedStream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))
  const decompressed = await new Response(decompressedStream).arrayBuffer()
  const headers = new Headers(res.headers)
  // The body is no longer encoded — drop the (already-unreliable) header
  // rather than leave a stale claim that could confuse a LATER consumer.
  headers.delete('content-encoding')
  return new Response(decompressed, { status: res.status, statusText: res.statusText, headers })
}

/** Build a typed `RepoService` Connect client bound to `baseUrl` (JSON wire format, matching the server's default). */
export function createRepoConnectClient(baseUrl: string): RepoConnectClient {
  return createClient(RepoService, createConnectTransport({ baseUrl, fetch: gzipAwareFetch }))
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

/**
 * ListRefs — one page of refs in the room, optionally filtered by name prefix. `startAfter` is the keyset cursor (empty
 * = from the start); `pageSize` bounds the page (0 = server's legacy unpaginated ALL). Mirrors `listCommits`'s
 * request/response mapping below.
 */
export async function listRefs(
  client: RepoConnectClient,
  room: string,
  prefix = '',
  startAfter = '',
  pageSize = 0,
): Promise<{ refs: RefEntry[]; nextCursorName: string; total: number }> {
  const res = await client.listRefs({ room, prefix, startAfter, pageSize })
  return {
    refs: res.refs.map((r) => ({ name: r.name, objectIdHex: hex(r.objectId) })),
    nextCursorName: res.nextCursor,
    total: res.total,
  }
}

/** ListMessages — recent room messages, oldest-first, capped by `limit`. */
export async function listMessages(client: RepoConnectClient, room: string, limit = 50): Promise<ChatMessageEntry[]> {
  const res = await client.listMessages({ room, limit })
  return res.messages.map((m) => ({
    messageIdHex: hex(m.messageId),
    authorPubkeyHex: hex(m.authorPubkey),
    text: m.text,
    // `createdAtUnixMs` is the unambiguous field (mkit#795); `createdAt` is
    // the deprecated same-unit sibling, kept as a fallback only for a stale
    // cached worker build that predates the new field. `||`, not `??`: a
    // proto3 scalar absent on the wire decodes as 0n (not null/undefined),
    // so an old build's response has `createdAtUnixMs` at its zero default,
    // not unset — only `||` treats that as "fall back to createdAt".
    createdAt: Number(m.createdAtUnixMs || m.createdAt),
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
