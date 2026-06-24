// Repo client — transport-agnostic interface over the `mkit.repo.v1.RepoService`
// ConnectRPC service, backed by an in-memory mock (design note §3–§5).
//
// The wire is ConnectRPC (proto `mkit.repo.v1.RepoService`), not raw REST. This
// module defines the service interface its procedures map to 1:1, plus an
// in-memory mock so the whole demo runs locally with no server. The concrete
// Connect client (connect-es over fetch, or a Rust-WASM client) drops in behind
// the same `RepoBackend` interface once chosen — no UI or hook changes needed.
//
// Service contract (unary unless noted):
//   PutObject(room, object_id, bytes)            getObject(room, object_id)
//   GetRef(room, name)                           ListRefs(room, prefix)
//   UpdateRef(room, name, new_id, expectation,   WatchRefs(room, prefix)  [server-streaming]
//             expected_id?)
//
// CAS lives INSIDE the message via `RefExpectation` (ANY | MISSING | MATCH),
// mirroring mkit-rpc/proto/ssh.proto — NOT in transport headers.
//
// Signed envelope (Connect-flavored, applied by the real client as call headers):
//   headers: X-Public-Key, X-Signature, X-Created-At, Idempotency-Key
//   canonical = ["mkit-write:v1", procedure, blake3(rawRequestBody)-hex,
//                createdAt, idempotencyKey].join("\n")
//   → BLAKE3 → Ed25519-sign with the derived seed.
// `procedure` is the Connect path, e.g. "/mkit.repo.v1.RepoService/UpdateRef".

import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useSyncExternalStore } from 'react'
import { bytesToHex } from '../components/use-mkit'
import type { MkitApi } from './mkit'

const TEXT_ENCODER = new TextEncoder()

// ---------------------------------------------------------------------------
// Service shapes (mirror mkit.repo.v1.RepoService)
// ---------------------------------------------------------------------------

/** CAS precondition carried inside UpdateRefRequest (proto enum RefExpectation). */
export type RefExpectation = 'ANY' | 'MISSING' | 'MATCH'

export type RefEntry = { name: string; objectIdHex: string }
export type RefUpdate = { name: string; objectIdHex: string; authorPubkeyHex: string }

/** One upstream commit a remix/fork derives from. */
export type RemixSourceEntry = { upstreamIdHex: string; commitHashHex: string }

export type CommitLogEntry = {
  hash: string
  message: string
  authorPubkey: string
  ref: string
  createdAt: string
  /** `'commit'` (default) or `'remix'` — drives the fork badge in the log. */
  kind?: 'commit' | 'remix'
  /** For a remix: the upstream commit(s) it forks from. */
  sources?: RemixSourceEntry[]
}

/**
 * Fork ref name for a remix derived from `upstreamCommitHash` by the forker
 * whose Ed25519 pubkey is `forkerPubkeyHex`. Lands under the `forks/` prefix
 * so the Refs panel can mark it as a fork (distinct from `main` / feature
 * branches).
 *
 * Scheme: `forks/<upstreamShort>-<forkerShort>` where `upstreamShort` is the
 * upstream commit's first 12 hex chars and `forkerShort` is the forker's
 * pubkey first 12 hex chars. Keying on BOTH makes the ref unique per (commit,
 * forker): two users forking the SAME commit get DISTINCT refs (no collision),
 * and a 48-bit prefix collision across two upstream commits no longer aliases
 * onto one ref. The same forker re-forking the same commit reuses ITS ref, so
 * repeated forks chain (CAS `MATCH` advances) instead of orphaning.
 *
 * `forkerPubkeyHex` is optional only so legacy seeded demo data (which keys on
 * the upstream alone) still resolves; real forks always pass it.
 */
export const FORKS_PREFIX = 'forks/'
export function forkRefName(upstreamCommitHash: string, forkerPubkeyHex?: string): string {
  const upstreamShort = upstreamCommitHash.slice(0, 12)
  if (!forkerPubkeyHex) return `${FORKS_PREFIX}${upstreamShort}`
  return `${FORKS_PREFIX}${upstreamShort}-${forkerPubkeyHex.slice(0, 12)}`
}
export function isForkRef(name: string): boolean {
  return name.startsWith(FORKS_PREFIX)
}

/** Fully-qualified Connect procedure paths — also the `procedure` field of the envelope. */
export const procedures = {
  PutObject: '/mkit.repo.v1.RepoService/PutObject',
  GetObject: '/mkit.repo.v1.RepoService/GetObject',
  GetRef: '/mkit.repo.v1.RepoService/GetRef',
  UpdateRef: '/mkit.repo.v1.RepoService/UpdateRef',
  ListRefs: '/mkit.repo.v1.RepoService/ListRefs',
  WatchRefs: '/mkit.repo.v1.RepoService/WatchRefs',
} as const

// ---------------------------------------------------------------------------
// Signed envelope (Connect-flavored)
// ---------------------------------------------------------------------------

export type EnvelopeParts = {
  /** Connect procedure path, e.g. `/mkit.repo.v1.RepoService/UpdateRef`. */
  procedure: string
  /** BLAKE3 hex of the raw (serialized) request body. */
  bodyDigest: string
  createdAt: string
  idempotencyKey: string
}

/** Canonical string the server reconstructs + verifies (Connect-flavored envelope). */
export function canonicalString(p: EnvelopeParts): string {
  return ['mkit-write:v1', p.procedure, p.bodyDigest, p.createdAt, p.idempotencyKey].join('\n')
}

export type SignedEnvelope = {
  publicKeyHex: string
  signatureHex: string
  /** BLAKE3 hex of the RAW request body — the `X-Digest` header the server recomputes. */
  bodyDigest: string
  /** BLAKE3 hex of the canonical string (the bytes that are Ed25519-signed). */
  digestHex: string
  /** Epoch-millis string (`String(Date.now())`) — the `X-Created-At` header. */
  createdAt: string
  idempotencyKey: string
  canonical: string
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.length % 2 === 0 ? hex : `0${hex}`
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

/** BLAKE3 hex of a UTF-8 string (via WASM). */
export function blake3OfString(api: MkitApi, s: string): string {
  return api.blake3_hex(TEXT_ENCODER.encode(s))
}

/**
 * Build + sign the request envelope. `bodyDigest` is the BLAKE3 of the raw
 * (serialized) request body. The signature is raw Ed25519 over the BLAKE3 digest
 * of the canonical string — what the server's `ed25519_verify` checks. The real
 * Connect client attaches `publicKeyHex` / `signatureHex` / `createdAt` /
 * `idempotencyKey` as the X-* call headers.
 */
export function buildSignedEnvelope(
  api: MkitApi,
  seedHex: string,
  parts: Pick<EnvelopeParts, 'procedure' | 'bodyDigest'> &
    Partial<Pick<EnvelopeParts, 'createdAt' | 'idempotencyKey'>>,
): SignedEnvelope {
  // `createdAt` MUST be epoch-ms (`String(Date.now())`) to match the server's
  // `String(epoch ms)` canonical field — see apps/repo-worker/src/lib/envelope.ts.
  const createdAt = parts.createdAt ?? String(Date.now())
  const idempotencyKey = parts.idempotencyKey ?? crypto.randomUUID()
  const canonical = canonicalString({ ...parts, createdAt, idempotencyKey })
  const digestHex = blake3OfString(api, canonical)
  const seed = hexToBytes(seedHex)
  const sig = api.ed25519_sign(hexToBytes(digestHex), seed)
  const pubkey = api.ed25519_pubkey_from_seed(seed)
  return {
    publicKeyHex: bytesToHex(pubkey),
    signatureHex: bytesToHex(sig),
    bodyDigest: parts.bodyDigest,
    digestHex,
    createdAt,
    idempotencyKey,
    canonical,
  }
}

export function envelopeHeaders(env: SignedEnvelope): Record<string, string> {
  return {
    'X-Public-Key': env.publicKeyHex,
    'X-Signature': env.signatureHex,
    // Client-claimed BLAKE3 of the raw request body; server rejects on mismatch.
    'X-Digest': env.bodyDigest,
    'X-Created-At': env.createdAt,
    'Idempotency-Key': env.idempotencyKey,
  }
}

// ---------------------------------------------------------------------------
// Transport-agnostic backend interface (maps 1:1 to the Connect service)
// ---------------------------------------------------------------------------

export interface RepoBackend {
  /** PutObject — content-addressed, idempotent (re-put of the same id is a no-op). */
  putObject(room: string, objectIdHex: string, bytes: Uint8Array): Promise<void>
  /** GetObject — raw object bytes, or null if absent. */
  getObject(room: string, objectIdHex: string): Promise<Uint8Array | null>
  /** GetRef — current object id the ref points at, or null. */
  getRef(room: string, name: string): Promise<string | null>
  /**
   * UpdateRef — CAS-advance a ref. `expectation` is the precondition:
   *   MISSING → create only (ref must not exist),
   *   MATCH   → advance only if current == `expectedIdHex`,
   *   ANY     → unconditional set.
   * Throws `CasConflictError` when the precondition fails.
   */
  updateRef(
    room: string,
    name: string,
    newIdHex: string,
    expectation: RefExpectation,
    expectedIdHex?: string,
  ): Promise<void>
  /** ListRefs — refs in the room, optionally filtered by name prefix. */
  listRefs(room: string, prefix?: string): Promise<RefEntry[]>
  /** WatchRefs (server-streaming) — fires on each ref advance. Returns an unsubscribe fn. */
  watchRefs(room: string, prefix: string, onUpdate: (u: RefUpdate) => void): () => void
  /**
   * Commit log for the demo UI — the chain reachable from `ref` (default
   * `main`), newest-first. The mock derives it; a server walk sources it.
   */
  commitLog(room: string, ref?: string): Promise<CommitLogEntry[]>
}

/**
 * Decode one fetched object into a log entry, routing by `object_kind` so
 * the SAME walk handles both commits and remixes (a fork ref's head is a
 * remix). Returns the entry plus its first parent to continue the walk, or
 * `null` for any other object kind (or a decode failure) so the caller
 * stops the walk rather than throwing. Shared by the wasm ref-walk and the
 * detail view's client-side decode.
 */
export function decodeLogObject(
  api: MkitApi,
  bytes: Uint8Array,
  hash: string,
  ref: string,
): { entry: CommitLogEntry; firstParent: string | undefined } | null {
  let kind: string
  try {
    kind = api.object_kind(bytes)
  } catch {
    return null
  }
  if (kind === 'commit') {
    let info: ReturnType<MkitApi['commit_decode']>
    try {
      info = api.commit_decode(bytes)
    } catch {
      return null
    }
    return {
      entry: {
        hash,
        message: info.message,
        authorPubkey: info.signer_hex,
        ref,
        kind: 'commit',
        // `timestamp` is unix seconds; keep a sortable ISO string.
        createdAt: new Date(Number(info.timestamp) * 1000).toISOString(),
      },
      firstParent: info.parent_count > 0 ? info.parent(0) : undefined,
    }
  }
  if (kind === 'remix') {
    let info: ReturnType<MkitApi['remix_decode']>
    try {
      info = api.remix_decode(bytes)
    } catch {
      return null
    }
    const sources: RemixSourceEntry[] = []
    for (let i = 0; i < info.source_count; i++) {
      const s = info.source(i)
      if (s) sources.push({ upstreamIdHex: s.upstream_id_hex, commitHashHex: s.commit_hash_hex })
    }
    return {
      entry: {
        hash,
        message: info.message,
        authorPubkey: info.signer_hex,
        ref,
        kind: 'remix',
        sources,
        createdAt: new Date(Number(info.timestamp) * 1000).toISOString(),
      },
      firstParent: info.parent_count > 0 ? info.parent(0) : undefined,
    }
  }
  return null
}

export class CasConflictError extends Error {
  constructor(public current: string | null) {
    super('ref CAS failed: the ref moved under you — refetch, re-parent, re-sign, retry')
    this.name = 'CasConflictError'
  }
}

/** Thrown when a signed write is attempted while the identity is locked (no
 * seed in memory). UI can catch this to surface an "unlock to push" prompt. */
export class IdentityLockedError extends Error {
  constructor() {
    super('cannot sign write: identity is locked (no seed in memory)')
    this.name = 'IdentityLockedError'
  }
}

// ---------------------------------------------------------------------------
// In-memory mock backend (no server)
// ---------------------------------------------------------------------------

/**
 * In-memory backend implementing the Connect service shape. Mirrors server
 * semantics: content-addressed idempotent object writes, in-message CAS via
 * `RefExpectation`, and a synchronous WatchRefs fan-out that drives Query
 * invalidation. Seeded with a couple of "other players'" commits so the live
 * multiplayer log isn't empty.
 */
export class MockRepoBackend implements RepoBackend {
  private objects = new Map<string, Uint8Array>()
  private refs = new Map<string, string>()
  private log = new Map<string, CommitLogEntry[]>()
  private watchers = new Map<string, Set<(u: RefUpdate) => void>>()

  constructor(private api: MkitApi) {}

  private key(room: string, name: string): string {
    return `${room}::${name}`
  }

  async putObject(room: string, objectIdHex: string, bytes: Uint8Array): Promise<void> {
    // Content-addressed + idempotent: re-PUT of the same object id is a no-op.
    if (!this.objects.has(this.key(room, objectIdHex))) this.objects.set(this.key(room, objectIdHex), bytes)
  }

  async getObject(room: string, objectIdHex: string): Promise<Uint8Array | null> {
    return this.objects.get(this.key(room, objectIdHex)) ?? null
  }

  async getRef(room: string, name: string): Promise<string | null> {
    return this.refs.get(this.key(room, name)) ?? null
  }

  async updateRef(
    room: string,
    name: string,
    newIdHex: string,
    expectation: RefExpectation,
    expectedIdHex?: string,
  ): Promise<void> {
    const k = this.key(room, name)
    const current = this.refs.get(k) ?? null
    // In-message CAS gate — the serial-queue semantics of the per-repo RefStore (§4).
    if (expectation === 'MISSING' && current !== null) throw new CasConflictError(current)
    if (expectation === 'MATCH' && current !== (expectedIdHex ?? null)) throw new CasConflictError(current)
    this.refs.set(k, newIdHex)
    this.broadcast(room, name, { name, objectIdHex: newIdHex, authorPubkeyHex: '' })
  }

  async listRefs(room: string, prefix?: string): Promise<RefEntry[]> {
    const out: RefEntry[] = []
    for (const [k, objectIdHex] of this.refs) {
      if (!k.startsWith(`${room}::`)) continue
      const name = k.slice(room.length + 2)
      if (prefix && !name.startsWith(prefix)) continue
      out.push({ name, objectIdHex })
    }
    return out
  }

  watchRefs(room: string, prefix: string, onUpdate: (u: RefUpdate) => void): () => void {
    const key = `${room}::${prefix}`
    let set = this.watchers.get(key)
    if (!set) {
      set = new Set()
      this.watchers.set(key, set)
    }
    set.add(onUpdate)
    return () => set?.delete(onUpdate)
  }

  async commitLog(room: string, ref = 'main'): Promise<CommitLogEntry[]> {
    return (this.log.get(room) ?? []).filter((e) => e.ref === ref).toReversed()
  }

  private broadcast(room: string, name: string, u: RefUpdate): void {
    for (const [key, set] of this.watchers) {
      if (!key.startsWith(`${room}::`)) continue
      const prefix = key.slice(room.length + 2)
      if (prefix && !name.startsWith(prefix)) continue
      for (const l of set) l(u)
    }
  }

  /** Append a commit to the mock log (used by the push mutation + seeding). */
  recordCommit(room: string, entry: CommitLogEntry): void {
    const list = this.log.get(room) ?? []
    list.push(entry)
    this.log.set(room, list)
  }

  /** Inject a foreign player's commit to make the multiplayer log lively. */
  seedForeignCommit(room: string, entry: CommitLogEntry): void {
    this.recordCommit(room, entry)
    this.refs.set(this.key(room, entry.ref), entry.hash)
    this.broadcast(room, entry.ref, {
      name: entry.ref,
      objectIdHex: entry.hash,
      authorPubkeyHex: entry.authorPubkey,
    })
  }
}

// ---------------------------------------------------------------------------
// WASM-backed backend (real ConnectRPC client over Fetch)
// ---------------------------------------------------------------------------

/**
 * The sign-callback the wasm client invokes per write. It receives the BLAKE3
 * hex of the RAW (serialized protobuf) request body — the EXACT bytes the
 * transport sends and the server re-hashes — and returns the signed-write
 * envelope. Computing the digest wasm-side (not in JS) is what guarantees
 * `X-Digest` matches `BLAKE3(actualBody)` on the server; JS could not reproduce
 * the protobuf bytes. See rust/crates/mkit-repo-client/README.md.
 *
 * The returned object's keys match what `SigningFetchTransport` reads:
 * `publicKeyHex`, `signatureHex`, `createdAt`, `idempotencyKey` (+ optional
 * `digestHex` echo, which must equal the supplied digest).
 */
export type RepoSignFn = (
  bodyDigestHex: string,
) => { publicKeyHex: string; signatureHex: string; createdAt: string; idempotencyKey: string; digestHex: string }

/** Build a per-procedure sign-callback bound to the active identity seed. */
export function makeSignFn(api: MkitApi, seedHex: string, procedure: string): RepoSignFn {
  return (bodyDigestHex: string) => {
    const env = buildSignedEnvelope(api, seedHex, { procedure, bodyDigest: bodyDigestHex })
    return {
      publicKeyHex: env.publicKeyHex,
      signatureHex: env.signatureHex,
      createdAt: env.createdAt,
      idempotencyKey: env.idempotencyKey,
      digestHex: env.bodyDigest,
    }
  }
}

/** The subset of the wasm client this backend drives (matches `repo-client.ts`). */
export interface RepoWasmClient {
  get_ref(baseUrl: string, room: string, name: string): Promise<string | undefined>
  get_object(baseUrl: string, room: string, objectIdHex: string): Promise<Uint8Array | undefined>
  list_refs(baseUrl: string, room: string, prefix: string): Promise<Array<{ name: string; objectIdHex: string }>>
  put_object(
    baseUrl: string,
    room: string,
    objectIdHex: string,
    bytes: Uint8Array,
    sign: RepoSignFn,
  ): Promise<{ stored: boolean; duplicate: boolean }>
  update_ref(
    baseUrl: string,
    room: string,
    name: string,
    newIdHex: string,
    expectation: RefExpectation,
    expectedIdHex: string | null | undefined,
    sign: RepoSignFn,
  ): Promise<{ committed: boolean; conflict: boolean; currentIdHex: string | null }>
}

/**
 * Real backend: drives `mkit.repo.v1.RepoService` over the wasm ConnectRPC
 * client (Fetch transport). Reads hit the server directly; writes flow through
 * the sign-callback (envelope built + signed here in JS, attached wasm-side).
 *
 * `WatchRefs` server-streaming is not surfaceable over the buffered Fetch
 * transport (see README §Streaming), so live updates ride the worker's raw
 * WebSocket route `GET /watch/<room>` — `watchRefs` opens it and fans each
 * broadcast frame out to `onUpdate` (which drives Query invalidation via
 * `useRepoEvents`). `commitLog` is accumulated in-memory on push (the service
 * has no log RPC).
 */
export class WasmRepoBackend implements RepoBackend {
  private log = new Map<string, CommitLogEntry[]>()
  /**
   * Memoised result of the last ref walk, keyed by `room::ref`. `head` is
   * the ref value the cached `entries` were walked from; when the ref
   * advances (our push, or a peer's push surfaced via WatchRefs → query
   * invalidation → re-`commitLog`), `head` no longer matches and we re-walk.
   * Keying by ref lets the browser switch between branches without one
   * branch's cache shadowing another's. The walk is INCREMENTAL: a re-walk
   * after an advance only fetches objects newer than the cached head, then
   * splices the cached tail (see {@link WasmRepoBackend.commitLog}).
   */
  private walkCache = new Map<string, { head: string; entries: CommitLogEntry[] }>()
  /**
   * Hash-keyed object cache, keyed by `room::objectIdHex`. mkit objects are
   * CONTENT-ADDRESSED — a given hash maps to fixed bytes forever — so a
   * cached entry can never go stale and is ALWAYS safe to serve without a
   * network round-trip. Populated on every successful {@link getObject} and
   * consulted first; subsumes the per-walk re-download of immutable history,
   * so a post-commit re-walk network-fetches only the NEW object(s).
   */
  private objectCache = new Map<string, Uint8Array>()

  /** Safety cap on how far back the ref walk follows first-parents. */
  private static readonly WALK_CAP = 100

  constructor(
    private wasm: RepoWasmClient,
    private api: MkitApi,
    private seedHex: () => string | null,
    private baseUrl: string,
  ) {}

  private requireSeed(): string {
    const s = this.seedHex()
    if (!s) throw new IdentityLockedError()
    return s
  }

  async putObject(room: string, objectIdHex: string, bytes: Uint8Array): Promise<void> {
    const sign = makeSignFn(this.api, this.requireSeed(), procedures.PutObject)
    await this.wasm.put_object(this.baseUrl, room, objectIdHex, bytes, sign)
  }

  async getObject(room: string, objectIdHex: string): Promise<Uint8Array | null> {
    return this.cachedObject(room, objectIdHex)
  }

  /**
   * Fetch an object, serving from {@link WasmRepoBackend.objectCache} when
   * present. Safe because objects are content-addressed (immutable): the bytes
   * behind a hash never change, so a cache hit is always correct. Misses hit
   * the wasm client once and populate the cache for every later read (the
   * post-commit re-walk, the detail view, a peer's re-walk).
   */
  private async cachedObject(room: string, objectIdHex: string): Promise<Uint8Array | null> {
    const ck = `${room}::${objectIdHex}`
    const hit = this.objectCache.get(ck)
    if (hit) return hit
    const bytes = (await this.wasm.get_object(this.baseUrl, room, objectIdHex)) ?? null
    if (bytes) this.objectCache.set(ck, bytes)
    return bytes
  }

  async getRef(room: string, name: string): Promise<string | null> {
    return (await this.wasm.get_ref(this.baseUrl, room, name)) ?? null
  }

  async updateRef(
    room: string,
    name: string,
    newIdHex: string,
    expectation: RefExpectation,
    expectedIdHex?: string,
  ): Promise<void> {
    const sign = makeSignFn(this.api, this.requireSeed(), procedures.UpdateRef)
    const res = await this.wasm.update_ref(this.baseUrl, room, name, newIdHex, expectation, expectedIdHex, sign)
    if (res.conflict) throw new CasConflictError(res.currentIdHex)
  }

  async listRefs(room: string, prefix?: string): Promise<RefEntry[]> {
    return await this.wasm.list_refs(this.baseUrl, room, prefix ?? '')
  }

  /**
   * Live ref updates over the raw WebSocket the worker exposes at
   * `GET /watch/<room>` (WatchRefs server-streaming isn't surfaceable over the
   * buffered Fetch transport — see apps/repo-worker README §"WatchRefs /
   * streaming"). The RefStore DO broadcasts one JSON frame per successful
   * UpdateRef: `{ name, object_id, author_pubkey }` — all hex (snake_case).
   * `prefix` filters client-side. Returns an unsubscribe that closes the socket.
   */
  watchRefs(room: string, prefix: string, onUpdate: (u: RefUpdate) => void): () => void {
    const wsUrl = `${this.baseUrl.replace(/^http/, 'ws')}/watch/${encodeURIComponent(room)}`
    let closed = false
    let ws: WebSocket | null = null
    let attempt = 0
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null
    const MAX_ATTEMPTS = 6 // ~bounded backoff; give up after this many failures

    const handleMessage = (ev: MessageEvent) => {
      if (typeof ev.data !== 'string') return
      let frame: {
        name?: string
        object_id?: string
        objectIdHex?: string
        author_pubkey?: string
        authorPubkeyHex?: string
      }
      try {
        frame = JSON.parse(ev.data)
      } catch {
        return // ignore malformed frames
      }
      const name = frame.name
      const objectIdHex = frame.objectIdHex ?? frame.object_id
      if (!name || !objectIdHex) return
      if (prefix && !name.startsWith(prefix)) return // client-side prefix filter
      const authorPubkeyHex = frame.authorPubkeyHex ?? frame.author_pubkey ?? ''
      // Surface peers' pushes in the live log so a signed-out viewer sees others
      // contributing. The ref event carries the commit id + author but not the
      // message, so peers show a placeholder; our own commits keep their real
      // message (recorded on push) and are deduped by hash here.
      this.recordCommit(room, {
        hash: objectIdHex,
        message: 'pushed by a peer',
        authorPubkey: authorPubkeyHex,
        ref: name,
        createdAt: new Date().toISOString(),
      })
      onUpdate({ name, objectIdHex, authorPubkeyHex })
    }

    // Schedule a bounded, exponentially-backed-off reconnect. The socket can
    // drop (DO hibernation, transient network) without the user closing it.
    const scheduleReconnect = () => {
      if (closed || attempt >= MAX_ATTEMPTS) return
      const delay = Math.min(1000 * 2 ** attempt, 30_000) // 1s,2s,…,capped 30s
      attempt += 1
      reconnectTimer = setTimeout(connect, delay)
    }

    function connect() {
      if (closed) return
      try {
        ws = new WebSocket(wsUrl)
      } catch {
        // No WebSocket available (e.g. SSR) — degrade to a no-op subscription.
        ws = null
        return
      }
      ws.addEventListener('open', () => {
        attempt = 0 // reset backoff once a connection is established
      })
      ws.addEventListener('message', handleMessage)
      // On error/close, retry with backoff (unless the caller unsubscribed).
      ws.addEventListener('error', () => {
        // `error` is followed by `close`; let `close` drive the reconnect.
      })
      ws.addEventListener('close', () => {
        if (!closed) scheduleReconnect()
      })
    }

    connect()

    return () => {
      if (closed) return
      closed = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      // CLOSING (2) / CLOSED (3) need no action; otherwise close the socket.
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        ws.close()
      }
    }
  }

  /**
   * Authoritative shared history: the chain reachable from the selected
   * `ref` (default `main`), read from the worker, so every viewer renders
   * the SAME log (history + live), not just this session's pushes. Walks
   * from the room's `ref` by first-parent, decoding each commit object
   * (`commit_decode`) for its real message / signer / parents — so a
   * peer's push (surfaced via WatchRefs → query invalidation → re-walk)
   * shows its real message, not a placeholder.
   *
   * Newest-first (head → parent → …), matching the order `LiveLog` renders.
   * Memoised by `room::ref` head hash so repeated calls (and other branches)
   * don't re-walk; a new head (push or WS event) invalidates the cache and
   * re-walks. Stops at no parent, a missing object, or
   * {@link WasmRepoBackend.WALK_CAP}.
   */
  async commitLog(room: string, ref = 'main'): Promise<CommitLogEntry[]> {
    const head = await this.wasm.get_ref(this.baseUrl, room, ref)
    if (!head) return []

    const cacheKey = `${room}::${ref}`
    const cached = this.walkCache.get(cacheKey)
    if (cached && cached.head === head) return cached.entries

    // INCREMENTAL re-walk: when we already have a cached chain for this ref,
    // walk from the NEW head by first-parent only until we reach a hash that
    // is already in the cached chain, then splice that cached tail on. The
    // common case (our push, a peer's single commit) fetches just the new
    // object(s) instead of re-walking up to WALK_CAP. A cold walk (no cache)
    // is bounded by WALK_CAP as before.
    const tailByHash = new Map<string, number>() // hash → index in cached.entries
    if (cached) cached.entries.forEach((e, i) => tailByHash.set(e.hash, i))

    const fresh: CommitLogEntry[] = []
    const seen = new Set<string>() // guard against a cyclic/self-parent chain
    let hash: string | undefined = head
    let spliced: CommitLogEntry[] | null = null
    while (hash && fresh.length < WasmRepoBackend.WALK_CAP && !seen.has(hash)) {
      const tailIdx = tailByHash.get(hash)
      if (tailIdx !== undefined) {
        // Reached the cached chain — splice its tail (from this hash down)
        // instead of re-fetching/decoding the immutable history again.
        // biome-ignore lint/style/noNonNullAssertion: tailIdx came from cached.entries
        spliced = cached!.entries.slice(tailIdx)
        break
      }
      seen.add(hash)
      const bytes = await this.cachedObject(room, hash)
      if (!bytes) break // object missing — stop the walk
      // Route by the object's prologue type: a fork ref's head is a remix,
      // not a commit. `decodeLogObject` handles both kinds (and stops the
      // walk on anything else) so a fork chain renders alongside commits.
      const decoded = decodeLogObject(this.api, bytes, hash, ref)
      if (!decoded) break // not a commit/remix — stop rather than throw
      fresh.push(decoded.entry)
      hash = decoded.firstParent
    }

    const entries = spliced ? [...fresh, ...spliced] : fresh
    this.walkCache.set(cacheKey, { head, entries })
    return entries
  }

  /**
   * Append a commit to the in-memory log (push mutation + WatchRefs peers),
   * deduped by hash. The ref walk in {@link WasmRepoBackend.commitLog} is the
   * authoritative source; this is kept for any callers that still read
   * `this.log`, and as a record of locally-originated pushes.
   */
  recordCommit(room: string, entry: CommitLogEntry): void {
    const list = this.log.get(room) ?? []
    if (list.some((e) => e.hash === entry.hash)) return // e.g. our own push echoed back over WatchRefs
    list.push(entry)
    this.log.set(room, list)
  }
}

// ---------------------------------------------------------------------------
// Backend selection (mock toggle) + query keys
// ---------------------------------------------------------------------------

// The backend holder is a tiny REACTIVE external store (useSyncExternalStore
// source) — not a bare global. The bug it fixes: the hooks read this via
// `getRepoBackend()` with no `enabled` gate, so in worker mode the synchronous
// mock bootstrap let refs/log queries RESOLVE to empty `[]` before the async
// WasmRepoBackend was installed, flipping `isPending → false` and rendering the
// "No refs/commits" empty state on a populated room. Making the holder reactive
// lets `useRepoBackendReady()` gate every query so they stay PENDING (skeleton)
// until a backend is actually installed.
let activeBackend: RepoBackend | null = null
const backendListeners = new Set<() => void>()

/** Install the backend used by the hooks, then notify subscribers so any
 * `useRepoBackendReady()` consumers re-render and gated queries enable. */
export function setRepoBackend(backend: RepoBackend): void {
  activeBackend = backend
  for (const l of backendListeners) l()
}

/** Subscribe to backend changes (useSyncExternalStore subscribe fn). Returns an unsubscribe. */
export function subscribeBackend(cb: () => void): () => void {
  backendListeners.add(cb)
  return () => backendListeners.delete(cb)
}

/** Current backend, or null if none is installed yet (useSyncExternalStore snapshot). */
export function getBackendSnapshot(): RepoBackend | null {
  return activeBackend
}

export function getRepoBackend(): RepoBackend {
  if (!activeBackend) throw new Error('repo backend not configured — call setRepoBackend()')
  return activeBackend
}

/**
 * Reactive readiness flag: `true` once a backend is installed. Drives the
 * `enabled` gate on every repo query (dependent-query pattern) so a query stays
 * `status:'pending'` (→ skeleton) until there is a backend to answer it, instead
 * of resolving empty against a not-yet-replaced mock. The 3rd `useSyncExternalStore`
 * arg is the SERVER snapshot (`false`) for SSR safety — the server never has a
 * backend, so readiness is false there and the queries don't fire during SSR.
 */
export function useRepoBackendReady(): boolean {
  return useSyncExternalStore(
    subscribeBackend,
    () => getBackendSnapshot() != null,
    () => false,
  )
}

export const repoKeys = {
  ref: (room: string, name: string) => ['repo', room, 'ref', name] as const,
  refs: (room: string, prefix: string) => ['repo', room, 'refs', prefix] as const,
  object: (room: string, hash: string) => ['repo', room, 'object', hash] as const,
  log: (room: string, ref: string) => ['repo', room, 'log', ref] as const,
}

// ---------------------------------------------------------------------------
// Query hooks
// ---------------------------------------------------------------------------

export function useRef(room: string, name: string) {
  const ready = useRepoBackendReady()
  return useQuery({
    queryKey: repoKeys.ref(room, name),
    queryFn: () => getRepoBackend().getRef(room, name),
    // Dependent query: don't run (stay pending) until a backend is installed,
    // so `getRepoBackend()` is never called while null.
    enabled: ready,
  })
}

export function useObject(room: string, hash: string | null) {
  const ready = useRepoBackendReady()
  return useQuery({
    queryKey: repoKeys.object(room, hash ?? ''),
    queryFn: () => (hash ? getRepoBackend().getObject(room, hash) : Promise.resolve(null)),
    // Preserve the existing hash guard AND gate on backend readiness.
    enabled: ready && !!hash,
    // Objects are CONTENT-ADDRESSED (immutable): a hash → fixed bytes forever,
    // so a cached object is never stale and never needs eviction. Keep this
    // query permanent (don't touch the global default, which keeps refs/log
    // fresh / WS-invalidated).
    staleTime: Number.POSITIVE_INFINITY,
    gcTime: Number.POSITIVE_INFINITY,
  })
}

export function useCommitLog(room: string, ref = 'main') {
  const ready = useRepoBackendReady()
  return useQuery({
    queryKey: repoKeys.log(room, ref),
    queryFn: () => getRepoBackend().commitLog(room, ref),
    enabled: ready,
    // Switching branches keeps the previous ref's list on screen during the
    // fetch (no skeleton/empty flash); replaced once the new ref's log resolves.
    placeholderData: keepPreviousData,
  })
}

/** All refs in the room (optionally prefix-filtered) — drives the branches panel. */
export function useRefs(room: string, prefix = '') {
  const ready = useRepoBackendReady()
  return useQuery({
    queryKey: repoKeys.refs(room, prefix),
    queryFn: () => getRepoBackend().listRefs(room, prefix),
    enabled: ready,
    // Keep the prior prefix's refs visible while a new prefix loads.
    placeholderData: keepPreviousData,
  })
}

export type PushArgs = {
  api: MkitApi
  seedHex: string
  room: string
  ref: string
  /**
   * Raw mkit object bytes — a commit (from `commit_encode_and_sign`) or a
   * remix (from `remix_encode_and_sign`). PutObject is content-addressed,
   * so the same push path stores either kind.
   */
  commitBytes: Uint8Array
  commitHash: string
  message: string
  /** Parent the object was built on — the CAS expected id (empty for the first object on the ref). */
  parentHash: string
  /** `'commit'` (default) or `'remix'` — tags the recorded log entry. */
  kind?: 'commit' | 'remix'
  /** For a remix push: the upstream commit(s) it forks from (for the log badge). */
  sources?: RemixSourceEntry[]
}

/**
 * Build the log entry recorded for a locally-originated push, SHAPE-IDENTICAL
 * to what a server ref-walk produces in {@link decodeLogObject}. We decode the
 * commit/remix bytes we already hold so `authorPubkey` (signer), `kind`,
 * `sources` and `createdAt` (ISO from the object's unix-seconds timestamp) all
 * match a walked entry exactly — so the optimistic entry we prepend renders
 * identically to the authoritative one and the later reconcile is a no-op for
 * our own commit. Falls back to args-derived fields if the bytes don't decode
 * (e.g. a test/mock that passes opaque bytes), so the entry is always usable.
 */
export function buildPushLogEntry(args: PushArgs): CommitLogEntry {
  const decoded = decodeLogObject(args.api, args.commitBytes, args.commitHash, args.ref)
  if (decoded) {
    // Prefer the caller's explicit kind/sources/message (the UI's intent),
    // but take signer + timestamp from the signed bytes for walk-parity.
    return {
      ...decoded.entry,
      message: args.message,
      kind: args.kind ?? decoded.entry.kind ?? 'commit',
      ...(args.sources ? { sources: args.sources } : {}),
    }
  }
  // Fallback: derive the author from the in-memory seed; stamp "now" (seconds,
  // rendered ISO) to stay consistent with the walked `createdAt` format.
  const authorPubkey = bytesToHex(args.api.ed25519_pubkey_from_seed(hexToBytes(args.seedHex)))
  return {
    hash: args.commitHash,
    message: args.message,
    authorPubkey,
    ref: args.ref,
    createdAt: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
    kind: args.kind ?? 'commit',
    ...(args.sources ? { sources: args.sources } : {}),
  }
}

/**
 * Mutation options for {@link usePushCommit}, factored out so the optimistic
 * lifecycle (onMutate prepend → onError rollback → onSettled reconcile) is
 * unit-testable against a real QueryClient + MutationObserver without React.
 */
export function pushCommitMutationOptions(qc: ReturnType<typeof useQueryClient>) {
  return {
    mutationFn: async (args: PushArgs) => {
      const backend = getRepoBackend()

      await backend.putObject(args.room, args.commitHash, args.commitBytes)

      const expectation: RefExpectation = args.parentHash ? 'MATCH' : 'MISSING'
      await backend.updateRef(args.room, args.ref, args.commitHash, expectation, args.parentHash || undefined)

      const entry = buildPushLogEntry(args)
      if (backend instanceof MockRepoBackend || backend instanceof WasmRepoBackend) {
        backend.recordCommit(args.room, entry)
      }
      return entry
    },
    // OPTIMISTIC PREPEND: show the user's own commit instantly. Cancel any
    // in-flight log fetch (so a slow walk can't clobber our optimistic value),
    // snapshot the current log for rollback, and prepend the new entry built
    // from the bytes we already hold.
    onMutate: async (args: PushArgs) => {
      const logKey = repoKeys.log(args.room, args.ref)
      await qc.cancelQueries({ queryKey: logKey })
      const previous = qc.getQueryData<CommitLogEntry[]>(logKey)
      const entry = buildPushLogEntry(args)
      qc.setQueryData<CommitLogEntry[]>(logKey, (prev) => {
        const list = prev ?? []
        if (list.some((e) => e.hash === entry.hash)) return list // already present — no dupe
        return [entry, ...list]
      })
      return { previous, logKey }
    },
    // ROLLBACK on a rejected push (e.g. CAS conflict) — restore the snapshot.
    onError: (
      _err: unknown,
      _args: PushArgs,
      context: { previous: CommitLogEntry[] | undefined; logKey: readonly unknown[] } | undefined,
    ) => {
      if (context) qc.setQueryData(context.logKey, context.previous)
    },
    // RECONCILE with the server regardless of outcome: invalidate ref + log +
    // refs so the authoritative walk corrects any divergence (the object cache
    // + incremental walk make this cheap — only new objects are fetched).
    onSettled: (_entry: CommitLogEntry | undefined, _err: unknown, args: PushArgs) => {
      void qc.invalidateQueries({ queryKey: repoKeys.ref(args.room, args.ref) })
      void qc.invalidateQueries({ queryKey: repoKeys.log(args.room, args.ref) })
      // A first push to a new ref makes a new branch appear in the panel.
      void qc.invalidateQueries({ queryKey: ['repo', args.room, 'refs'] })
    },
  }
}

/**
 * Push a signed commit: PutObject (idempotent), then UpdateRef with an in-message
 * CAS expectation (§3 step 5). First commit (no parent) → `MISSING`; otherwise
 * `MATCH` on the parent. A failed precondition surfaces as `CasConflictError`
 * for the caller's fetch→re-parent→re-sign retry loop (§4).
 *
 * The signed-write envelope is NOT built here: each backend owns signing. The
 * `WasmRepoBackend` signs inside its sign-callback over the EXACT serialized
 * protobuf body the transport sends (so `X-Digest` matches the server); the mock
 * verifies the signing path in its own tests. This mutation only orchestrates
 * the two calls and records the commit-log entry.
 */
export function usePushCommit() {
  const qc = useQueryClient()
  return useMutation(pushCommitMutationOptions(qc))
}

/**
 * Subscribe to live ref updates (WatchRefs server-stream) for a room and
 * invalidate the affected queries (§5) — turns a peer's push into a refetch so
 * the log updates within a frame.
 */
export function useRepoEvents(room: string, prefix = ''): void {
  const qc = useQueryClient()
  useEffect(() => {
    const unsub = getRepoBackend().watchRefs(room, prefix, (u) => {
      void qc.invalidateQueries({ queryKey: repoKeys.ref(room, u.name) })
      void qc.invalidateQueries({ queryKey: repoKeys.log(room, u.name) })
      // The advanced ref may be new (a peer created a branch) → refresh the panel.
      void qc.invalidateQueries({ queryKey: ['repo', room, 'refs'] })
    })
    return unsub
  }, [room, prefix, qc])
}
