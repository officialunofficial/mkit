// Transport-agnostic repo backend: service shapes, fork-ref scheme, the
// `RepoBackend` interface, `decodeLogObject`, typed errors, the in-memory
// `MockRepoBackend` (incl. `seedDemo`), and the wasm-backed `WasmRepoBackend`.
//
// Moved verbatim out of the former monolithic `repo-api.ts`; re-exported by the
// `repo-api` barrel so existing `from '../lib/repo-api'` imports keep working.

import { TEXT_ENCODER, bytesToHex, hexToBytes } from '../../components/use-mkit'
import type { MkitApi } from '../mkit'
import { type RepoSignFn, makeSignFn, procedures } from './envelope'

// ---------------------------------------------------------------------------
// Service shapes (mirror mkit.repo.v1.RepoService)
// ---------------------------------------------------------------------------

/** CAS precondition carried inside UpdateRefRequest (proto enum RefExpectation). */
export type RefExpectation = 'ANY' | 'MISSING' | 'MATCH'

export type RefEntry = { name: string; objectIdHex: string }
export type RefUpdate = { name: string; objectIdHex: string; authorPubkeyHex: string }

/**
 * One stored chat message — mirrors the proto `ChatMessage`. `createdAt` is server epoch-ms; `seq` is the monotonic
 * per-room order used to merge chat against commits in the lobby feed.
 */
export type ChatMessageEntry = {
  messageIdHex: string
  authorPubkeyHex: string
  text: string
  createdAt: number
  seq: number
}

/** Max chat message length in characters — mirrors the server cap (chat.rs). */
export const MAX_MESSAGE_CHARS = 280

/**
 * Domain prefix for a chat message's canonical bytes — MUST byte-match the server's `CHAT_CANONICAL_PREFIX` so a mock
 * and the worker content-address an identical (room, author, text) to the SAME id.
 */
const CHAT_CANONICAL_PREFIX = 'mkit-chat:v1'

/**
 * Canonical bytes a chat message is content-addressed by (mirrors `chat::canonical_message`):
 * `mkit-chat:v1\n{room}\n{authorHex}\n{text}`.
 */
export function chatCanonical(room: string, authorHex: string, text: string): Uint8Array {
  return TEXT_ENCODER.encode(`${CHAT_CANONICAL_PREFIX}\n${room}\n${authorHex}\n${text}`)
}

/**
 * One stored reaction — mirrors the proto `Reaction`. `targetIdHex` is the hex id of the feed item (chat message id or
 * commit hash).
 */
export type ReactionEntry = { targetIdHex: string; emoji: string; authorPubkeyHex: string }

/** A live reaction toggle frame (the new on/off state for one reactor). */
export type ReactionUpdate = {
  targetIdHex: string
  emoji: string
  authorPubkeyHex: string
  active: boolean
  count: number
}

/** Aggregated reactions for one feed item: emoji → count + whether I reacted. */
export type ReactionAgg = { emoji: string; count: number; mine: boolean }

/**
 * Aggregate raw reaction rows into per-target emoji tallies. Pure + unit-tested. Emoji order within a target is the
 * order they first appear (stable).
 */
export function aggregateReactions(entries: ReactionEntry[], myPubkeyHex?: string): Map<string, ReactionAgg[]> {
  const byTarget = new Map<string, ReactionAgg[]>()
  for (const e of entries) {
    let list = byTarget.get(e.targetIdHex)
    if (!list) {
      list = []
      byTarget.set(e.targetIdHex, list)
    }
    let agg = list.find((a) => a.emoji === e.emoji)
    if (!agg) {
      agg = { emoji: e.emoji, count: 0, mine: false }
      list.push(agg)
    }
    agg.count += 1
    if (myPubkeyHex && e.authorPubkeyHex === myPubkeyHex) agg.mine = true
  }
  return byTarget
}

/**
 * Live-stream handlers for a room: ref advances, chat messages, and reaction toggles. All ride the ONE `/watch/<room>`
 * socket so the lobby stays live.
 */
/** One online participant — an Ed25519 key present in the room right now. */
export type PresenceMember = { pubkeyHex: string; since: number }
/** Live room presence: distinct online keys + the count of identity-less viewers. */
export type PresenceState = { members: PresenceMember[]; viewers: number }
export const EMPTY_PRESENCE: PresenceState = { members: [], viewers: 0 }

export type RoomWatchHandlers = {
  onRef?: (u: RefUpdate) => void
  onChat?: (m: ChatMessageEntry) => void
  onPresence?: (p: PresenceState) => void
  onReaction?: (r: ReactionUpdate) => void
}

/** A parsed `/watch` frame — a ref advance (`commit`), a `chat` message, a `presence` roster, or a `reaction` toggle. */
export type ActivityFrame =
  | { kind: 'commit'; ref: RefUpdate }
  | { kind: 'chat'; message: ChatMessageEntry }
  | { kind: 'presence'; presence: PresenceState }
  | { kind: 'reaction'; reaction: ReactionUpdate }

/**
 * Parse one raw `/watch` WebSocket frame. Accepts the server's snake_case fields and camelCase, dispatches on the
 * `kind` discriminator, and stays back-compatible with legacy untagged ref frames (no `kind` → inferred from the
 * presence of `object_id`/`message_id`). Returns null for non-strings, malformed JSON, or frames missing their required
 * ids.
 */
export function parseActivityFrame(data: unknown): ActivityFrame | null {
  if (typeof data !== 'string') return null
  let f: Record<string, unknown>
  try {
    f = JSON.parse(data) as Record<string, unknown>
  } catch {
    return null
  }
  if (!f || typeof f !== 'object') return null

  const kind = f.kind
  if (kind === 'presence') {
    const raw = Array.isArray(f.members) ? f.members : []
    const members: PresenceMember[] = raw
      .map((m) => {
        const o = (m ?? {}) as Record<string, unknown>
        return { pubkeyHex: String(o.pubkey ?? o.pubkeyHex ?? ''), since: Number(o.since ?? 0) }
      })
      .filter((m) => m.pubkeyHex)
    return { kind: 'presence', presence: { members, viewers: Number(f.viewers ?? 0) } }
  }
  if (kind === 'reaction') {
    const targetIdHex = (f.targetIdHex ?? f.target_id) as string | undefined
    if (!targetIdHex) return null
    return {
      kind: 'reaction',
      reaction: {
        targetIdHex,
        emoji: (f.emoji ?? '') as string,
        authorPubkeyHex: (f.authorPubkeyHex ?? f.author_pubkey ?? '') as string,
        active: f.active === true,
        count: Number(f.count ?? 0),
      },
    }
  }

  const messageIdHex = (f.messageIdHex ?? f.message_id) as string | undefined
  if (kind === 'chat' || (kind === undefined && messageIdHex)) {
    if (!messageIdHex) return null
    return {
      kind: 'chat',
      message: {
        messageIdHex,
        authorPubkeyHex: (f.authorPubkeyHex ?? f.author_pubkey ?? '') as string,
        text: (f.text ?? '') as string,
        createdAt: Number(f.createdAt ?? f.created_at ?? 0),
        seq: Number(f.seq ?? 0),
      },
    }
  }

  const name = f.name as string | undefined
  const objectIdHex = (f.objectIdHex ?? f.object_id) as string | undefined
  if (!name || !objectIdHex) return null
  return {
    kind: 'commit',
    ref: { name, objectIdHex, authorPubkeyHex: (f.authorPubkeyHex ?? f.author_pubkey ?? '') as string },
  }
}

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
 * Parse the DO index's `sources_json` (`[[upstreamHex, commitHex], …]`, `"[]"` for a plain commit) back into
 * {@link RemixSourceEntry}[]. Tolerant of malformed input (returns `[]`).
 */
export function parseSourcesJson(json: string): RemixSourceEntry[] {
  if (!json || json === '[]') return []
  try {
    const arr: unknown = JSON.parse(json)
    if (!Array.isArray(arr)) return []
    return arr
      .filter((p): p is [string, string] => Array.isArray(p) && p.length === 2)
      .map(([upstreamIdHex, commitHashHex]) => ({ upstreamIdHex, commitHashHex }))
  } catch {
    return []
  }
}

/**
 * Fork ref name for a remix derived from `upstreamCommitHash` by the forker whose Ed25519 pubkey is `forkerPubkeyHex`.
 * Lands under the `forks/` prefix so the Refs panel can mark it as a fork (distinct from `main` / feature branches).
 *
 * Scheme: `forks/<upstreamShort>-<forkerShort>` where `upstreamShort` is the upstream commit's first 12 hex chars and
 * `forkerShort` is the forker's pubkey first 12 hex chars. Keying on BOTH makes the ref unique per (commit, forker):
 * two users forking the SAME commit get DISTINCT refs (no collision), and a 48-bit prefix collision across two upstream
 * commits no longer aliases onto one ref. The same forker re-forking the same commit reuses ITS ref, so repeated forks
 * chain (CAS `MATCH` advances) instead of orphaning.
 *
 * `forkerPubkeyHex` is optional only so legacy seeded demo data (which keys on the upstream alone) still resolves; real
 * forks always pass it.
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

/**
 * Branch-off (NO attribution) ref name: a plain branch pointing AT a commit (git `branch <name> <commit>`) — no remix
 * object, no recorded source. A distinct `b/` namespace from remix `forks/` so the two never collide, and unique per
 * (commit, brancher) so two people branching the same commit get distinct branches.
 */
export const BRANCH_PREFIX = 'b/'
export function branchRefName(upstreamCommitHash: string, brancherPubkeyHex: string): string {
  return `${BRANCH_PREFIX}${upstreamCommitHash.slice(0, 12)}-${brancherPubkeyHex.slice(0, 12)}`
}

// ---------------------------------------------------------------------------
// Transport-agnostic backend interface (maps 1:1 to the Connect service)
// ---------------------------------------------------------------------------

/**
 * Options for {@link RepoBackend.commitLog}. A cold walk fetches each commit object over its own network round-trip, so:
 * - `limit` caps how many commits to walk (the front-page lobby only needs recent activity, not the full history); and
 * - `onProgress` streams the entries gathered so far (newest-first) after each object resolves, so a consumer can paint
 * commits incrementally instead of waiting for the whole chain.
 */
export interface CommitLogOpts {
  limit?: number
  onProgress?: (entries: CommitLogEntry[]) => void
}

export interface RepoBackend {
  /** PutObject — content-addressed, idempotent (re-put of the same id is a no-op). */
  putObject(room: string, objectIdHex: string, bytes: Uint8Array): Promise<void>
  /** GetObject — raw object bytes, or null if absent. */
  getObject(room: string, objectIdHex: string): Promise<Uint8Array | null>
  /** GetRef — current object id the ref points at, or null. */
  getRef(room: string, name: string): Promise<string | null>
  /**
   * UpdateRef — CAS-advance a ref. `expectation` is the precondition: MISSING → create only (ref must not exist), MATCH
   * → advance only if current == `expectedIdHex`, ANY → unconditional set. Throws `CasConflictError` when the
   * precondition fails.
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
   * Live room stream — ref advances AND chat messages over ONE subscription (the merged lobby feed). Returns an
   * unsubscribe fn. `watchRefs` is the refs-only special case (`{ onRef }`).
   */
  watchRoom(room: string, prefix: string, handlers: RoomWatchHandlers, pubkeyHex?: string | null): () => void
  /**
   * Commit log for the demo UI — the chain reachable from `ref` (default `main`), newest-first. The mock derives it; a
   * server walk sources it. `opts` bounds the walk (`limit`) and/or streams partial results (`onProgress`).
   */
  commitLog(room: string, ref?: string, opts?: CommitLogOpts): Promise<CommitLogEntry[]>
  /**
   * PostMessage — post a signed chat message to the room. The signing identity is the author (server-verified). Throws
   * `IdentityLockedError` when no seed is available; resolves `{ rateLimited: true, accepted: false }` when the author
   * posted too recently.
   */
  postMessage(room: string, text: string): Promise<{ messageIdHex: string; accepted: boolean; rateLimited: boolean }>
  /** ListMessages — recent room messages, oldest-first, capped by `limit`. */
  listMessages(room: string, limit?: number): Promise<ChatMessageEntry[]>
  /** React — toggle the signing identity's emoji reaction on a feed item (`targetIdHex`). */
  react(room: string, targetIdHex: string, emoji: string): Promise<{ active: boolean; count: number }>
  /** ListReactions — every reaction in the room (client aggregates). */
  listReactions(room: string): Promise<ReactionEntry[]>
}

/**
 * Decode one fetched object into a log entry, routing by `object_kind` so the SAME walk handles both commits and
 * remixes (a fork ref's head is a remix). Returns the entry plus its first parent to continue the walk, or `null` for
 * any other object kind (or a decode failure) so the caller stops the walk rather than throwing. Shared by the wasm
 * ref-walk and the detail view's client-side decode.
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

// ---------------------------------------------------------------------------
// Merged lobby feed: commits + chat on one timeline
// ---------------------------------------------------------------------------

/**
 * One row of the merged lobby feed — a commit/remix or a chat message. `ts` is epoch-ms (the sort key); `key` is a
 * stable React key.
 */
export type FeedItem =
  | { kind: 'commit'; ts: number; key: string; entry: CommitLogEntry }
  | { kind: 'chat'; ts: number; key: string; message: ChatMessageEntry }

/**
 * Merge a room's commit log and chat messages into one chronological feed, OLDEST-FIRST (chat reading order; newest at
 * the bottom). Both kinds are signed by the same Ed25519 identity, so the lobby renders a player's commits and chatter
 * on one timeline. Stable tiebreak at equal timestamps puts the commit before the chat message. Pure — unit-tested
 * without React.
 */
export function mergeFeed(commits: CommitLogEntry[], messages: ChatMessageEntry[]): FeedItem[] {
  const items: FeedItem[] = [
    // `commits` arrive newest-first (the ref walk / commitLog order); reverse to
    // oldest-first so two commits sharing a timestamp (unix-second precision)
    // render oldest-first under the stable sort, consistent with the rest of the
    // feed — not newest-first like the raw walk.
    ...[...commits]
      .reverse()
      .map(
        (entry): FeedItem => ({ kind: 'commit', ts: Date.parse(entry.createdAt) || 0, key: `c:${entry.hash}`, entry }),
      ),
    ...messages.map(
      (message): FeedItem => ({
        kind: 'chat',
        ts: message.createdAt || 0,
        key: `m:${message.messageIdHex}:${message.seq}`,
        message,
      }),
    ),
  ]
  items.sort((a, b) => a.ts - b.ts || (a.kind === b.kind ? 0 : a.kind === 'commit' ? -1 : 1))
  return items
}

export class CasConflictError extends Error {
  constructor(public current: string | null) {
    super('Someone else changed this first. Refresh and try again.')
    this.name = 'CasConflictError'
  }
}

/**
 * Thrown when a signed write is attempted while the identity is locked (no seed in memory). UI can catch this to
 * surface an "unlock to push" prompt.
 */
export class IdentityLockedError extends Error {
  constructor() {
    super('Unlock your identity before signing.')
    this.name = 'IdentityLockedError'
  }
}

/**
 * Thrown when a push is attempted before a backend is available. In practice push is only reachable once unlocked
 * (backend present), so this is a guard for the structurally-impossible null case rather than a user-facing path.
 */
export class BackendNotReadyError extends Error {
  constructor() {
    super('Not ready yet. Try again in a moment.')
    this.name = 'BackendNotReadyError'
  }
}

// ---------------------------------------------------------------------------
// In-memory mock backend (no server)
// ---------------------------------------------------------------------------

// A couple of "other players'" commits, so the live multiplayer log isn't empty
// on first load. Seeded once per mock backend via `seedDemo`. The third lands on
// a `feature` branch so the refs panel shows more than just `main` offline.
const FOREIGN_SEEDS = ['7'.repeat(64), 'a3'.repeat(32), 'b5'.repeat(32)]
const FOREIGN_MESSAGES = ['hello from another tab', 'ship it 🚀', 'spike on a feature branch']
const FOREIGN_REFS = ['main', 'main', 'feature']

/**
 * Register `handler` in the Set stored at `key` (creating the Set on first use) and return an unsubscribe that removes
 * it. The one shape behind all three of `watchRoom`'s channels — ref, chat, reaction — so adding a channel is one line.
 * A missing handler is a no-op (returns an unsubscribe that does nothing).
 */
function addWatcher<T>(map: Map<string, Set<T>>, key: string, handler: T | undefined): () => void {
  if (!handler) return () => {}
  let set = map.get(key)
  if (!set) {
    set = new Set()
    map.set(key, set)
  }
  set.add(handler)
  return () => set.delete(handler)
}

/**
 * In-memory backend implementing the Connect service shape. Mirrors server semantics: content-addressed idempotent
 * object writes, in-message CAS via `RefExpectation`, and a synchronous WatchRefs fan-out that drives Query
 * invalidation. Seeded with a couple of "other players'" commits so the live multiplayer log isn't empty.
 */
export class MockRepoBackend implements RepoBackend {
  private objects = new Map<string, Uint8Array>()
  private refs = new Map<string, string>()
  private log = new Map<string, CommitLogEntry[]>()
  private watchers = new Map<string, Set<(u: RefUpdate) => void>>()
  // Chat state: an ordered message log per room, a per-room sequence counter,
  // and chat subscribers (keyed by room — chat isn't prefix-filtered).
  private messages = new Map<string, ChatMessageEntry[]>()
  private seqByRoom = new Map<string, number>()
  private chatWatchers = new Map<string, Set<(m: ChatMessageEntry) => void>>()
  // Reactions: raw rows per room + subscribers (keyed by room).
  private reactions = new Map<string, ReactionEntry[]>()
  private reactionWatchers = new Map<string, Set<(r: ReactionUpdate) => void>>()
  /**
   * Rooms already demo-seeded, so `seedDemoOnce` is idempotent across renders and room switches (the instance is
   * reused, never recreated).
   */
  private seededRooms = new Set<string>()

  /**
   * `seedHex` supplies the live signing seed so the mock can attribute a posted message to the unlocked player (the
   * wasm backend gets the author from the server; offline the mock derives it locally). Optional so existing `new
   * MockRepoBackend(api)` call sites and tests keep working — posting then throws `IdentityLockedError` until a seed
   * accessor is provided.
   */
  constructor(
    private api: MkitApi,
    private seedHex?: () => string | null,
  ) {}

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
    return this.watchRoom(room, prefix, { onRef: onUpdate })
  }

  watchRoom(room: string, prefix: string, handlers: RoomWatchHandlers, pubkeyHex?: string | null): () => void {
    const unsubs = [
      addWatcher(this.watchers, `${room}::${prefix}`, handlers.onRef),
      addWatcher(this.chatWatchers, room, handlers.onChat),
      addWatcher(this.reactionWatchers, room, handlers.onReaction),
    ]
    if (handlers.onPresence) {
      // Offline parity: there are no real peers on the mock, so synthesise a
      // small roster — a couple of seeded "online" keys, plus YOU as a member
      // when unlocked (or an extra viewer when signed out). Re-emitted whenever
      // the subscription re-runs (i.e. on lock/unlock), so the panel visibly
      // moves you between member and viewer.
      handlers.onPresence(this.mockPresence(pubkeyHex ?? null))
    }
    return () => {
      for (const u of unsubs) u()
    }
  }

  /** Synthetic roster for offline (mock) presence — see `watchRoom`. */
  private mockPresence(pubkeyHex: string | null): PresenceState {
    const now = Date.now()
    const members: PresenceMember[] = [FOREIGN_SEEDS[0]!, FOREIGN_SEEDS[1]!].map((seed, i) => ({
      pubkeyHex: bytesToHex(this.api.ed25519_pubkey_from_seed(hexToBytes(seed))),
      since: now - (i + 1) * 90_000,
    }))
    if (pubkeyHex) members.unshift({ pubkeyHex, since: now })
    return { members, viewers: pubkeyHex ? 1 : 2 }
  }

  async react(room: string, targetIdHex: string, emoji: string): Promise<{ active: boolean; count: number }> {
    const seed = this.seedHex?.() ?? null
    if (!seed) throw new IdentityLockedError()
    const authorPubkeyHex = bytesToHex(this.api.ed25519_pubkey_from_seed(hexToBytes(seed)))
    const list = this.reactions.get(room) ?? []
    const idx = list.findIndex(
      (r) => r.targetIdHex === targetIdHex && r.emoji === emoji && r.authorPubkeyHex === authorPubkeyHex,
    )
    let active: boolean
    if (idx >= 0) {
      list.splice(idx, 1) // toggle off
      active = false
    } else {
      list.push({ targetIdHex, emoji, authorPubkeyHex }) // toggle on
      active = true
    }
    this.reactions.set(room, list)
    const count = list.filter((r) => r.targetIdHex === targetIdHex && r.emoji === emoji).length
    this.broadcastReaction(room, { targetIdHex, emoji, authorPubkeyHex, active, count })
    return { active, count }
  }

  async listReactions(room: string): Promise<ReactionEntry[]> {
    return [...(this.reactions.get(room) ?? [])]
  }

  private broadcastReaction(room: string, u: ReactionUpdate): void {
    for (const l of this.reactionWatchers.get(room) ?? []) l(u)
  }

  async postMessage(
    room: string,
    text: string,
  ): Promise<{ messageIdHex: string; accepted: boolean; rateLimited: boolean }> {
    const trimmed = text.trim()
    if (!trimmed) throw new Error('Add a message before sending.')
    if ([...trimmed].length > MAX_MESSAGE_CHARS) throw new Error('Your message is too long. Shorten it and try again.')
    const seed = this.seedHex?.() ?? null
    if (!seed) throw new IdentityLockedError()

    const authorPubkeyHex = bytesToHex(this.api.ed25519_pubkey_from_seed(hexToBytes(seed)))
    // Content-address the canonical bytes — same scheme as the server, so the
    // id is the message's hash (a first-class object, not a row id).
    const messageIdHex = this.api.blake3_hex(chatCanonical(room, authorPubkeyHex, trimmed))
    const seq = (this.seqByRoom.get(room) ?? 0) + 1
    this.seqByRoom.set(room, seq)
    const entry: ChatMessageEntry = { messageIdHex, authorPubkeyHex, text: trimmed, createdAt: Date.now(), seq }
    const list = this.messages.get(room) ?? []
    list.push(entry)
    this.messages.set(room, list)
    this.broadcastChat(room, entry)
    return { messageIdHex, accepted: true, rateLimited: false }
  }

  async listMessages(room: string, limit = 50): Promise<ChatMessageEntry[]> {
    const list = this.messages.get(room) ?? []
    // Oldest-first, capped to the most-recent `limit` (mirrors the DO).
    return list.slice(Math.max(0, list.length - limit))
  }

  private broadcastChat(room: string, entry: ChatMessageEntry): void {
    for (const l of this.chatWatchers.get(room) ?? []) l(entry)
  }

  /**
   * Seed a couple of foreign players' messages so the offline lobby isn't empty. Mock-only (worker mode sources real
   * history).
   */
  seedDemoChat(room: string): void {
    const samples: Array<{ seed: string; text: string }> = [
      { seed: FOREIGN_SEEDS[0]!, text: 'gm — every message here is ed25519-signed' },
      { seed: FOREIGN_SEEDS[1]!, text: 'pushed a commit, say hi 👋' },
    ]
    const ids: string[] = []
    samples.forEach(({ seed, text }, i) => {
      const authorPubkeyHex = bytesToHex(this.api.ed25519_pubkey_from_seed(hexToBytes(seed)))
      const messageIdHex = this.api.blake3_hex(chatCanonical(room, authorPubkeyHex, text))
      ids.push(messageIdHex)
      const seq = (this.seqByRoom.get(room) ?? 0) + 1
      this.seqByRoom.set(room, seq)
      const list = this.messages.get(room) ?? []
      list.push({
        messageIdHex,
        authorPubkeyHex,
        text,
        createdAt: Date.now() - (samples.length - i) * 45_000,
        seq,
      })
      this.messages.set(room, list)
    })
    // Seed a few reactions so the offline lobby shows the affordance.
    const a0 = bytesToHex(this.api.ed25519_pubkey_from_seed(hexToBytes(FOREIGN_SEEDS[0]!)))
    const a1 = bytesToHex(this.api.ed25519_pubkey_from_seed(hexToBytes(FOREIGN_SEEDS[1]!)))
    const a2 = bytesToHex(this.api.ed25519_pubkey_from_seed(hexToBytes(FOREIGN_SEEDS[2]!)))
    const seeded: ReactionEntry[] = [
      { targetIdHex: ids[0]!, emoji: '👋', authorPubkeyHex: a1 },
      { targetIdHex: ids[0]!, emoji: '👋', authorPubkeyHex: a2 },
      { targetIdHex: ids[1]!, emoji: '🚀', authorPubkeyHex: a0 },
    ]
    this.reactions.set(room, [...(this.reactions.get(room) ?? []), ...seeded])
  }

  async commitLog(room: string, ref = 'main', opts?: CommitLogOpts): Promise<CommitLogEntry[]> {
    const all = (this.log.get(room) ?? []).filter((e) => e.ref === ref).toReversed()
    const entries = opts?.limit != null ? all.slice(0, opts.limit) : all
    // Local/in-memory: no round-trips, so just emit the final set once (lets the
    // shared `onProgress` consumer treat mock and wasm backends identically).
    opts?.onProgress?.(entries)
    return entries
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

  /**
   * Seed a room's offline demo activity (commits + chat) exactly once. Safe to call on every render: the `seededRooms`
   * guard makes repeat calls (and a room switch back) no-ops, so the long-lived mock instance is never recreated and a
   * user's session posts survive a room change. Called during render (lazy initialization), not from an Effect, so the
   * data exists before the first query reads it.
   */
  seedDemoOnce(room: string): void {
    if (this.seededRooms.has(room)) return
    this.seededRooms.add(room)
    this.seedDemo(room)
    this.seedDemoChat(room)
  }

  /**
   * MOCK-MODE demo seeding (offline affordance). Builds a few "other players'" commits — three foreign commits (two on
   * `main`, one on a `feature` branch) plus a sample remix/fork of the first commit on a `forks/` ref — so the live
   * multiplayer log isn't empty on first load and the offline detail + fork UI paths are exercised before anyone
   * interacts. Deterministic: the objects (and their hashes/messages/authors/refs/timestamps) are fixed per `room`,
   * built via the same `commit_encode_and_sign` / `remix_encode_and_sign` a real push uses so they decode through the
   * SAME `object_kind` → commit/remix walk.
   *
   * In worker mode the room's real shared history comes from the worker, so this is NOT called there.
   */
  seedDemo(room: string): void {
    const api = this.api
    // Seed foreign commits deterministically so the log shows multiplayer life.
    // Also store the commit object so the offline detail view can decode it.
    // Keep the first foreign commit's hash so we can seed a remix of it.
    let firstCommitHash: string | null = null
    FOREIGN_SEEDS.forEach((seed, i) => {
      const tree = api.tree_encode('[]')
      // Stamp a REAL recent unix-seconds timestamp into the signed object (not
      // `BigInt(i)`, which decoded to ~1970 → an absurd "20629d" if any path
      // reads the object's own timestamp).
      const tsSecs = BigInt(Math.floor((Date.now() - (FOREIGN_SEEDS.length - i) * 60_000) / 1000))
      const commit = api.commit_encode_and_sign(tree.hash_hex, '', FOREIGN_MESSAGES[i]!, tsSecs, seed)
      if (i === 0) firstCommitHash = commit.hash_hex
      const pubkey = bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(seed)))
      void this.putObject(room, commit.hash_hex, commit.bytes)
      this.seedForeignCommit(room, {
        hash: commit.hash_hex,
        message: FOREIGN_MESSAGES[i]!,
        authorPubkey: pubkey,
        ref: FOREIGN_REFS[i]!,
        createdAt: new Date(Date.now() - (FOREIGN_SEEDS.length - i) * 60_000).toISOString(),
      })
    })
    // Seed a sample remix/fork of the first commit so the fork UI path
    // (badge + navigable upstream link + `forks/` ref) is exercised offline,
    // even before anyone clicks "Fork". The remix decodes through the SAME
    // object_kind → remix_decode walk a real push produces.
    if (firstCommitHash) {
      const upstreamCommit: string = firstCommitHash
      const upstreamId = api.blake3_hex(TEXT_ENCODER.encode(room))
      const sourcesJson = JSON.stringify([{ upstream_id_hex: upstreamId, commit_hash_hex: upstreamCommit }])
      const tree = api.tree_encode('[]')
      const remix = api.remix_encode_and_sign(
        tree.hash_hex,
        '',
        sourcesJson,
        `fork of ${upstreamCommit.slice(0, 10)}…`,
        4n,
        FOREIGN_SEEDS[0]!,
      )
      const forkRef = forkRefName(upstreamCommit)
      const pubkey = bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(FOREIGN_SEEDS[0]!)))
      void this.putObject(room, remix.hash_hex, remix.bytes)
      this.seedForeignCommit(room, {
        hash: remix.hash_hex,
        message: `fork of ${upstreamCommit.slice(0, 10)}…`,
        authorPubkey: pubkey,
        ref: forkRef,
        createdAt: new Date(Date.now() - 30_000).toISOString(),
        kind: 'remix',
        sources: [{ upstreamIdHex: upstreamId, commitHashHex: upstreamCommit }],
      })
    }
  }
}

// ---------------------------------------------------------------------------
// WASM-backed backend (real ConnectRPC client over Fetch)
// ---------------------------------------------------------------------------

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
  post_message(
    baseUrl: string,
    room: string,
    text: string,
    sign: RepoSignFn,
  ): Promise<{ messageIdHex: string; accepted: boolean; rateLimited: boolean }>
  list_messages(baseUrl: string, room: string, limit: number): Promise<ChatMessageEntry[]>
  react(
    baseUrl: string,
    room: string,
    targetIdHex: string,
    emoji: string,
    sign: RepoSignFn,
  ): Promise<{ active: boolean; count: number }>
  list_reactions(baseUrl: string, room: string): Promise<ReactionEntry[]>
  /**
   * ListCommits — server-side first-parent walk; one round-trip returns a page of denormalized commit metadata (already
   * decoded server-side, no object bytes) plus a continuation cursor. The client renders it directly.
   */
  list_commits(
    baseUrl: string,
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
  }>
}

/**
 * Real backend: drives `mkit.repo.v1.RepoService` over the wasm ConnectRPC client (Fetch transport). Reads hit the
 * server directly; writes flow through the sign-callback (envelope built + signed here in JS, attached wasm-side).
 *
 * `WatchRefs` server-streaming is not surfaceable over the buffered Fetch transport (see README §Streaming), so live
 * updates ride the worker's raw WebSocket route `GET /watch/<room>` — `watchRefs` opens it and fans each broadcast
 * frame out to `onUpdate` (which drives Query invalidation via `useRepoEvents`). `commitLog` is accumulated in-memory
 * on push (the service has no log RPC).
 */
/**
 * Open the live room WebSocket the worker exposes at `GET /watch/<room>` and dispatch parsed frames to `handlers`. PURE
 * transport — it needs only the backend BASE URL, NO wasm — so a consumer (the lobby) can open it on mount, in PARALLEL
 * with the wasm load, instead of waiting for the wasm backend to resolve (which serialized ~800ms onto first live
 * delivery). Reconnects with bounded exponential backoff; returns an unsubscribe that closes the socket.
 */
export function subscribeRoom(
  baseUrl: string,
  room: string,
  prefix: string,
  handlers: RoomWatchHandlers,
  pubkeyHex?: string | null,
): () => void {
  // Attribute this connection's presence to the current key when one is provided
  // + well-formed; absent → the DO counts it as a signed-out viewer.
  const pk = pubkeyHex && /^[0-9a-f]{64}$/.test(pubkeyHex) ? `?pubkey=${pubkeyHex}` : ''
  const wsUrl = `${baseUrl.replace(/^http/, 'ws')}/watch/${encodeURIComponent(room)}${pk}`
  let closed = false
  let ws: WebSocket | null = null
  let attempt = 0
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  const MAX_ATTEMPTS = 6 // ~bounded backoff; give up after this many failures

  const handleMessage = (ev: MessageEvent) => {
    const frame = parseActivityFrame(ev.data)
    if (!frame) return
    if (frame.kind === 'presence') return void handlers.onPresence?.(frame.presence)
    if (frame.kind === 'chat') return void handlers.onChat?.(frame.message)
    if (frame.kind === 'reaction') return void handlers.onReaction?.(frame.reaction)
    const u = frame.ref
    if (prefix && !u.name.startsWith(prefix)) return // client-side prefix filter
    handlers.onRef?.(u)
  }

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
      ws = null // No WebSocket available (e.g. SSR) — degrade to a no-op subscription.
      return
    }
    ws.addEventListener('open', () => {
      attempt = 0 // reset backoff once a connection is established
    })
    ws.addEventListener('message', handleMessage)
    ws.addEventListener('close', () => {
      if (!closed) scheduleReconnect()
    })
  }

  connect()

  return () => {
    if (closed) return
    closed = true
    if (reconnectTimer) clearTimeout(reconnectTimer)
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) ws.close()
  }
}

export class WasmRepoBackend implements RepoBackend {
  private log = new Map<string, CommitLogEntry[]>()
  /**
   * Memoised result of the last ref walk, keyed by `room::ref`. `head` is the ref value the cached `entries` were
   * walked from; when the ref advances (our push, or a peer's push surfaced via WatchRefs → query invalidation →
   * re-`commitLog`), `head` no longer matches and we re-walk. Keying by ref lets the browser switch between branches
   * without one branch's cache shadowing another's. The walk is INCREMENTAL: a re-walk after an advance only fetches
   * objects newer than the cached head, then splices the cached tail (see {@link WasmRepoBackend.commitLog}).
   */
  private walkCache = new Map<string, { head: string; entries: CommitLogEntry[] }>()
  /**
   * Hash-keyed object cache, keyed by `room::objectIdHex`. mkit objects are CONTENT-ADDRESSED — a given hash maps to
   * fixed bytes forever — so a cached entry can never go stale and is ALWAYS safe to serve without a network
   * round-trip. Populated on every successful {@link getObject} and consulted first; subsumes the per-walk re-download
   * of immutable history, so a post-commit re-walk network-fetches only the NEW object(s).
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
   * Fetch an object, serving from {@link WasmRepoBackend.objectCache} when present. Safe because objects are
   * content-addressed (immutable): the bytes behind a hash never change, so a cache hit is always correct. Misses hit
   * the wasm client once and populate the cache for every later read (the post-commit re-walk, the detail view, a
   * peer's re-walk).
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

  async postMessage(
    room: string,
    text: string,
  ): Promise<{ messageIdHex: string; accepted: boolean; rateLimited: boolean }> {
    // Sign over the EXACT serialized PostMessage body (the transport hashes it
    // and the server re-hashes); the verified pubkey becomes the author.
    const sign = makeSignFn(this.api, this.requireSeed(), procedures.PostMessage)
    return await this.wasm.post_message(this.baseUrl, room, text, sign)
  }

  async listMessages(room: string, limit = 50): Promise<ChatMessageEntry[]> {
    return await this.wasm.list_messages(this.baseUrl, room, limit)
  }

  async react(room: string, targetIdHex: string, emoji: string): Promise<{ active: boolean; count: number }> {
    const sign = makeSignFn(this.api, this.requireSeed(), procedures.React)
    return await this.wasm.react(this.baseUrl, room, targetIdHex, emoji, sign)
  }

  async listReactions(room: string): Promise<ReactionEntry[]> {
    return await this.wasm.list_reactions(this.baseUrl, room)
  }

  /**
   * Live ref updates over the raw WebSocket the worker exposes at `GET /watch/<room>` (WatchRefs server-streaming isn't
   * surfaceable over the buffered Fetch transport — see apps/repo-worker README §"WatchRefs / streaming"). The RefStore
   * DO broadcasts one JSON frame per successful UpdateRef: `{ name, object_id, author_pubkey }` — all hex (snake_case).
   * `prefix` filters client-side. Returns an unsubscribe that closes the socket.
   */
  watchRefs(room: string, prefix: string, onUpdate: (u: RefUpdate) => void): () => void {
    return this.watchRoom(room, prefix, { onRef: onUpdate })
  }

  /**
   * Live room stream over the raw WebSocket the worker exposes at `GET /watch/<room>` (Connect server-streaming isn't
   * surfaceable over the buffered Fetch transport — see apps/repo-worker README §"WatchRefs / streaming"). The RefStore
   * DO multiplexes ONE socket: a `kind:"commit"` frame per successful UpdateRef and a `kind:"chat"` frame per
   * PostMessage. `parseActivityFrame` normalises both; `prefix` filters ref frames client-side. Returns an unsubscribe
   * that closes the socket.
   */
  watchRoom(room: string, prefix: string, handlers: RoomWatchHandlers, pubkeyHex?: string | null): () => void {
    // Delegate to the shared, wasm-free socket (which carries presence + the
    // `?pubkey=` attribution). Wrap `onRef` to also record the peer's push into
    // the in-memory log (a placeholder message) so callers that read `this.log`
    // still see others contributing; the lobby instead drives the socket via
    // `subscribeRoom` directly (no wasm dependency).
    return subscribeRoom(
      this.baseUrl,
      room,
      prefix,
      {
        ...handlers,
        onRef: (u) => {
          this.recordCommit(room, {
            hash: u.objectIdHex,
            message: 'pushed by a peer',
            authorPubkey: u.authorPubkeyHex,
            ref: u.name,
            createdAt: new Date().toISOString(),
          })
          handlers.onRef?.(u)
        },
      },
      pubkeyHex,
    )
  }

  /**
   * Authoritative shared history: the chain reachable from the selected `ref` (default `main`), read from the worker,
   * so every viewer renders the SAME log (history + live), not just this session's pushes. Walks from the room's `ref`
   * by first-parent, decoding each commit object (`commit_decode`) for its real message / signer / parents — so a
   * peer's push (surfaced via WatchRefs → query invalidation → re-walk) shows its real message, not a placeholder.
   *
   * Newest-first (head → parent → …), matching the order `LiveLog` renders. Memoised by `room::ref` head hash so
   * repeated calls (and other branches) don't re-walk; a new head (push or WS event) invalidates the cache and
   * re-walks. Stops at no parent, a missing object, or {@link WasmRepoBackend.WALK_CAP}.
   */
  async commitLog(room: string, ref = 'main', opts?: CommitLogOpts): Promise<CommitLogEntry[]> {
    // Never walk past the safety cap; a caller (e.g. the front-page lobby) can
    // ask for fewer so a cold load isn't N sequential object round-trips deep.
    const cap = Math.min(opts?.limit ?? WasmRepoBackend.WALK_CAP, WasmRepoBackend.WALK_CAP)

    const head = await this.wasm.get_ref(this.baseUrl, room, ref)
    if (!head) return []

    const cacheKey = `${room}::${ref}`
    const cached = this.walkCache.get(cacheKey)
    if (cached && cached.head === head) return cached.entries.slice(0, cap)

    // The worker owns the commit-log walk: ListCommits returns the whole page of
    // denormalized metadata in ONE round-trip (O(1) round-trips, no per-object
    // GetObject + decode). The client just renders what it's handed.
    const entries = await this.commitLogViaListCommits(room, ref, cap, cached, opts)
    this.walkCache.set(cacheKey, { head, entries })
    return entries
  }

  /**
   * Page through ListCommits, mapping each denormalized entry straight to a log entry, and splice the cached tail when
   * the walk reaches a hash we already have. No object bytes, no decode — the worker serves the metadata.
   */
  private async commitLogViaListCommits(
    room: string,
    ref: string,
    cap: number,
    cached: { head: string; entries: CommitLogEntry[] } | undefined,
    opts?: CommitLogOpts,
  ): Promise<CommitLogEntry[]> {
    const tailByHash = new Map<string, number>()
    if (cached) cached.entries.forEach((e, i) => tailByHash.set(e.hash, i))

    const fresh: CommitLogEntry[] = []
    const seen = new Set<string>()
    let spliced: CommitLogEntry[] | null = null
    let cursor = '' // '' = walk from the ref head
    let done = false

    while (!done && fresh.length < cap) {
      const page = await this.wasm.list_commits(this.baseUrl, room, ref, cursor, cap - fresh.length)
      if (page.commits.length === 0) break
      for (const c of page.commits) {
        const tailIdx = tailByHash.get(c.hash)
        if (tailIdx !== undefined) {
          // biome-ignore lint/style/noNonNullAssertion: tailIdx came from cached.entries
          spliced = cached!.entries.slice(tailIdx)
          done = true
          break
        }
        if (seen.has(c.hash)) {
          done = true
          break
        } // cycle guard
        seen.add(c.hash)
        // Metadata from the DO index maps STRAIGHT to a log entry — no object
        // bytes, no decode.
        const sources = parseSourcesJson(c.sourcesJson)
        const entry: CommitLogEntry = {
          hash: c.hash,
          message: c.message,
          authorPubkey: c.authorPubkeyHex,
          ref,
          kind: c.kind === 'remix' ? 'remix' : 'commit',
          createdAt: new Date(c.createdAtUnix * 1000).toISOString(),
          ...(sources.length > 0 ? { sources } : {}),
        }
        fresh.push(entry)
        opts?.onProgress?.([...fresh])
        if (fresh.length >= cap) {
          done = true
          break
        }
      }
      cursor = page.nextCursorHex
      if (!cursor) break
    }

    return spliced ? [...fresh, ...spliced] : fresh
  }

  /**
   * Append a commit to the in-memory log (push mutation + WatchRefs peers), deduped by hash. The ref walk in
   * {@link WasmRepoBackend.commitLog} is the authoritative source; this is kept for any callers that still read
   * `this.log`, and as a record of locally-originated pushes.
   */
  recordCommit(room: string, entry: CommitLogEntry): void {
    const list = this.log.get(room) ?? []
    if (list.some((e) => e.hash === entry.hash)) return // e.g. our own push echoed back over WatchRefs
    list.push(entry)
    this.log.set(room, list)
  }
}
