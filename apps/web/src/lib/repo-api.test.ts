import { QueryClient, QueryObserver, MutationObserver, keepPreviousData } from '@tanstack/react-query'
import { describe, expect, it, vi } from 'vitest'
import { bytesToHex } from '../components/use-mkit'
import type { MkitApi } from './mkit'
import { mkit } from './mkit'
import {
  CasConflictError,
  type ChatMessageEntry,
  type CommitLogEntry,
  IdentityLockedError,
  MockRepoBackend,
  type FeedItem,
  type ReactionEntry,
  type RepoConnectClient,
  aggregateReactions,
  mergeFeed,
  parseActivityFrame,
  type PushArgs,
  type RepoBackend,
  type RepoWasmClient,
  type SignedEnvelope,
  WasmRepoBackend,
  buildSignedEnvelope,
  canonicalString,
  decodeLogObject,
  envelopeHeaders,
  forkRefName,
  isForkRef,
  makeSignFn,
  procedures,
  postMessageMutationOptions,
  pushCommitMutationOptions,
  repoKeys,
} from './repo-api'

const SEED = '0101010101010101010101010101010101010101010101010101010101010101'

/** No writes exercised — every WasmRepoBackend fixture below only drives reads through {@link fakeClient}. */
const NO_WRITES = {} as unknown as RepoWasmClient

/**
 * A fully-stubbed `RepoBackend` with inert no-op defaults; pass `overrides` to make just the method(s) under test do
 * something. One factory so adding a method to the interface is a single edit here, not a sweep across every test's
 * hand-rolled literal.
 */
function stubBackend(overrides: Partial<RepoBackend> = {}): RepoBackend {
  return {
    putObject: async () => {},
    getObject: async () => null,
    getRef: async () => null,
    updateRef: async () => {},
    listRefs: async () => [],
    watchRefs: () => () => {},
    watchRoom: () => () => {},
    commitLog: async () => [],
    postMessage: async () => ({ messageIdHex: '', accepted: true, rateLimited: false }),
    listMessages: async () => [],
    react: async () => ({ active: true, count: 1 }),
    listReactions: async () => [],
    ...overrides,
  }
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

/**
 * A `RepoConnectClient` stand-in exposing only the six unauthenticated reads `WasmRepoBackend` drives through it
 * (GetRef, GetObject, ListRefs, ListMessages, ListReactions, ListCommits — see `connect-client.ts`); the write RPCs
 * stay on the wasm client (`NO_WRITES` above), so the fake never needs them. Each stub receives the SAME
 * `bytes`/`bigint`-shaped request `connect-client.ts`'s wrapper functions build and returns a generated-message- shaped
 * response (minus the `$typeName` brand, irrelevant to the wrapper's field reads) — so these tests exercise the real
 * hex<->bytes / bigint<->number conversion, not a re-declared parallel shape. Missing methods default to an
 * empty/absent response. Cast at the call site like every other fake in this file (`as unknown as RepoWasmClient`).
 */
type GetRefReq = { room: string; name: string }
type GetObjectReq = { room: string; objectId: Uint8Array }
type ListRefsReq = { room: string; prefix: string }
type ListMessagesReq = { room: string; limit: number }
type ListReactionsReq = { room: string }
type ListCommitsReq = { room: string; ref: string; startId: Uint8Array; pageSize: number }

function fakeClient(methods: {
  getRef?: (req: GetRefReq) => { exists: boolean; objectId: Uint8Array }
  getObject?: (req: GetObjectReq) => { found: boolean; bytes: Uint8Array }
  listRefs?: (req: ListRefsReq) => { refs: Array<{ name: string; objectId: Uint8Array }> }
  listMessages?: (req: ListMessagesReq) => {
    messages: Array<{ messageId: Uint8Array; authorPubkey: Uint8Array; text: string; createdAt: bigint; seq: bigint }>
  }
  listReactions?: (req: ListReactionsReq) => {
    reactions: Array<{ targetId: string; emoji: string; authorPubkey: Uint8Array }>
  }
  listCommits?: (req: ListCommitsReq) => {
    commits: Array<{
      hash: string
      parent: string
      authorPubkey: string
      message: string
      createdAtUnix: bigint
      kind: string
      sourcesJson: string
    }>
    nextCursor: string
  }
}): RepoConnectClient {
  return {
    getRef: async (req: GetRefReq) => methods.getRef?.(req) ?? { exists: false, objectId: new Uint8Array(0) },
    getObject: async (req: GetObjectReq) => methods.getObject?.(req) ?? { found: false, bytes: new Uint8Array(0) },
    listRefs: async (req: ListRefsReq) => methods.listRefs?.(req) ?? { refs: [] },
    listMessages: async (req: ListMessagesReq) => methods.listMessages?.(req) ?? { messages: [] },
    listReactions: async (req: ListReactionsReq) => methods.listReactions?.(req) ?? { reactions: [] },
    listCommits: async (req: ListCommitsReq) => methods.listCommits?.(req) ?? { commits: [], nextCursor: '' },
  } as unknown as RepoConnectClient
}

describe('Connect-flavored envelope construction', () => {
  it('canonical string joins the exact 5 fields in order with newlines', () => {
    const s = canonicalString({
      procedure: procedures.UpdateRef,
      bodyDigest: 'deadbeef',
      createdAt: '2026-06-23T00:00:00.000Z',
      idempotencyKey: 'idem-1',
    })
    expect(s).toBe(
      ['mkit-write:v1', '/mkit.repo.v1.RepoService/UpdateRef', 'deadbeef', '2026-06-23T00:00:00.000Z', 'idem-1'].join(
        '\n',
      ),
    )
    expect(s.split('\n')).toHaveLength(5)
    expect(s.split('\n')[0]).toBe('mkit-write:v1')
    expect(s.split('\n')[1]).toBe(procedures.UpdateRef)
  })

  it('signs the BLAKE3 of the canonical string with Ed25519, verifiable by the server path', async () => {
    const api = await mkit()
    const env: SignedEnvelope = buildSignedEnvelope(api, SEED, {
      procedure: procedures.UpdateRef,
      bodyDigest: 'abc',
      createdAt: '2026-06-23T00:00:00.000Z',
      idempotencyKey: 'fixed-idem',
    })

    expect(env.digestHex).toBe(api.blake3_hex(new TextEncoder().encode(env.canonical)))
    expect(env.publicKeyHex).toBe(api.keypair_from_seed(SEED).pubkey_hex)

    const ok = api.ed25519_verify(hexToBytes(env.signatureHex), hexToBytes(env.digestHex), hexToBytes(env.publicKeyHex))
    expect(ok).toBe(true)

    const bad = api.ed25519_verify(
      hexToBytes(env.signatureHex),
      hexToBytes('00'.repeat(32)),
      hexToBytes(env.publicKeyHex),
    )
    expect(bad).toBe(false)
  })

  it('a deterministic envelope (fixed createdAt + idempotencyKey) is reproducible', async () => {
    const api = await mkit()
    const parts = {
      procedure: procedures.PutObject,
      bodyDigest: 'ff',
      createdAt: '2026-06-23T00:00:00.000Z',
      idempotencyKey: 'k',
    }
    const a = buildSignedEnvelope(api, SEED, parts)
    const b = buildSignedEnvelope(api, SEED, parts)
    expect(a.signatureHex).toBe(b.signatureHex)
    expect(a.digestHex).toBe(b.digestHex)
  })
})

describe('server-parity envelope contract (X-* headers + sign-callback)', () => {
  it('emits all five envelope headers, with X-Digest = the raw-body digest', async () => {
    const api = await mkit()
    const env = buildSignedEnvelope(api, SEED, {
      procedure: procedures.UpdateRef,
      bodyDigest: 'deadbeef',
      createdAt: '1700000000000',
      idempotencyKey: 'idem-1',
    })
    const h = envelopeHeaders(env)
    expect(h['X-Public-Key']).toBe(env.publicKeyHex)
    expect(h['X-Signature']).toBe(env.signatureHex)
    // X-Digest is the RAW request body digest the server recomputes — NOT the signing digest.
    expect(h['X-Digest']).toBe('deadbeef')
    expect(h['X-Created-At']).toBe('1700000000000')
    expect(h['Idempotency-Key']).toBe('idem-1')
  })

  it('defaults createdAt to epoch-millis (String(Date.now())), not ISO-8601', async () => {
    const api = await mkit()
    const env = buildSignedEnvelope(api, SEED, { procedure: procedures.PutObject, bodyDigest: 'ab' })
    // epoch-ms is all digits; ISO-8601 would contain a 'T'.
    expect(env.createdAt).toMatch(/^\d+$/)
    expect(Number.isFinite(Number(env.createdAt))).toBe(true)
  })

  it('makeSignFn signs the wasm-supplied body digest and echoes it as digestHex', async () => {
    const api = await mkit()
    const sign = makeSignFn(api, SEED, procedures.UpdateRef)
    const bodyDigest = api.blake3_hex(new TextEncoder().encode('serialized-protobuf-body'))
    const out = sign(bodyDigest)
    expect(out.digestHex).toBe(bodyDigest) // echoes the supplied raw-body digest
    expect(out.publicKeyHex).toBe(api.keypair_from_seed(SEED).pubkey_hex)
    // The signature must verify over BLAKE3(canonical(bodyDigest, ...)).
    const canonical = canonicalString({
      procedure: procedures.UpdateRef,
      bodyDigest,
      createdAt: out.createdAt,
      idempotencyKey: out.idempotencyKey,
    })
    const ok = api.ed25519_verify(
      hexToBytes(out.signatureHex),
      hexToBytes(api.blake3_hex(new TextEncoder().encode(canonical))),
      hexToBytes(out.publicKeyHex),
    )
    expect(ok).toBe(true)
  })
})

describe('mock backend / RefExpectation CAS semantics', () => {
  async function makeBackend() {
    const api = await mkit()
    return { api, backend: new MockRepoBackend(api) }
  }

  it('object writes are idempotent and content-addressed', async () => {
    const { backend } = await makeBackend()
    await backend.putObject('r', 'h', new Uint8Array([1, 2, 3]))
    await backend.putObject('r', 'h', new Uint8Array([9, 9, 9])) // no-op: same id
    expect(await backend.getObject('r', 'h')).toEqual(new Uint8Array([1, 2, 3]))
  })

  it('MISSING expectation creates, then conflicts on a second create', async () => {
    const { backend } = await makeBackend()
    await backend.updateRef('r', 'main', 'h1', 'MISSING')
    expect(await backend.getRef('r', 'main')).toBe('h1')
    await expect(backend.updateRef('r', 'main', 'h2', 'MISSING')).rejects.toBeInstanceOf(CasConflictError)
  })

  it('MATCH expectation advances on a match and conflicts on a stale parent', async () => {
    const { backend } = await makeBackend()
    await backend.updateRef('r', 'main', 'h1', 'MISSING')
    await backend.updateRef('r', 'main', 'h2', 'MATCH', 'h1')
    expect(await backend.getRef('r', 'main')).toBe('h2')
    await expect(backend.updateRef('r', 'main', 'h3', 'MATCH', 'h1')).rejects.toBeInstanceOf(CasConflictError)
  })

  it('ANY expectation sets unconditionally', async () => {
    const { backend } = await makeBackend()
    await backend.updateRef('r', 'main', 'h1', 'MISSING')
    await backend.updateRef('r', 'main', 'hX', 'ANY')
    expect(await backend.getRef('r', 'main')).toBe('hX')
  })

  it('listRefs filters by prefix', async () => {
    const { backend } = await makeBackend()
    await backend.updateRef('r', 'main', 'h1', 'ANY')
    await backend.updateRef('r', 'tags/v1', 'h2', 'ANY')
    const heads = await backend.listRefs('r', 'tags/')
    expect(heads).toEqual([{ name: 'tags/v1', objectIdHex: 'h2' }])
  })

  it('WatchRefs streams ref updates to subscribers, honouring prefix + unsubscribe', async () => {
    const { backend } = await makeBackend()
    const seen: string[] = []
    const unsub = backend.watchRefs('r', '', (u) => seen.push(u.objectIdHex))
    await backend.updateRef('r', 'main', 'h1', 'MISSING')
    expect(seen).toEqual(['h1'])
    unsub()
    await backend.updateRef('r', 'main', 'h2', 'MATCH', 'h1')
    expect(seen).toEqual(['h1']) // unsubscribed
  })
})

describe('WasmRepoBackend.commitLog walks the shared `main` ref', () => {
  // A fake commit graph: hash → { message, signer, firstParent }. The walk
  // follows firstParent from the room's `main` head, decoding each node.
  type Node = { message: string; signer: string; parent?: string }

  /** Build a fake Connect client + api over a static commit graph. */
  function harness(opts: {
    head: string | undefined
    graph: Record<string, Node>
    /** Counts decode + object reads so we can assert the head-keyed cache. */
    counters: { decode: number; getObject: number; getRef: number }
    /** Optional extra ref → head map (beyond `main`) for branch tests. */
    refs?: Record<string, string>
  }) {
    const { graph, counters } = opts
    let head = opts.head
    const refs = opts.refs ?? {}
    // The worker now owns the commit-log walk (ListCommits), so the client just
    // calls `listCommits` and renders the denormalized metadata. The harness
    // serves that walk straight from `graph`; `listCommitsCalls` lets the
    // head-keyed cache tests assert round-trips the way they used to with decode.
    const listCommitsCalls: string[] = []

    const client = fakeClient({
      getRef: ({ name }) => {
        counters.getRef++
        const v = name === 'main' ? head : refs[name]
        return v ? { exists: true, objectId: hexToBytes(v) } : { exists: false, objectId: new Uint8Array(0) }
      },
      listCommits: ({ ref, startId, pageSize }) => {
        listCommitsCalls.push(ref)
        const startIdHex = bytesToHex(startId)
        let cur: string | undefined = startIdHex || (ref === 'main' ? head : refs[ref])
        const commits: Array<{
          hash: string
          parent: string
          authorPubkey: string
          message: string
          createdAtUnix: bigint
          kind: string
          sourcesJson: string
        }> = []
        const seen = new Set<string>()
        while (cur && commits.length < pageSize && !seen.has(cur)) {
          seen.add(cur)
          const node = graph[cur]
          if (!node) break // not indexed → stop (the real worker backfills from R2)
          commits.push({
            hash: cur,
            parent: node.parent ?? '',
            authorPubkey: node.signer,
            message: node.message,
            createdAtUnix: 1n,
            kind: 'commit',
            sourcesJson: '[]',
          })
          cur = node.parent
        }
        return { commits, nextCursor: cur && commits.length >= pageSize ? cur : '' }
      },
      listRefs: ({ prefix }) => {
        const all = [
          ...(head ? [{ name: 'main', objectId: hexToBytes(head) }] : []),
          ...Object.entries(refs).map(([name, h]) => ({ name, objectId: hexToBytes(h) })),
        ]
        return { refs: all.filter((r) => r.name.startsWith(prefix)) }
      },
    })

    const api = {
      // The walk now routes by object_kind first; every node in these
      // graphs is a commit, so report "commit" for any known hash.
      object_kind: (bytes: Uint8Array) => {
        const hash = new TextDecoder().decode(bytes)
        if (!graph[hash]) throw new Error('unknown object')
        return 'commit'
      },
      commit_decode: (bytes: Uint8Array) => {
        counters.decode++
        const hash = new TextDecoder().decode(bytes)
        const node = graph[hash]
        if (!node) throw new Error('not a commit')
        return {
          message: node.message,
          signer_hex: node.signer,
          timestamp: 1n,
          tree_hex: 'aa'.repeat(32),
          signature_hex: 'bb'.repeat(64),
          parent_count: node.parent ? 1 : 0,
          parent: (i: number) => (i === 0 ? node.parent : undefined),
        }
      },
    } as unknown as MkitApi

    const backend = new WasmRepoBackend(NO_WRITES, api, () => null, 'http://x', client)
    return { backend, listCommitsCalls, setHead: (h: string | undefined) => (head = h) }
  }

  it('returns [] when the room has no `main` ref', async () => {
    const counters = { decode: 0, getObject: 0, getRef: 0 }
    const { backend } = harness({ head: undefined, graph: {}, counters })
    expect(await backend.commitLog('room')).toEqual([])
    expect(counters.getObject).toBe(0)
  })

  it('walks first-parents newest-first, decoding real message + signer', async () => {
    const counters = { decode: 0, getObject: 0, getRef: 0 }
    const graph = {
      c3: { message: 'third', signer: 'sig3', parent: 'c2' },
      c2: { message: 'second', signer: 'sig2', parent: 'c1' },
      c1: { message: 'first', signer: 'sig1' },
    }
    const { backend } = harness({ head: 'c3', graph, counters })
    const log = await backend.commitLog('room')
    expect(log.map((e) => e.hash)).toEqual(['c3', 'c2', 'c1']) // newest-first
    expect(log.map((e) => e.message)).toEqual(['third', 'second', 'first'])
    expect(log.map((e) => e.authorPubkey)).toEqual(['sig3', 'sig2', 'sig1'])
    expect(log.every((e) => e.ref === 'main')).toBe(true)
  })

  it('caches by head: a repeat call does not re-walk, a new head does', async () => {
    const counters = { decode: 0, getObject: 0, getRef: 0 }
    const graph = {
      c2: { message: 'second', signer: 's', parent: 'c1' },
      c1: { message: 'first', signer: 's' },
    }
    const h = harness({ head: 'c1', graph, counters })

    await h.backend.commitLog('room') // walks c1
    expect(h.listCommitsCalls.length).toBe(1)

    await h.backend.commitLog('room') // same head → cache hit, no round-trip
    expect(h.listCommitsCalls.length).toBe(1)

    h.setHead('c2') // a peer pushed → head advanced → re-walk
    const log = await h.backend.commitLog('room')
    expect(log.map((e) => e.hash)).toEqual(['c2', 'c1'])
    expect(h.listCommitsCalls.length).toBe(2)
  })

  it('stops the walk on a missing object rather than throwing', async () => {
    const counters = { decode: 0, getObject: 0, getRef: 0 }
    // head points at c2 whose parent c1 is absent from the object store.
    const graph = { c2: { message: 'second', signer: 's', parent: 'c1' } }
    const { backend } = harness({ head: 'c2', graph, counters })
    const log = await backend.commitLog('room')
    expect(log.map((e) => e.hash)).toEqual(['c2'])
  })

  it('walks a non-`main` ref independently, tagging entries with that ref', async () => {
    const counters = { decode: 0, getObject: 0, getRef: 0 }
    // Ref target hashes must be valid hex (they round-trip through real bytes on the wire, unlike the plain-string
    // CommitEntry.hash/message/signer fields) — 'a1'/'a2' stand in for what were 'm1'/'m2' before this backend moved
    // GetRef/ListRefs onto the generated Connect client.
    const graph = {
      a2: { message: 'main 2', signer: 's', parent: 'a1' },
      a1: { message: 'main 1', signer: 's' },
      f1: { message: 'feature spike', signer: 's' },
    }
    const { backend } = harness({ head: 'a2', graph, counters, refs: { feature: 'f1' } })

    const main = await backend.commitLog('room', 'main')
    expect(main.map((e) => e.hash)).toEqual(['a2', 'a1'])
    expect(main.every((e) => e.ref === 'main')).toBe(true)

    const feature = await backend.commitLog('room', 'feature')
    expect(feature.map((e) => e.hash)).toEqual(['f1'])
    expect(feature.every((e) => e.ref === 'feature')).toBe(true)
  })

  it('caches per `room::ref`: switching branches does not invalidate the other', async () => {
    const counters = { decode: 0, getObject: 0, getRef: 0 }
    const graph = {
      a1: { message: 'main', signer: 's' },
      f1: { message: 'feature', signer: 's' },
    }
    const { backend, listCommitsCalls } = harness({ head: 'a1', graph, counters, refs: { feature: 'f1' } })

    await backend.commitLog('room', 'main')
    await backend.commitLog('room', 'feature')
    expect(listCommitsCalls.length).toBe(2) // each ref walked once

    // Repeat calls hit each ref's own cache — no extra round-trips.
    await backend.commitLog('room', 'main')
    await backend.commitLog('room', 'feature')
    expect(listCommitsCalls.length).toBe(2)
  })

  it('decodes a single commit by hash for the detail view (tree + signature)', async () => {
    // #505 PR 5/5 (Pattern 6): the previous version of this test only
    // round-tripped opaque bytes through the fake `harness` above and
    // never actually decoded anything — a real gap wearing a
    // coverage-claiming name. Use the REAL wasm module + a real signed
    // commit (mirroring `CommitDetail` in repo-browser.tsx, which fetches
    // via `get_object` then decodes with `commit_decode`) so `tree_hex`
    // and `signature_hex` are genuinely exercised, not asserted against
    // a mock's own hardcoded return value.
    const api = await mkit()
    const TREE = '33'.repeat(32)
    const commit = api.commit_encode_and_sign(TREE, '', 'detail me', 1n, SEED)

    const client = fakeClient({
      getObject: ({ objectId }) =>
        bytesToHex(objectId) === commit.hash_hex
          ? { found: true, bytes: commit.bytes }
          : { found: false, bytes: new Uint8Array(0) },
    })
    const backend = new WasmRepoBackend(NO_WRITES, api, () => null, 'http://x', client)

    // The detail view fetches the object then decodes it client-side.
    const bytes = await backend.getObject('room', commit.hash_hex)
    expect(bytes).not.toBeNull()
    expect(bytes).toEqual(commit.bytes)

    const info = api.commit_decode(bytes!)
    expect(info.message).toBe('detail me')
    expect(info.tree_hex).toBe(TREE)
    // A real ed25519 signature: 64 bytes, hex-encoded.
    expect(info.signature_hex).toMatch(/^[0-9a-f]{128}$/)
  })
})

describe('listRefs exposes all branches in the room', () => {
  it('WasmRepoBackend.listRefs returns main + branches', async () => {
    const client = fakeClient({
      listRefs: ({ prefix }) => ({
        refs: [
          { name: 'main', objectId: hexToBytes('a1') },
          { name: 'feature', objectId: hexToBytes('f1') },
        ].filter((r) => r.name.startsWith(prefix)),
      }),
    })
    const backend = new WasmRepoBackend(NO_WRITES, {} as unknown as MkitApi, () => null, 'http://x', client)
    const refs = await backend.listRefs('room')
    expect(refs.map((r) => r.name).toSorted()).toEqual(['feature', 'main'])
    const filtered = await backend.listRefs('room', 'feat')
    expect(filtered.map((r) => r.name)).toEqual(['feature'])
  })

  it('MockRepoBackend.commitLog filters by ref so each branch shows its own chain', async () => {
    const api = await mkit()
    const backend = new MockRepoBackend(api)
    backend.seedForeignCommit('room', {
      hash: 'h-main',
      message: 'on main',
      authorPubkey: 'a',
      ref: 'main',
      createdAt: '1',
    })
    backend.seedForeignCommit('room', {
      hash: 'h-feat',
      message: 'on feature',
      authorPubkey: 'a',
      ref: 'feature',
      createdAt: '2',
    })
    expect((await backend.commitLog('room', 'main')).map((e) => e.hash)).toEqual(['h-main'])
    expect((await backend.commitLog('room', 'feature')).map((e) => e.hash)).toEqual(['h-feat'])
    // Both refs are listed in the panel.
    expect((await backend.listRefs('room')).map((r) => r.name).toSorted()).toEqual(['feature', 'main'])
  })
})

describe('MockRepoBackend.seedDemo populates the offline demo state', () => {
  it('seeds refs (main + feature + a fork), a main log, and the remix entry', async () => {
    const api = await mkit()
    const backend = new MockRepoBackend(api)
    backend.seedDemo('room')

    // Refs: two foreign commits on main + one on feature + one forks/ ref.
    const refs = await backend.listRefs('room')
    const names = refs.map((r) => r.name)
    expect(names).toContain('main')
    expect(names).toContain('feature')
    expect(names.some((n) => isForkRef(n))).toBe(true)

    // main log has the two foreign commits, newest-first.
    const mainLog = await backend.commitLog('room', 'main')
    expect(mainLog.map((e) => e.message)).toEqual(['ship it 🚀', 'hello from another tab'])

    // feature ref carries its own commit.
    const featLog = await backend.commitLog('room', 'feature')
    expect(featLog.map((e) => e.message)).toEqual(['spike on a feature branch'])

    // The fork ref's head is a remix carrying its upstream source.
    const forkRef = names.find((n) => isForkRef(n))!
    const forkLog = await backend.commitLog('room', forkRef)
    expect(forkLog).toHaveLength(1)
    expect(forkLog[0]!.kind).toBe('remix')
    expect(forkLog[0]!.sources?.length).toBe(1)

    // The remix's upstream is the FIRST foreign commit (on main).
    const upstream = forkLog[0]!.sources![0]!.commitHashHex
    const firstMain = mainLog.find((e) => e.message === 'hello from another tab')!
    expect(upstream).toBe(firstMain.hash)

    // The seeded objects are stored so the offline detail view can decode them.
    expect(await backend.getObject('room', firstMain.hash)).not.toBeNull()
    expect(await backend.getObject('room', forkLog[0]!.hash)).not.toBeNull()
  })
})

describe('fork ref scheme', () => {
  it('forkRefName keys a fork by the upstream short hash under forks/ (legacy, no forker)', () => {
    const upstream = 'abcdef0123456789'.repeat(4) // 64 hex
    const ref = forkRefName(upstream)
    expect(ref).toBe('forks/abcdef012345')
    expect(isForkRef(ref)).toBe(true)
    expect(isForkRef('main')).toBe(false)
    expect(isForkRef('feature')).toBe(false)
  })

  it('keys a fork by BOTH the upstream short hash AND the forker short pubkey', () => {
    const upstream = 'abcdef0123456789'.repeat(4)
    const forker = '1122334455667788'.repeat(4)
    const ref = forkRefName(upstream, forker)
    expect(ref).toBe('forks/abcdef012345-112233445566')
    expect(isForkRef(ref)).toBe(true)
  })

  it('two different forkers of the SAME commit get DISTINCT refs (no collision)', () => {
    const upstream = 'abcdef0123456789'.repeat(4)
    const alice = 'aa'.repeat(32)
    const bob = 'bb'.repeat(32)
    expect(forkRefName(upstream, alice)).not.toBe(forkRefName(upstream, bob))
  })

  it('the same forker re-forking the same commit reuses ITS ref (so the chain advances)', () => {
    const upstream = 'abcdef0123456789'.repeat(4)
    const forker = 'dd'.repeat(32)
    expect(forkRefName(upstream, forker)).toBe(forkRefName(upstream, forker))
  })
})

describe('fork push: fresh ref → MISSING, existing ref → MATCH chains (no orphan)', () => {
  // The component builds the remix with parent = (current head ?? '') and
  // pushes via usePushCommit, which picks MISSING when parentHash is empty and
  // MATCH otherwise. Here we replay that decision against the mock backend to
  // prove a first fork creates the ref and a second fork on the SAME ref
  // chains onto the prior head (CAS MATCH) rather than overwriting it.
  async function pushRemix(
    backend: MockRepoBackend,
    room: string,
    ref: string,
    hash: string,
    parentHash: string,
  ): Promise<void> {
    await backend.putObject(room, hash, new TextEncoder().encode(hash))
    const expectation = parentHash ? 'MATCH' : 'MISSING'
    await backend.updateRef(room, ref, hash, expectation, parentHash || undefined)
  }

  it('first fork of a fresh ref uses MISSING and creates the ref', async () => {
    const api = await mkit()
    const backend = new MockRepoBackend(api)
    const ref = forkRefName('abcdef0123456789'.repeat(4), 'aa'.repeat(32))
    // The component reads head first; a fresh ref has none → parent '' → MISSING.
    const head = await backend.getRef('room', ref)
    expect(head).toBeNull()
    await pushRemix(backend, 'room', ref, 'remix1', head ?? '')
    expect(await backend.getRef('room', ref)).toBe('remix1')
  })

  it('a second fork on the existing ref chains onto the prior head (MATCH), not orphaning it', async () => {
    const api = await mkit()
    const backend = new MockRepoBackend(api)
    const ref = forkRefName('abcdef0123456789'.repeat(4), 'aa'.repeat(32))

    await pushRemix(backend, 'room', ref, 'remix1', '') // MISSING → create
    const head1 = await backend.getRef('room', ref)
    expect(head1).toBe('remix1')

    // Second fork: parent = current head → MATCH advances the SAME ref.
    await pushRemix(backend, 'room', ref, 'remix2', head1 ?? '')
    expect(await backend.getRef('room', ref)).toBe('remix2')

    // A stale parent (orphan attempt) would have conflicted under MATCH.
    await expect(pushRemix(backend, 'room', ref, 'remix3', 'remix1')).rejects.toBeInstanceOf(CasConflictError)
  })
})

describe('decodeLogObject routes commits vs remixes via object_kind', () => {
  const SEED2 = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
  const TREE = '11'.repeat(32)
  const UPSTREAM_ID = '22'.repeat(32)

  it('a commit decodes as kind="commit" with its first parent', async () => {
    const api = await mkit()
    const root = api.commit_encode_and_sign(TREE, '', 'root', 1n, SEED2)
    const child = api.commit_encode_and_sign(TREE, root.hash_hex, 'child', 2n, SEED2)

    const res = decodeLogObject(api, child.bytes, child.hash_hex, 'main')
    expect(res).not.toBeNull()
    expect(res!.entry.kind).toBe('commit')
    expect(res!.entry.message).toBe('child')
    expect(res!.entry.sources).toBeUndefined()
    expect(res!.firstParent).toBe(root.hash_hex)
  })

  it('a remix decodes as kind="remix" carrying its upstream source', async () => {
    const api = await mkit()
    const upstream = api.commit_encode_and_sign(TREE, '', 'upstream', 1n, SEED2)
    const sourcesJson = JSON.stringify([{ upstream_id_hex: UPSTREAM_ID, commit_hash_hex: upstream.hash_hex }])
    const remix = api.remix_encode_and_sign(TREE, '', sourcesJson, 'forked it', 2n, SEED2)

    const res = decodeLogObject(api, remix.bytes, remix.hash_hex, forkRefName(upstream.hash_hex))
    expect(res).not.toBeNull()
    expect(res!.entry.kind).toBe('remix')
    expect(res!.entry.message).toBe('forked it')
    expect(res!.entry.sources).toEqual([{ upstreamIdHex: UPSTREAM_ID, commitHashHex: upstream.hash_hex }])
    // Root remix → no parent to continue the walk.
    expect(res!.firstParent).toBeUndefined()
  })

  it('returns null on non-commit/remix bytes so the walk stops cleanly', async () => {
    const api = await mkit()
    expect(decodeLogObject(api, new Uint8Array([1, 2, 3]), 'h', 'main')).toBeNull()
  })

  it('object_kind separates a commit from a remix', async () => {
    const api = await mkit()
    const commit = api.commit_encode_and_sign(TREE, '', 'c', 1n, SEED2)
    const sourcesJson = JSON.stringify([{ upstream_id_hex: UPSTREAM_ID, commit_hash_hex: commit.hash_hex }])
    const remix = api.remix_encode_and_sign(TREE, '', sourcesJson, 'r', 2n, SEED2)
    expect(api.object_kind(commit.bytes)).toBe('commit')
    expect(api.object_kind(remix.bytes)).toBe('remix')
  })
})

describe('WasmRepoBackend.commitLog walks a fork ref of remixes', () => {
  it('routes a remix head through remix_decode and tags entries kind="remix"', async () => {
    const api = await mkit()
    const SEED2 = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
    const TREE = '11'.repeat(32)
    const UPSTREAM_ID = '22'.repeat(32)

    const upstream = api.commit_encode_and_sign(TREE, '', 'upstream', 1n, SEED2)
    const sourcesJson = JSON.stringify([{ upstream_id_hex: UPSTREAM_ID, commit_hash_hex: upstream.hash_hex }])
    const remix = api.remix_encode_and_sign(TREE, '', sourcesJson, 'a fork', 2n, SEED2)
    const forkRef = forkRefName(upstream.hash_hex)

    // The worker's ListCommits index serves the remix's denormalized metadata (kind + sources), so the client
    // renders it with no client-side decode / no GetObject round-trip.
    const client = fakeClient({
      getRef: ({ name }) =>
        name === forkRef
          ? { exists: true, objectId: hexToBytes(remix.hash_hex) }
          : { exists: false, objectId: new Uint8Array(0) },
      listCommits: () => ({
        commits: [
          {
            hash: remix.hash_hex,
            parent: '',
            authorPubkey: 'sig',
            message: 'a fork',
            createdAtUnix: 2n,
            kind: 'remix',
            sourcesJson: JSON.stringify([[UPSTREAM_ID, upstream.hash_hex]]),
          },
        ],
        nextCursor: '',
      }),
      listRefs: ({ prefix }) => ({
        refs: [{ name: forkRef, objectId: hexToBytes(remix.hash_hex) }].filter((r) => r.name.startsWith(prefix)),
      }),
    })

    const backend = new WasmRepoBackend(NO_WRITES, api, () => null, 'http://x', client)
    const log = await backend.commitLog('room', forkRef)
    // Root remix → the walk yields just the remix (its parents are empty).
    expect(log.map((e) => e.hash)).toEqual([remix.hash_hex])
    expect(log[0]!.kind).toBe('remix')
    expect(log[0]!.message).toBe('a fork')
    expect(log[0]!.sources).toEqual([{ upstreamIdHex: UPSTREAM_ID, commitHashHex: upstream.hash_hex }])
  })
})

describe('usePushCommit optimistic prepend (TanStack Query)', () => {
  const SEED2 = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
  const TREE = '11'.repeat(32)
  const ROOM = 'room'
  const REF = 'main'

  /**
   * A backend whose updateRef we can make succeed or reject on demand, and (optionally) block on an external gate so we
   * can assert the optimistic prepend is visible while the push is still in flight.
   */
  function makeControllableBackend(opts: { failUpdate?: boolean; gate?: Promise<void> }) {
    return stubBackend({
      updateRef: async () => {
        if (opts.gate) await opts.gate
        if (opts.failUpdate) throw new CasConflictError(null)
      },
    })
  }

  async function makePushArgs(message: string): Promise<PushArgs> {
    const api = await mkit()
    const commit = api.commit_encode_and_sign(TREE, '', message, 7n, SEED2)
    return {
      api,
      seedHex: SEED2,
      room: ROOM,
      ref: REF,
      commitBytes: commit.bytes,
      commitHash: commit.hash_hex,
      message,
      parentHash: '',
    }
  }

  it('prepends the new commit to the log query data while the push is still in flight', async () => {
    // Gate updateRef so the mutation cannot settle until we release it — this
    // makes "the entry is visible before the push resolves" a real assertion.
    let release: () => void = () => {}
    const gate = new Promise<void>((r) => {
      release = r
    })
    const backend = makeControllableBackend({ gate })
    const qc = new QueryClient()
    const logKey = repoKeys.log(ROOM, REF)
    qc.setQueryData<CommitLogEntry[]>(logKey, []) // an empty walked log

    const args = await makePushArgs('optimistic me')
    // The backend is INJECTED (no global) — the mutation writes through it.
    const observer = new MutationObserver(qc, pushCommitMutationOptions(qc, backend))

    const p = observer.mutate(args)
    // Let onMutate (cancelQueries → setQueryData) run; the push itself is still
    // blocked on `gate`, so the entry below is purely optimistic.
    await new Promise((r) => setTimeout(r, 0))

    const optimistic = qc.getQueryData<CommitLogEntry[]>(logKey)
    expect(optimistic?.map((e) => e.hash)).toEqual([args.commitHash])
    expect(optimistic?.[0]?.message).toBe('optimistic me')
    // Walk-parity: signer + ISO createdAt come from the decoded bytes.
    const decoded = decodeLogObject(args.api, args.commitBytes, args.commitHash, REF)
    expect(optimistic?.[0]?.authorPubkey).toBe(decoded?.entry.authorPubkey)
    expect(optimistic?.[0]?.createdAt).toBe(decoded?.entry.createdAt)

    release() // unblock the push
    await p // let it settle
  })

  it('rolls the optimistic entry back when the push is rejected', async () => {
    const backend = makeControllableBackend({ failUpdate: true })
    const qc = new QueryClient()
    const logKey = repoKeys.log(ROOM, REF)
    const prior: CommitLogEntry[] = [
      { hash: 'old', message: 'prior', authorPubkey: 'a', ref: REF, createdAt: '1970-01-01T00:00:01.000Z' },
    ]
    qc.setQueryData<CommitLogEntry[]>(logKey, prior)

    const args = await makePushArgs('will fail')
    const observer = new MutationObserver(qc, pushCommitMutationOptions(qc, backend))
    await expect(observer.mutate(args)).rejects.toBeInstanceOf(CasConflictError)

    // onError restored the snapshot — the optimistic entry is gone.
    expect(qc.getQueryData<CommitLogEntry[]>(logKey)).toEqual(prior)
  })

  it('writes through the INJECTED backend (putObject + updateRef), not a global', async () => {
    // The backend is an explicit param: the mutation must call THIS instance.
    const backend = makeControllableBackend({})
    const putObject = vi.spyOn(backend, 'putObject')
    const updateRef = vi.spyOn(backend, 'updateRef')
    const qc = new QueryClient()
    qc.setQueryData<CommitLogEntry[]>(repoKeys.log(ROOM, REF), [])

    const args = await makePushArgs('inject me')
    const observer = new MutationObserver(qc, pushCommitMutationOptions(qc, backend))
    await observer.mutate(args)

    expect(putObject).toHaveBeenCalledWith(ROOM, args.commitHash, args.commitBytes)
    // First object on the ref (parentHash '') → MISSING expectation.
    expect(updateRef).toHaveBeenCalledWith(ROOM, REF, args.commitHash, 'MISSING', undefined)
  })
})

describe('WasmRepoBackend object cache (content-addressed → cache forever)', () => {
  function spyClient(store: Record<string, Uint8Array>) {
    const calls: string[] = []
    const client = fakeClient({
      getObject: ({ objectId }) => {
        const hex = bytesToHex(objectId)
        calls.push(hex)
        const bytes = store[hex]
        return bytes ? { found: true, bytes } : { found: false, bytes: new Uint8Array(0) }
      },
    })
    return { client, calls }
  }

  it('getObject for the same hash issues exactly ONE underlying client call', async () => {
    const bytes = new Uint8Array([1, 2, 3])
    const { client, calls } = spyClient({ a1: bytes })
    const backend = new WasmRepoBackend(NO_WRITES, {} as unknown as MkitApi, () => null, 'http://x', client)

    const a = await backend.getObject('room', 'a1')
    const b = await backend.getObject('room', 'a1')
    expect(a).toEqual(bytes)
    expect(b).toEqual(bytes)
    expect(calls).toEqual(['a1']) // second read served from cache
  })

  it('getObject for a DIFFERENT hash still fetches', async () => {
    const { client, calls } = spyClient({ a1: new Uint8Array([1]), a2: new Uint8Array([2]) })
    const backend = new WasmRepoBackend(NO_WRITES, {} as unknown as MkitApi, () => null, 'http://x', client)
    await backend.getObject('room', 'a1')
    await backend.getObject('room', 'a2')
    await backend.getObject('room', 'a1') // cached
    expect(calls).toEqual(['a1', 'a2'])
  })
})

describe('WasmRepoBackend incremental commit-log walk', () => {
  type Node = { message: string; signer: string; parent?: string }

  function harness(graph: Record<string, Node>, initialHead: string) {
    let head = initialHead
    const getObjectCalls: string[] = []
    const listCommitsCalls: string[] = []
    const client = fakeClient({
      getRef: () => ({ exists: true, objectId: hexToBytes(head) }),
      getObject: ({ objectId }) => {
        const hash = bytesToHex(objectId)
        getObjectCalls.push(hash)
        return graph[hash]
          ? { found: true, bytes: new TextEncoder().encode(hash) }
          : { found: false, bytes: new Uint8Array(0) }
      },
      listCommits: ({ startId, pageSize }) => {
        const startIdHex = bytesToHex(startId)
        listCommitsCalls.push(startIdHex || head)
        let cur: string | undefined = startIdHex || head
        const commits: Array<{
          hash: string
          parent: string
          authorPubkey: string
          message: string
          createdAtUnix: bigint
          kind: string
          sourcesJson: string
        }> = []
        const seen = new Set<string>()
        while (cur && commits.length < pageSize && !seen.has(cur)) {
          seen.add(cur)
          const row: Node | undefined = graph[cur]
          if (!row) break
          commits.push({
            hash: cur,
            parent: row.parent ?? '',
            authorPubkey: row.signer,
            message: row.message,
            createdAtUnix: 1n,
            kind: 'commit',
            sourcesJson: '[]',
          })
          cur = row.parent
        }
        return { commits, nextCursor: cur && commits.length >= pageSize ? cur : '' }
      },
    })
    const api = {
      object_kind: (bytes: Uint8Array) => {
        const hash = new TextDecoder().decode(bytes)
        if (!graph[hash]) throw new Error('unknown')
        return 'commit'
      },
      commit_decode: (bytes: Uint8Array) => {
        const hash = new TextDecoder().decode(bytes)
        const node = graph[hash]!
        return {
          message: node.message,
          signer_hex: node.signer,
          timestamp: 1n,
          tree_hex: 'aa'.repeat(32),
          signature_hex: 'bb'.repeat(64),
          parent_count: node.parent ? 1 : 0,
          parent: (i: number) => (i === 0 ? node.parent : undefined),
        }
      },
    } as unknown as MkitApi
    const backend = new WasmRepoBackend(NO_WRITES, api, () => null, 'http://x', client)
    return { backend, getObjectCalls, listCommitsCalls, setHead: (h: string) => (head = h) }
  }

  it('after a cached 3-commit walk, a 4th-commit re-walk is one round-trip that splices the cached tail', async () => {
    const graph: Record<string, Node> = {
      c3: { message: 'c3', signer: 's', parent: 'c2' },
      c2: { message: 'c2', signer: 's', parent: 'c1' },
      c1: { message: 'c1', signer: 's' },
    }
    const h = harness(graph, 'c3')

    const first = await h.backend.commitLog('room')
    expect(first.map((e) => e.hash)).toEqual(['c3', 'c2', 'c1'])

    // Push a 4th commit on top → head advances.
    graph.c4 = { message: 'c4', signer: 's', parent: 'c3' }
    h.setHead('c4')

    h.listCommitsCalls.length = 0
    const second = await h.backend.commitLog('room')
    expect(second.map((e) => e.hash)).toEqual(['c4', 'c3', 'c2', 'c1']) // newest-first, full chain
    expect(h.listCommitsCalls.length).toBe(1) // one round-trip; the cached tail (c3,c2,c1) is spliced, not re-walked
  })
})

describe('enabled-gating keeps repo queries pending until a backend is ready', () => {
  it('a query with enabled:false never calls its queryFn and stays pending; flipping enabled runs it', async () => {
    const qc = new QueryClient()
    const queryFn = vi.fn(async () => ['ref-a'])

    // Mirror the dependent-query options shape the hooks build: keyed by repoKeys,
    // gated by `enabled`, with the same queryFn the hook would call.
    const buildOptions = (ready: boolean) => ({
      queryKey: repoKeys.refs('room', ''),
      queryFn,
      enabled: ready,
    })

    const observer = new QueryObserver(qc, buildOptions(false))
    const seen: string[] = []
    const unsub = observer.subscribe((r) => seen.push(r.status))

    await new Promise((r) => setTimeout(r, 0))
    expect(queryFn).not.toHaveBeenCalled() // disabled → queryFn never runs
    expect(observer.getCurrentResult().status).toBe('pending') // stays pending → skeleton

    // Flip enabled true (backend ready) → the query runs.
    observer.setOptions(buildOptions(true))
    await vi.waitFor(() => expect(queryFn).toHaveBeenCalledTimes(1))
    await vi.waitFor(() => expect(observer.getCurrentResult().status).toBe('success'))
    expect(observer.getCurrentResult().data).toEqual(['ref-a'])

    unsub()
    expect(seen[0]).toBe('pending')
  })

  it('useObject gating predicate is !!backend && !!hash (preserves the hash guard)', () => {
    const enabledFor = (hasBackend: boolean, hash: string | null) => hasBackend && !!hash
    expect(enabledFor(false, 'abc')).toBe(false) // no backend
    expect(enabledFor(true, null)).toBe(false) // no hash
    expect(enabledFor(true, '')).toBe(false) // empty hash
    expect(enabledFor(true, 'abc')).toBe(true) // both → enabled
  })
})

describe('keepPreviousData smooths ref switching (useCommitLog / useRefs)', () => {
  it('keepPreviousData keeps prior data on a key change until the new fetch resolves', async () => {
    const qc = new QueryClient()
    const logKeyMain = repoKeys.log('room', 'main')
    const logKeyFeat = repoKeys.log('room', 'feature')

    // Seed "main" as already-loaded.
    qc.setQueryData<CommitLogEntry[]>(logKeyMain, [
      { hash: 'm1', message: 'on main', authorPubkey: 'a', ref: 'main', createdAt: '1' },
    ])

    let resolveFeat: (v: CommitLogEntry[]) => void = () => {}
    const featData = new Promise<CommitLogEntry[]>((r) => {
      resolveFeat = r
    })

    const observer = new QueryObserver<CommitLogEntry[]>(qc, {
      queryKey: logKeyMain,
      queryFn: async () => qc.getQueryData<CommitLogEntry[]>(logKeyMain) ?? [],
      placeholderData: keepPreviousData,
      enabled: true,
    })
    const unsub = observer.subscribe(() => {})
    await vi.waitFor(() => expect(observer.getCurrentResult().data?.[0]?.hash).toBe('m1'))

    // Switch to "feature" — its fetch is in flight (pending) but keepPreviousData
    // keeps main's list visible (isPlaceholderData true) rather than flashing empty.
    observer.setOptions({
      queryKey: logKeyFeat,
      queryFn: () => featData,
      placeholderData: keepPreviousData,
      enabled: true,
    })
    await new Promise((r) => setTimeout(r, 0))
    const during = observer.getCurrentResult()
    expect(during.data?.[0]?.hash).toBe('m1') // prior data retained
    expect(during.isPlaceholderData).toBe(true)

    // Once the new ref resolves, its data replaces the placeholder.
    resolveFeat([{ hash: 'f1', message: 'on feature', authorPubkey: 'a', ref: 'feature', createdAt: '2' }])
    await vi.waitFor(() => expect(observer.getCurrentResult().data?.[0]?.hash).toBe('f1'))
    await vi.waitFor(() => expect(observer.getCurrentResult().isPlaceholderData).toBe(false))

    unsub()
  })
})

describe('parseActivityFrame dispatches commit vs chat frames', () => {
  it('parses a server commit frame (kind=commit, snake_case)', () => {
    const f = parseActivityFrame(
      JSON.stringify({ kind: 'commit', name: 'main', object_id: 'abc', author_pubkey: 'pk' }),
    )
    expect(f).toEqual({ kind: 'commit', ref: { name: 'main', objectIdHex: 'abc', authorPubkeyHex: 'pk' } })
  })

  it('parses a legacy commit frame with no kind (back-compat with deployed clients)', () => {
    const f = parseActivityFrame(JSON.stringify({ name: 'main', object_id: 'abc' }))
    expect(f?.kind).toBe('commit')
  })

  it('parses a chat frame (kind=chat, snake_case)', () => {
    const f = parseActivityFrame(
      JSON.stringify({ kind: 'chat', message_id: 'mid', author_pubkey: 'pk', text: 'gm', created_at: 123, seq: 7 }),
    )
    expect(f).toEqual({
      kind: 'chat',
      message: { messageIdHex: 'mid', authorPubkeyHex: 'pk', text: 'gm', createdAt: 123, seq: 7 },
    })
  })

  it('returns null for malformed or incomplete frames', () => {
    expect(parseActivityFrame('not json')).toBeNull()
    expect(parseActivityFrame(JSON.stringify({ name: 'main' }))).toBeNull() // commit missing object id
    expect(parseActivityFrame(42 as unknown)).toBeNull()
  })
})

describe('MockRepoBackend chat: post / list / watch', () => {
  async function makeBackend() {
    const api = await mkit()
    return { api, backend: new MockRepoBackend(api, () => SEED) }
  }

  it('postMessage stores a content-addressed signed message; listMessages returns oldest-first', async () => {
    const { backend } = await makeBackend()
    const a = await backend.postMessage('lobby', 'gm')
    const b = await backend.postMessage('lobby', 'hello')
    expect(a.accepted).toBe(true)
    expect(a.messageIdHex).toMatch(/^[0-9a-f]{64}$/)
    expect(a.messageIdHex).not.toBe(b.messageIdHex)

    const msgs: ChatMessageEntry[] = await backend.listMessages('lobby')
    expect(msgs.map((m) => m.text)).toEqual(['gm', 'hello']) // oldest-first
    expect(msgs[0]!.seq).toBeLessThan(msgs[1]!.seq)
    expect(msgs[0]!.authorPubkeyHex).toMatch(/^[0-9a-f]{64}$/)
  })

  it('two identical-text posts get DISTINCT ids (per-post signed nonce)', async () => {
    // Each send folds a unique nonce into the content hash, so the same author
    // posting the same text twice yields two different message objects — the fix
    // that lets reactions key on the plain id without leaking across reposts.
    const { backend } = await makeBackend()
    const a = await backend.postMessage('lobby', 'same')
    const b = await backend.postMessage('lobby', 'same')
    expect(a.messageIdHex).toMatch(/^[0-9a-f]{64}$/)
    expect(a.messageIdHex).not.toBe(b.messageIdHex)
  })

  it('rejects empty and over-long messages (≤280 chars)', async () => {
    const { backend } = await makeBackend()
    await expect(backend.postMessage('lobby', '   ')).rejects.toThrow()
    await expect(backend.postMessage('lobby', 'x'.repeat(281))).rejects.toThrow()
  })

  it('watchRoom delivers chat to onChat, honouring unsubscribe', async () => {
    const { backend } = await makeBackend()
    const seen: string[] = []
    const unsub = backend.watchRoom('lobby', '', { onChat: (m) => seen.push(m.text) })
    await backend.postMessage('lobby', 'one')
    expect(seen).toEqual(['one'])
    unsub()
    await backend.postMessage('lobby', 'two')
    expect(seen).toEqual(['one']) // unsubscribed
  })

  it('a locked identity (no seed) cannot post', async () => {
    const api = await mkit()
    const backend = new MockRepoBackend(api, () => null)
    await expect(backend.postMessage('lobby', 'hi')).rejects.toBeInstanceOf(IdentityLockedError)
  })
})

describe('mergeFeed merges commits + chat oldest-first by timestamp', () => {
  const commits: CommitLogEntry[] = [
    { hash: 'c1', message: 'first commit', authorPubkey: 'a', ref: 'main', createdAt: new Date(1000).toISOString() },
    { hash: 'c2', message: 'second commit', authorPubkey: 'a', ref: 'main', createdAt: new Date(3000).toISOString() },
  ]
  const messages: ChatMessageEntry[] = [
    { messageIdHex: 'm1', authorPubkeyHex: 'b', text: 'hi', createdAt: 2000, seq: 1 },
    { messageIdHex: 'm2', authorPubkeyHex: 'b', text: 'yo', createdAt: 4000, seq: 2 },
  ]

  it('interleaves commit + chat ascending by timestamp', () => {
    const feed: FeedItem[] = mergeFeed(commits, messages)
    expect(feed.map((f) => f.kind)).toEqual(['commit', 'chat', 'commit', 'chat'])
    expect(feed.map((f) => f.ts)).toEqual([1000, 2000, 3000, 4000])
  })

  it('gives every item a stable, unique key', () => {
    const feed = mergeFeed(commits, messages)
    const keys = feed.map((f) => f.key)
    expect(new Set(keys).size).toBe(keys.length)
  })

  it('orders a commit before a chat message at an equal timestamp (stable tiebreak)', () => {
    const sameTsCommit: CommitLogEntry[] = [
      { hash: 'cx', message: 'x', authorPubkey: 'a', ref: 'main', createdAt: new Date(5000).toISOString() },
    ]
    const sameTsChat: ChatMessageEntry[] = [
      { messageIdHex: 'mx', authorPubkeyHex: 'b', text: 'x', createdAt: 5000, seq: 9 },
    ]
    expect(mergeFeed(sameTsCommit, sameTsChat).map((f) => f.kind)).toEqual(['commit', 'chat'])
  })

  it('handles empty inputs', () => {
    expect(mergeFeed([], [])).toEqual([])
  })

  it('orders two same-second commits oldest-first (reverses the newest-first walk input)', () => {
    // commitLog yields newest-first: [head, parent]. Both share a unix-second ts.
    const sameSecond: CommitLogEntry[] = [
      { hash: 'head', message: 'newer', authorPubkey: 'a', ref: 'main', createdAt: new Date(7000).toISOString() },
      { hash: 'parent', message: 'older', authorPubkey: 'a', ref: 'main', createdAt: new Date(7000).toISOString() },
    ]
    // Feed is oldest-first, so the parent must render above the head.
    expect(mergeFeed(sameSecond, []).map((f) => (f.kind === 'commit' ? f.entry.hash : ''))).toEqual(['parent', 'head'])
  })
})

describe('postMessageMutationOptions optimistic echo (TanStack Query)', () => {
  const ROOM = 'lobby'

  function makeControllableBackend(opts: { fail?: boolean; rateLimited?: boolean; gate?: Promise<void> }) {
    return stubBackend({
      postMessage: async () => {
        if (opts.gate) await opts.gate
        if (opts.fail) throw new Error('post failed')
        // A rate-limited post RESOLVES (does not throw) with accepted:false.
        if (opts.rateLimited) return { messageIdHex: '', accepted: false, rateLimited: true }
        return { messageIdHex: 'real', accepted: true, rateLimited: false }
      },
    })
  }

  it('appends the message to the cache while the post is still in flight', async () => {
    let release: () => void = () => {}
    const gate = new Promise<void>((r) => {
      release = r
    })
    const backend = makeControllableBackend({ gate })
    const qc = new QueryClient()
    const key = repoKeys.messages(ROOM)
    qc.setQueryData<ChatMessageEntry[]>(key, [])

    const observer = new MutationObserver(qc, postMessageMutationOptions(qc, backend, ROOM, 'mypk'))
    const p = observer.mutate('hello there')
    await new Promise((r) => setTimeout(r, 0)) // let onMutate run; post blocked on gate

    const optimistic = qc.getQueryData<ChatMessageEntry[]>(key)
    expect(optimistic?.map((m) => m.text)).toEqual(['hello there'])
    expect(optimistic?.[0]?.authorPubkeyHex).toBe('mypk')
    expect(optimistic?.[0]?.messageIdHex.startsWith('optimistic-')).toBe(true)

    release()
    await p
  })

  it('rolls the optimistic message back when the post is rejected', async () => {
    const backend = makeControllableBackend({ fail: true })
    const qc = new QueryClient()
    const key = repoKeys.messages(ROOM)
    const prior: ChatMessageEntry[] = [
      { messageIdHex: 'm0', authorPubkeyHex: 'a', text: 'prior', createdAt: 1, seq: 1 },
    ]
    qc.setQueryData<ChatMessageEntry[]>(key, prior)

    const observer = new MutationObserver(qc, postMessageMutationOptions(qc, backend, ROOM, 'mypk'))
    await expect(observer.mutate('will fail')).rejects.toThrow()
    expect(qc.getQueryData<ChatMessageEntry[]>(key)).toEqual(prior)
  })

  it('rolls the optimistic message back when the post RESOLVES rate-limited (no throw)', async () => {
    const backend = makeControllableBackend({ rateLimited: true })
    const qc = new QueryClient()
    const key = repoKeys.messages(ROOM)
    const prior: ChatMessageEntry[] = [
      { messageIdHex: 'm0', authorPubkeyHex: 'a', text: 'prior', createdAt: 1, seq: 1 },
    ]
    qc.setQueryData<ChatMessageEntry[]>(key, prior)

    const observer = new MutationObserver(qc, postMessageMutationOptions(qc, backend, ROOM, 'mypk'))
    // Resolves (accepted:false) — onError never fires; onSuccess must remove the
    // optimistic echo so it doesn't linger until the settle refetch.
    await observer.mutate('too fast')
    expect(qc.getQueryData<ChatMessageEntry[]>(key)).toEqual(prior)
  })
})

describe('aggregateReactions tallies per target with mine flag', () => {
  it('groups by target then emoji, counts reactors, and marks mine', () => {
    const rows: ReactionEntry[] = [
      { targetIdHex: 't1', emoji: '👍', authorPubkeyHex: 'me' },
      { targetIdHex: 't1', emoji: '👍', authorPubkeyHex: 'other' },
      { targetIdHex: 't1', emoji: '🚀', authorPubkeyHex: 'other' },
      { targetIdHex: 't2', emoji: '❤️', authorPubkeyHex: 'other' },
    ]
    const agg = aggregateReactions(rows, 'me')
    expect(agg.get('t1')).toEqual([
      { emoji: '👍', count: 2, mine: true },
      { emoji: '🚀', count: 1, mine: false },
    ])
    expect(agg.get('t2')).toEqual([{ emoji: '❤️', count: 1, mine: false }])
    expect(agg.get('nope')).toBeUndefined()
  })

  it('mine is false when no pubkey is supplied', () => {
    const agg = aggregateReactions([{ targetIdHex: 't', emoji: '👍', authorPubkeyHex: 'me' }])
    expect(agg.get('t')?.[0]?.mine).toBe(false)
  })
})

describe('chat message ids are unique per post (signed nonce), so reactions do not collide', () => {
  it('gives two identical-text posts DISTINCT ids — the Slack "reaction on both messages" bug', async () => {
    // emerald-robin posts "hello" twice. With the per-post nonce folded into the
    // content hash, the two posts get different message ids, so a reaction on one
    // can never aggregate onto the other.
    const api = await mkit()
    const backend = new MockRepoBackend(api, () => SEED)
    const first = await backend.postMessage('room', 'hello')
    const second = await backend.postMessage('room', 'hello')
    expect(first.messageIdHex).not.toBe(second.messageIdHex)

    // React on the second post only; it must not show on the first.
    const rows: ReactionEntry[] = [{ targetIdHex: second.messageIdHex, emoji: '🚀', authorPubkeyHex: 'me' }]
    const agg = aggregateReactions(rows, 'me')
    expect(agg.get(second.messageIdHex)).toEqual([{ emoji: '🚀', count: 1, mine: true }])
    expect(agg.get(first.messageIdHex)).toBeUndefined()
  })
})

describe('MockRepoBackend reactions: toggle / list / watch', () => {
  async function makeBackend() {
    const api = await mkit()
    return new MockRepoBackend(api, () => SEED)
  }

  it('react toggles on then off, listReactions reflects it, and onReaction fires', async () => {
    const backend = await makeBackend()
    const seen: Array<{ emoji: string; active: boolean; count: number }> = []
    backend.watchRoom('lobby', '', {
      onReaction: (r) => seen.push({ emoji: r.emoji, active: r.active, count: r.count }),
    })

    const on = await backend.react('lobby', 'target1', '👍')
    expect(on).toEqual({ active: true, count: 1 })
    expect((await backend.listReactions('lobby')).map((r) => r.emoji)).toEqual(['👍'])

    const off = await backend.react('lobby', 'target1', '👍')
    expect(off).toEqual({ active: false, count: 0 })
    expect(await backend.listReactions('lobby')).toEqual([])

    expect(seen).toEqual([
      { emoji: '👍', active: true, count: 1 },
      { emoji: '👍', active: false, count: 0 },
    ])
  })

  it('a locked identity (no seed) cannot react', async () => {
    const api = await mkit()
    const backend = new MockRepoBackend(api, () => null)
    await expect(backend.react('lobby', 't', '👍')).rejects.toBeInstanceOf(IdentityLockedError)
  })
})
