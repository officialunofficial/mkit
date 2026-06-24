import { describe, expect, it } from 'vitest'
import type { MkitApi } from './mkit'
import { mkit } from './mkit'
import {
  CasConflictError,
  MockRepoBackend,
  type RepoWasmClient,
  type SignedEnvelope,
  WasmRepoBackend,
  buildSignedEnvelope,
  canonicalString,
  envelopeHeaders,
  makeSignFn,
  procedures,
} from './repo-api'

const SEED = '0101010101010101010101010101010101010101010101010101010101010101'

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
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

    const ok = api.ed25519_verify(
      hexToBytes(env.signatureHex),
      hexToBytes(env.digestHex),
      hexToBytes(env.publicKeyHex),
    )
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

  /** Build a fake wasm client + api over a static commit graph. */
  function harness(opts: {
    head: string | undefined
    graph: Record<string, Node>
    /** Counts decode + object reads so we can assert the head-keyed cache. */
    counters: { decode: number; getObject: number; getRef: number }
  }) {
    const { graph, counters } = opts
    let head = opts.head

    const wasm = {
      get_ref: async (_base: string, _room: string, name: string) => {
        counters.getRef++
        return name === 'main' ? head : undefined
      },
      get_object: async (_base: string, _room: string, hash: string) => {
        counters.getObject++
        // Encode the hash itself as the "bytes" so commit_decode can map back.
        return graph[hash] ? new TextEncoder().encode(hash) : undefined
      },
    } as unknown as RepoWasmClient

    const api = {
      commit_decode: (bytes: Uint8Array) => {
        counters.decode++
        const hash = new TextDecoder().decode(bytes)
        const node = graph[hash]
        if (!node) throw new Error('not a commit')
        return {
          message: node.message,
          signer_hex: node.signer,
          timestamp: 1n,
          parent_count: node.parent ? 1 : 0,
          parent: (i: number) => (i === 0 ? node.parent : undefined),
        }
      },
    } as unknown as MkitApi

    const backend = new WasmRepoBackend(wasm, api, () => null, 'http://x')
    return { backend, setHead: (h: string | undefined) => (head = h) }
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
    const afterFirst = counters.decode
    expect(afterFirst).toBe(1)

    await h.backend.commitLog('room') // same head → cache hit, no decode
    expect(counters.decode).toBe(afterFirst)

    h.setHead('c2') // a peer pushed → head advanced → re-walk
    const log = await h.backend.commitLog('room')
    expect(log.map((e) => e.hash)).toEqual(['c2', 'c1'])
    expect(counters.decode).toBeGreaterThan(afterFirst)
  })

  it('stops the walk on a missing object rather than throwing', async () => {
    const counters = { decode: 0, getObject: 0, getRef: 0 }
    // head points at c2 whose parent c1 is absent from the object store.
    const graph = { c2: { message: 'second', signer: 's', parent: 'c1' } }
    const { backend } = harness({ head: 'c2', graph, counters })
    const log = await backend.commitLog('room')
    expect(log.map((e) => e.hash)).toEqual(['c2'])
  })
})
