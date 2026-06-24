import { MutationObserver, QueryClient } from '@tanstack/react-query'
import { describe, expect, it } from 'vitest'
import type { MkitApi } from './mkit'
import { mkit } from './mkit'
import {
  CasConflictError,
  type CommitLogEntry,
  MockRepoBackend,
  type PushArgs,
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
  pushCommitMutationOptions,
  repoKeys,
  setRepoBackend,
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
    /** Optional extra ref → head map (beyond `main`) for branch tests. */
    refs?: Record<string, string>
  }) {
    const { graph, counters } = opts
    let head = opts.head
    const refs = opts.refs ?? {}

    const wasm = {
      get_ref: async (_base: string, _room: string, name: string) => {
        counters.getRef++
        if (name === 'main') return head
        return refs[name]
      },
      get_object: async (_base: string, _room: string, hash: string) => {
        counters.getObject++
        // Encode the hash itself as the "bytes" so commit_decode can map back.
        return graph[hash] ? new TextEncoder().encode(hash) : undefined
      },
      list_refs: async (_base: string, _room: string, prefix: string) => {
        const all = [
          ...(head ? [{ name: 'main', objectIdHex: head }] : []),
          ...Object.entries(refs).map(([name, objectIdHex]) => ({ name, objectIdHex })),
        ]
        return all.filter((r) => r.name.startsWith(prefix))
      },
    } as unknown as RepoWasmClient

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

  it('walks a non-`main` ref independently, tagging entries with that ref', async () => {
    const counters = { decode: 0, getObject: 0, getRef: 0 }
    const graph = {
      m2: { message: 'main 2', signer: 's', parent: 'm1' },
      m1: { message: 'main 1', signer: 's' },
      f1: { message: 'feature spike', signer: 's' },
    }
    const { backend } = harness({ head: 'm2', graph, counters, refs: { feature: 'f1' } })

    const main = await backend.commitLog('room', 'main')
    expect(main.map((e) => e.hash)).toEqual(['m2', 'm1'])
    expect(main.every((e) => e.ref === 'main')).toBe(true)

    const feature = await backend.commitLog('room', 'feature')
    expect(feature.map((e) => e.hash)).toEqual(['f1'])
    expect(feature.every((e) => e.ref === 'feature')).toBe(true)
  })

  it('caches per `room::ref`: switching branches does not invalidate the other', async () => {
    const counters = { decode: 0, getObject: 0, getRef: 0 }
    const graph = {
      m1: { message: 'main', signer: 's' },
      f1: { message: 'feature', signer: 's' },
    }
    const { backend } = harness({ head: 'm1', graph, counters, refs: { feature: 'f1' } })

    await backend.commitLog('room', 'main')
    await backend.commitLog('room', 'feature')
    const afterBoth = counters.decode
    expect(afterBoth).toBe(2) // each ref walked once

    // Repeat calls hit each ref's own cache — no extra decodes.
    await backend.commitLog('room', 'main')
    await backend.commitLog('room', 'feature')
    expect(counters.decode).toBe(afterBoth)
  })

  it('decodes a single commit by hash for the detail view (tree + signature)', async () => {
    const counters = { decode: 0, getObject: 0, getRef: 0 }
    const graph = { c1: { message: 'detail me', signer: 'sig1' } }
    const { backend } = harness({ head: 'c1', graph, counters })

    // The detail view fetches the object then decodes it client-side.
    const bytes = await backend.getObject('room', 'c1')
    expect(bytes).not.toBeNull()
    // The wasm walk in commitLog already exercises commit_decode; here we just
    // assert the bytes round-trip back to the same hash for get_object.
    expect(new TextDecoder().decode(bytes!)).toBe('c1')
  })
})

describe('listRefs exposes all branches in the room', () => {
  it('WasmRepoBackend.listRefs returns main + branches', async () => {
    const graph = { m1: { message: 'main', signer: 's' }, f1: { message: 'feat', signer: 's' } }
    // Reuse the wasm harness above via a fresh instance.
    const backend = new WasmRepoBackend(
      {
        get_ref: async (_b: string, _r: string, n: string) => (n === 'main' ? 'm1' : n === 'feature' ? 'f1' : undefined),
        get_object: async (_b: string, _r: string, h: string) =>
          graph[h as keyof typeof graph] ? new TextEncoder().encode(h) : undefined,
        list_refs: async (_b: string, _r: string, prefix: string) =>
          [
            { name: 'main', objectIdHex: 'm1' },
            { name: 'feature', objectIdHex: 'f1' },
          ].filter((r) => r.name.startsWith(prefix)),
      } as unknown as RepoWasmClient,
      {} as unknown as MkitApi,
      () => null,
      'http://x',
    )
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
    const sourcesJson = JSON.stringify([
      { upstream_id_hex: UPSTREAM_ID, commit_hash_hex: upstream.hash_hex },
    ])
    const remix = api.remix_encode_and_sign(TREE, '', sourcesJson, 'forked it', 2n, SEED2)

    const res = decodeLogObject(api, remix.bytes, remix.hash_hex, forkRefName(upstream.hash_hex))
    expect(res).not.toBeNull()
    expect(res!.entry.kind).toBe('remix')
    expect(res!.entry.message).toBe('forked it')
    expect(res!.entry.sources).toEqual([
      { upstreamIdHex: UPSTREAM_ID, commitHashHex: upstream.hash_hex },
    ])
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
    const sourcesJson = JSON.stringify([
      { upstream_id_hex: UPSTREAM_ID, commit_hash_hex: commit.hash_hex },
    ])
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
    const sourcesJson = JSON.stringify([
      { upstream_id_hex: UPSTREAM_ID, commit_hash_hex: upstream.hash_hex },
    ])
    const remix = api.remix_encode_and_sign(TREE, '', sourcesJson, 'a fork', 2n, SEED2)
    const forkRef = forkRefName(upstream.hash_hex)

    // Real object bytes keyed by hash; get_object returns them verbatim so the
    // walk decodes the genuine remix object (not a fake).
    const store: Record<string, Uint8Array> = {
      [remix.hash_hex]: remix.bytes,
      [upstream.hash_hex]: upstream.bytes,
    }
    const wasm = {
      get_ref: async (_b: string, _r: string, name: string) =>
        name === forkRef ? remix.hash_hex : undefined,
      get_object: async (_b: string, _r: string, hash: string) => store[hash],
      list_refs: async (_b: string, _r: string, prefix: string) =>
        [{ name: forkRef, objectIdHex: remix.hash_hex }].filter((r) => r.name.startsWith(prefix)),
    } as unknown as RepoWasmClient

    const backend = new WasmRepoBackend(wasm, api, () => null, 'http://x')
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
   * A backend whose updateRef we can make succeed or reject on demand, and
   * (optionally) block on an external gate so we can assert the optimistic
   * prepend is visible while the push is still in flight.
   */
  function makeControllableBackend(opts: { failUpdate?: boolean; gate?: Promise<void> }) {
    return {
      putObject: async () => {},
      getObject: async () => null,
      getRef: async () => null,
      updateRef: async () => {
        if (opts.gate) await opts.gate
        if (opts.failUpdate) throw new CasConflictError(null)
      },
      listRefs: async () => [],
      watchRefs: () => () => {},
      commitLog: async () => [],
    } satisfies import('./repo-api').RepoBackend
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
    setRepoBackend(makeControllableBackend({ gate }))
    const qc = new QueryClient()
    const logKey = repoKeys.log(ROOM, REF)
    qc.setQueryData<CommitLogEntry[]>(logKey, []) // an empty walked log

    const args = await makePushArgs('optimistic me')
    const observer = new MutationObserver(qc, pushCommitMutationOptions(qc))

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
    setRepoBackend(makeControllableBackend({ failUpdate: true }))
    const qc = new QueryClient()
    const logKey = repoKeys.log(ROOM, REF)
    const prior: CommitLogEntry[] = [
      { hash: 'old', message: 'prior', authorPubkey: 'a', ref: REF, createdAt: '1970-01-01T00:00:01.000Z' },
    ]
    qc.setQueryData<CommitLogEntry[]>(logKey, prior)

    const args = await makePushArgs('will fail')
    const observer = new MutationObserver(qc, pushCommitMutationOptions(qc))
    await expect(observer.mutate(args)).rejects.toBeInstanceOf(CasConflictError)

    // onError restored the snapshot — the optimistic entry is gone.
    expect(qc.getQueryData<CommitLogEntry[]>(logKey)).toEqual(prior)
  })
})

describe('WasmRepoBackend object cache (content-addressed → cache forever)', () => {
  function spyClient(store: Record<string, Uint8Array>) {
    const calls: string[] = []
    const wasm = {
      get_ref: async () => undefined,
      get_object: async (_b: string, _r: string, hash: string) => {
        calls.push(hash)
        return store[hash]
      },
      list_refs: async () => [],
    } as unknown as RepoWasmClient
    return { wasm, calls }
  }

  it('getObject for the same hash issues exactly ONE underlying client call', async () => {
    const bytes = new Uint8Array([1, 2, 3])
    const { wasm, calls } = spyClient({ h1: bytes })
    const backend = new WasmRepoBackend(wasm, {} as unknown as MkitApi, () => null, 'http://x')

    const a = await backend.getObject('room', 'h1')
    const b = await backend.getObject('room', 'h1')
    expect(a).toEqual(bytes)
    expect(b).toEqual(bytes)
    expect(calls).toEqual(['h1']) // second read served from cache
  })

  it('getObject for a DIFFERENT hash still fetches', async () => {
    const { wasm, calls } = spyClient({ h1: new Uint8Array([1]), h2: new Uint8Array([2]) })
    const backend = new WasmRepoBackend(wasm, {} as unknown as MkitApi, () => null, 'http://x')
    await backend.getObject('room', 'h1')
    await backend.getObject('room', 'h2')
    await backend.getObject('room', 'h1') // cached
    expect(calls).toEqual(['h1', 'h2'])
  })
})

describe('WasmRepoBackend incremental commit-log walk', () => {
  type Node = { message: string; signer: string; parent?: string }

  function harness(graph: Record<string, Node>, initialHead: string) {
    let head = initialHead
    const getObjectCalls: string[] = []
    const wasm = {
      get_ref: async () => head,
      get_object: async (_b: string, _r: string, hash: string) => {
        getObjectCalls.push(hash)
        return graph[hash] ? new TextEncoder().encode(hash) : undefined
      },
      list_refs: async () => [],
    } as unknown as RepoWasmClient
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
    const backend = new WasmRepoBackend(wasm, api, () => null, 'http://x')
    return { backend, getObjectCalls, setHead: (h: string) => (head = h) }
  }

  it('after a cached 3-commit walk, a 4th-commit re-walk fetches only the new object', async () => {
    const graph: Record<string, Node> = {
      c3: { message: 'c3', signer: 's', parent: 'c2' },
      c2: { message: 'c2', signer: 's', parent: 'c1' },
      c1: { message: 'c1', signer: 's' },
    }
    const h = harness(graph, 'c3')

    const first = await h.backend.commitLog('room')
    expect(first.map((e) => e.hash)).toEqual(['c3', 'c2', 'c1'])
    const afterCold = h.getObjectCalls.length
    expect(afterCold).toBe(3) // cold walk fetched all 3

    // Push a 4th commit on top → head advances.
    graph.c4 = { message: 'c4', signer: 's', parent: 'c3' }
    h.setHead('c4')

    h.getObjectCalls.length = 0
    const second = await h.backend.commitLog('room')
    expect(second.map((e) => e.hash)).toEqual(['c4', 'c3', 'c2', 'c1']) // newest-first, full chain
    expect(h.getObjectCalls).toEqual(['c4']) // ONLY the new object, not 4
  })
})
