import { describe, expect, it } from 'vitest'
import { mkit } from './mkit'
import {
  CasConflictError,
  MockRepoBackend,
  type SignedEnvelope,
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
