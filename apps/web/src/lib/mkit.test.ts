import { describe, expect, it } from 'vitest'
import { mkit } from './mkit'

const ZERO_SEED = '0000000000000000000000000000000000000000000000000000000000000000'
const ONE_SEED = '0101010101010101010101010101010101010101010101010101010101010101'
// Seeds for ECDSA tests — the constant-byte seeds above happen to land outside the valid scalar range for
// secp256k1 / p256, so we use well-distributed 32-byte values that are unambiguously valid for all three algorithms.
const SEED_A = '4a7c6b5a493827160908070605040302d1c0bfb8a79683726150403a2b1c0d0e'
const SEED_B = 'f1e2d3c4b5a697887766554433221100ffeeddccbbaa99887766554433221100'

describe('mkit-wasm wrapper', () => {
  it('blake3_hex returns a 64-char lowercase hex digest', async () => {
    const m = await mkit()
    const out = m.blake3_hex(new TextEncoder().encode('hello'))
    expect(out).toMatch(/^[0-9a-f]{64}$/)
    // BLAKE3("hello") is a fixed value — lock it in so a silent codegen
    // regression (wrong hash, endianness, etc.) trips immediately.
    expect(out).toBe('ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f')
  })

  it('blob_encode produces canonical v1 bytes whose hash matches the reported id', async () => {
    const m = await mkit()
    const encoded = m.blob_encode(new TextEncoder().encode('hi'))
    expect(encoded.bytes.byteLength).toBeGreaterThan(6) // prologue at minimum
    // Prologue: [type=0x01 blob][MAGIC "MKT1"][schema=0x01]
    const view = new Uint8Array(encoded.bytes)
    expect(view[0]).toBe(0x01)
    expect(view.slice(1, 5)).toEqual(new Uint8Array([0x4d, 0x4b, 0x54, 0x31]))
    expect(view[5]).toBe(0x01)

    // The reported hash must equal BLAKE3 over the reported bytes.
    expect(m.blake3_hex(view)).toBe(encoded.hash_hex)
  })

  it('keypair_from_seed is deterministic and distinct for distinct seeds', async () => {
    const m = await mkit()
    const a1 = m.keypair_from_seed(ZERO_SEED)
    const a2 = m.keypair_from_seed(ZERO_SEED)
    const b = m.keypair_from_seed(ONE_SEED)
    expect(a1.pubkey_hex).toBe(a2.pubkey_hex)
    expect(a1.pubkey_hex).not.toBe(b.pubkey_hex)
    expect(a1.pubkey_hex).toMatch(/^[0-9a-f]{64}$/)
  })

  it('sign/verify round-trips over the commit signing domain', async () => {
    const m = await mkit()
    const kp = m.keypair_from_seed(ONE_SEED)
    const payload = new TextEncoder().encode('some bytes to sign')
    const sig = m.sign_bytes_commit_domain(ONE_SEED, payload)
    expect(sig).toMatch(/^[0-9a-f]{128}$/)
    expect(m.verify_bytes_commit_domain(kp.pubkey_hex, payload, sig)).toBe(true)
    // Tampering the payload must break verification.
    const tampered = new TextEncoder().encode('some bytes to sigN')
    expect(m.verify_bytes_commit_domain(kp.pubkey_hex, tampered, sig)).toBe(false)
  })

  it('commit_encode_and_sign builds bytes that commit_verify accepts', async () => {
    const m = await mkit()
    const blob = m.blob_encode(new TextEncoder().encode('README'))
    const tree = m.tree_encode(`[["README.md","blob","${blob.hash_hex}"]]`)
    const commit = m.commit_encode_and_sign(tree.hash_hex, '', 'first commit', 0n, ONE_SEED)
    expect(commit.hash_hex).toMatch(/^[0-9a-f]{64}$/)
    expect(commit.signature_hex).toMatch(/^[0-9a-f]{128}$/)
    expect(m.commit_verify(commit.bytes)).toBe(true)
    // Flipping a byte inside the commit must break verification.
    const tampered = new Uint8Array(commit.bytes)
    const last = tampered.length - 1
    tampered[last] = (tampered[last] ?? 0) ^ 0x01
    expect(m.commit_verify(tampered)).toBe(false)
  })

  it.each([
    { algo: 'ed25519', keyidRe: /^blake3:[0-9a-f]{64}$/, pubkeyRe: /^[0-9a-f]{64}$/ },
    { algo: 'secp256k1', keyidRe: /^secp256k1:[0-9a-f]{66}$/, pubkeyRe: /^[0-9a-f]{66}$/ },
    { algo: 'p256', keyidRe: /^p256:[0-9a-f]{66}$/, pubkeyRe: /^[0-9a-f]{66}$/ },
  ])('attest_build + attest_verify round-trips under $algo', async ({ algo, keyidRe, pubkeyRe }) => {
    const m = await mkit()
    const kp = m.attest_keypair(SEED_A, algo)
    expect(kp.keyid).toMatch(keyidRe)
    expect(kp.pubkey_hex).toMatch(pubkeyRe)
    expect(kp.algo).toBe(algo)

    const subjectBytes = new TextEncoder().encode('commit-fixture')
    const predicate = new TextEncoder().encode('{"approved":true}')
    const att = m.attest_build(subjectBytes, 'https://example.com/Review/v1', predicate, SEED_A, algo)
    expect(att.keyid).toBe(kp.keyid)
    expect(att.attestation_id_hex).toMatch(/^[0-9a-f]{64}$/)
    expect(m.attest_verify(att.envelope_json, kp.pubkey_hex, algo)).toBe(true)

    // A different seed's pubkey must fail verification under the same algorithm.
    const other = m.attest_keypair(SEED_B, algo)
    expect(m.attest_verify(att.envelope_json, other.pubkey_hex, algo)).toBe(false)
  })
})
