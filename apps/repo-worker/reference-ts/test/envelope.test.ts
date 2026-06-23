import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import {
  ENVELOPE_PREFIX,
  canonicalEnvelope,
  envelopeSigningDigest,
  verifyEnvelope,
  FRESHNESS_WINDOW_MS,
  type CanonicalEnvelopeInput,
} from "../src/lib/envelope";
import { bytesToHex } from "../src/lib/hex";

const ENC = new TextEncoder();

// Deterministic test signer.
const SEED = new Uint8Array(32).fill(7);
const PUBKEY = bytesToHex(ed25519.getPublicKey(SEED));

function signCanonical(input: CanonicalEnvelopeInput): string {
  const digest = blake3(ENC.encode(canonicalEnvelope(input)));
  return bytesToHex(ed25519.sign(digest, SEED));
}

const NOW = 1_700_000_000_000;
const PROCEDURE = "/mkit.repo.v1.RepoService/UpdateRef";
const BODY_DIGEST = bytesToHex(blake3(ENC.encode("serialized-protobuf-request")));

function baseInput(overrides: Partial<CanonicalEnvelopeInput> = {}): CanonicalEnvelopeInput {
  return {
    procedure: PROCEDURE,
    bodyDigest: BODY_DIGEST,
    createdAt: NOW,
    idempotencyKey: "abc-123",
    ...overrides,
  };
}

describe("canonicalEnvelope", () => {
  it("produces the documented 5-field newline-joined string", () => {
    const input = baseInput();
    const lines = canonicalEnvelope(input).split("\n");
    expect(lines).toHaveLength(5);
    expect(lines[0]).toBe(ENVELOPE_PREFIX);
    expect(lines[1]).toBe(PROCEDURE);
    expect(lines[2]).toBe(BODY_DIGEST);
    expect(lines[3]).toBe(String(NOW));
    expect(lines[4]).toBe("abc-123");
  });

  it("represents an absent idempotency key as an empty field", () => {
    expect(canonicalEnvelope(baseInput({ idempotencyKey: "" })).split("\n")[4]).toBe("");
  });

  it("is deterministic", () => {
    expect(canonicalEnvelope(baseInput())).toBe(canonicalEnvelope(baseInput()));
  });

  it("changes when any field changes (no field collisions)", () => {
    const a = envelopeSigningDigest(baseInput());
    expect(envelopeSigningDigest(baseInput({ procedure: "/mkit.repo.v1.RepoService/PutObject" }))).not.toBe(a);
    expect(envelopeSigningDigest(baseInput({ bodyDigest: bytesToHex(blake3(ENC.encode("x"))) }))).not.toBe(a);
    expect(envelopeSigningDigest(baseInput({ createdAt: NOW + 1 }))).not.toBe(a);
    expect(envelopeSigningDigest(baseInput({ idempotencyKey: "different" }))).not.toBe(a);
  });
});

describe("verifyEnvelope", () => {
  function headersFor(input: CanonicalEnvelopeInput) {
    return {
      publicKey: PUBKEY,
      signature: signCanonical(input),
      digest: input.bodyDigest,
      createdAt: String(input.createdAt),
      idempotencyKey: input.idempotencyKey || undefined,
    };
  }

  it("accepts a correctly signed, fresh envelope", () => {
    const input = baseInput();
    const res = verifyEnvelope({
      procedure: input.procedure,
      actualBodyDigest: input.bodyDigest,
      now: NOW,
      headers: headersFor(input),
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.publicKey).toBe(PUBKEY);
      expect(res.bodyDigest).toBe(BODY_DIGEST);
      expect(res.idempotencyKey).toBe("abc-123");
    }
  });

  it("rejects a tampered body (X-Digest != actual)", () => {
    const input = baseInput();
    const res = verifyEnvelope({
      procedure: input.procedure,
      actualBodyDigest: bytesToHex(blake3(ENC.encode("tampered"))),
      now: NOW,
      headers: headersFor(input),
    });
    expect(res).toMatchObject({ ok: false, status: 400, error: "body digest mismatch" });
  });

  it("rejects a signature over a different procedure", () => {
    const signed = baseInput();
    const res = verifyEnvelope({
      procedure: "/mkit.repo.v1.RepoService/PutObject", // server sees a different procedure
      actualBodyDigest: signed.bodyDigest,
      now: NOW,
      headers: headersFor(signed),
    });
    expect(res).toMatchObject({ ok: false, status: 401, error: "invalid signature" });
  });

  it("rejects a stale signature (> 5 min old)", () => {
    const input = baseInput();
    const res = verifyEnvelope({
      procedure: input.procedure,
      actualBodyDigest: input.bodyDigest,
      now: NOW + FRESHNESS_WINDOW_MS + 1,
      headers: headersFor(input),
    });
    expect(res).toMatchObject({ ok: false, status: 401, error: "stale or future signature" });
  });

  it("rejects a future signature (> 5 min ahead)", () => {
    const input = baseInput();
    const res = verifyEnvelope({
      procedure: input.procedure,
      actualBodyDigest: input.bodyDigest,
      now: NOW - FRESHNESS_WINDOW_MS - 1,
      headers: headersFor(input),
    });
    expect(res).toMatchObject({ ok: false, status: 401, error: "stale or future signature" });
  });

  it("accepts a signature exactly at the freshness boundary", () => {
    const input = baseInput();
    const res = verifyEnvelope({
      procedure: input.procedure,
      actualBodyDigest: input.bodyDigest,
      now: NOW + FRESHNESS_WINDOW_MS,
      headers: headersFor(input),
    });
    expect(res.ok).toBe(true);
  });

  it("rejects missing signature headers (401)", () => {
    const input = baseInput();
    const res = verifyEnvelope({
      procedure: input.procedure,
      actualBodyDigest: input.bodyDigest,
      now: NOW,
      headers: { ...headersFor(input), signature: undefined },
    });
    expect(res).toMatchObject({ ok: false, status: 401, error: "missing signature headers" });
  });

  it("rejects malformed hex headers (400)", () => {
    const input = baseInput();
    const res = verifyEnvelope({
      procedure: input.procedure,
      actualBodyDigest: input.bodyDigest,
      now: NOW,
      headers: { ...headersFor(input), publicKey: "nothex" },
    });
    expect(res).toMatchObject({ ok: false, status: 400, error: "malformed signature headers" });
  });

  it("demo open-write: any key is allowed, but the sig must match THAT key", () => {
    const input = baseInput();
    const otherPub = bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
    const res = verifyEnvelope({
      procedure: input.procedure,
      actualBodyDigest: input.bodyDigest,
      now: NOW,
      headers: { ...headersFor(input), publicKey: otherPub },
    });
    expect(res).toMatchObject({ ok: false, status: 401, error: "invalid signature" });
  });

  it("demo open-write: a DIFFERENT valid key signing its own envelope is accepted", () => {
    const seed2 = new Uint8Array(32).fill(3);
    const pub2 = bytesToHex(ed25519.getPublicKey(seed2));
    const input = baseInput();
    const digest = blake3(ENC.encode(canonicalEnvelope(input)));
    const sig2 = bytesToHex(ed25519.sign(digest, seed2));
    const res = verifyEnvelope({
      procedure: input.procedure,
      actualBodyDigest: input.bodyDigest,
      now: NOW,
      headers: {
        publicKey: pub2,
        signature: sig2,
        digest: input.bodyDigest,
        createdAt: String(input.createdAt),
        idempotencyKey: input.idempotencyKey,
      },
    });
    expect(res.ok).toBe(true);
  });
});
