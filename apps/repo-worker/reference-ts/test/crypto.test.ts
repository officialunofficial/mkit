import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { blake3Hex, ed25519VerifyHex, objectIdMatches } from "../src/lib/crypto";
import { bytesToHex, hexToBytes, normalizeHex, HEX64 } from "../src/lib/hex";

const ENC = new TextEncoder();

describe("blake3Hex — content-addressing hash check", () => {
  it("produces 64-char lowercase hex", () => {
    const h = blake3Hex(ENC.encode("hello"));
    expect(h).toMatch(HEX64);
  });

  it("matches @noble/hashes blake3 directly", () => {
    const bytes = ENC.encode("the quick brown fox");
    expect(blake3Hex(bytes)).toBe(bytesToHex(blake3(bytes)));
  });

  it("known empty-input vector", () => {
    // BLAKE3 of the empty input.
    expect(blake3Hex(new Uint8Array())).toBe("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
  });

  it("a one-byte flip changes the hash (so PUT hash-check rejects tampering)", () => {
    const a = blake3Hex(ENC.encode("object-bytes"));
    const b = blake3Hex(ENC.encode("Object-bytes"));
    expect(a).not.toBe(b);
  });
});

describe("objectIdMatches — content-addressing (PutObject) check", () => {
  const bytes = new TextEncoder().encode("raw mkit object bytes");
  const id = blake3(bytes); // raw 32-byte id

  it("accepts a raw 32-byte id that matches", () => {
    expect(objectIdMatches(bytes, id)).toBe(true);
  });
  it("accepts a hex id that matches", () => {
    expect(objectIdMatches(bytes, bytesToHex(id))).toBe(true);
  });
  it("rejects a one-byte-flipped raw id", () => {
    const bad = id.slice();
    bad[0] ^= 1;
    expect(objectIdMatches(bytes, bad)).toBe(false);
  });
  it("rejects a hex id for different bytes", () => {
    expect(objectIdMatches(new TextEncoder().encode("other"), bytesToHex(id))).toBe(false);
  });
  it("rejects a wrong-length raw id", () => {
    expect(objectIdMatches(bytes, id.slice(0, 31))).toBe(false);
  });
});

describe("ed25519VerifyHex — strict verification", () => {
  const seed = new Uint8Array(32).fill(7);
  const pub = bytesToHex(ed25519.getPublicKey(seed));
  const digest = blake3Hex(ENC.encode("envelope-canonical-string"));
  const sig = bytesToHex(ed25519.sign(hexToBytes(digest), seed));

  it("accepts a valid signature", () => {
    expect(ed25519VerifyHex(pub, sig, digest)).toBe(true);
  });

  it("rejects a tampered signature", () => {
    const bad = sig.slice(0, -2) + (sig.endsWith("00") ? "01" : "00");
    expect(ed25519VerifyHex(pub, bad, digest)).toBe(false);
  });

  it("rejects a signature over a different digest", () => {
    const other = blake3Hex(ENC.encode("different-string"));
    expect(ed25519VerifyHex(pub, sig, other)).toBe(false);
  });

  it("rejects a different public key", () => {
    const otherPub = bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
    expect(ed25519VerifyHex(otherPub, sig, digest)).toBe(false);
  });

  it("returns false (never throws) on malformed hex", () => {
    expect(ed25519VerifyHex("xyz", sig, digest)).toBe(false);
    expect(ed25519VerifyHex(pub, "short", digest)).toBe(false);
  });
});

describe("hex helpers", () => {
  it("round-trips bytes ↔ hex", () => {
    const bytes = new Uint8Array([0, 1, 15, 16, 255, 128]);
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
  });

  it("rejects uppercase hex on decode (mkit forbids uppercase wire)", () => {
    expect(() => hexToBytes("AABB")).toThrow();
  });

  it("normalizeHex strips 0x and lowercases", () => {
    expect(normalizeHex("0xABCD")).toBe("abcd");
    expect(normalizeHex("  AbCd ")).toBe("abcd");
  });
});
