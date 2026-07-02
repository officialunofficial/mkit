// TODO(parity): swap @noble for `@makechain/mkit-wasm` (`ed25519_verify`,
// and `commit_verify` for object validation) once that package is wired into
// this standalone worker's build. The reference vcs worker uses mkit-wasm
// strict verify for byte-exact parity with the Rust node. mkit-wasm@0.2.1 is
// published to npm and resolvable, but its wasm-bindgen `--target bundler`
// build needs a Workers-specific re-instantiation shim (see the reference
// vcs worker's mkit-wasm bootstrap shim). @noble/curves implements the SAME
// algorithm with the SAME strict semantics (RFC 8032 / ZIP-215-off), so the
// envelope contract is byte-for-byte identical; only the implementation
// differs. See README "Crypto parity" for details.

import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex, hexToBytes } from "./hex";

/** BLAKE3 default-mode hash → 32 bytes. (SPEC-SIGNING §1.) */
export function blake3Hash(bytes: Uint8Array): Uint8Array {
  return blake3(bytes);
}

export function blake3Hex(bytes: Uint8Array): string {
  return bytesToHex(blake3(bytes));
}

/**
 * Object-id (content-addressing) check: BLAKE3(bytes) === object_id.
 *
 * `objectId` may be the raw 32-byte digest (proto wire) or its lowercase-hex
 * form (HTTP/JSON edge); both are accepted. Returns false on any length /
 * encoding mismatch rather than throwing.
 */
export function objectIdMatches(bytes: Uint8Array, objectId: Uint8Array | string): boolean {
  const actual = blake3(bytes);
  if (typeof objectId === "string") {
    return bytesToHex(actual) === objectId.toLowerCase();
  }
  if (objectId.length !== actual.length) return false;
  for (let i = 0; i < actual.length; i++) {
    if (actual[i] !== objectId[i]) return false;
  }
  return true;
}

/**
 * Strict Ed25519 verify of `signature` over `digest` (a BLAKE3 hash) under
 * `publicKey`. All three arguments are lowercase hex.
 *
 * Strict mode (`zip215: false`) matches mkit's `verify_strict` (SPEC-SIGNING
 * §1 / §6): non-canonical R, high-s, and non-canonical public-key encodings
 * are rejected — exactly the line the Rust node and the reference vcs worker
 * hold. Returns false (never throws) on any malformed input.
 */
export function ed25519VerifyHex(publicKeyHex: string, signatureHex: string, digestHex: string): boolean {
  try {
    const sig = hexToBytes(signatureHex);
    const msg = hexToBytes(digestHex);
    const pub = hexToBytes(publicKeyHex);
    return ed25519.verify(sig, msg, pub, { zip215: false });
  } catch {
    return false;
  }
}
