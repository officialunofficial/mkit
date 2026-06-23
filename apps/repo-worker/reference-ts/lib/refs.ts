import { HEX64 } from "./hex";

// Ref name grammar — mkit SPEC-REFS §3.
//
//   ref_name := segment ( '/' segment )*
//   segment  := char+
//   char     := ALNUM | '.' | '_' | '-'      (ALNUM = [0-9A-Za-z])
//
// Plus rejections: empty, leading '/', empty segment ('//' / trailing '/'),
// any segment == "." or "..", any byte in {0x00, '\\'}, any segment ending
// in ".lock", and a final segment equal to "HEAD".
//
// Validated at the transport boundary, as the spec requires.

const SEGMENT_CHAR = /^[0-9A-Za-z._-]+$/;

export function isValidRefName(name: string): boolean {
  if (name.length === 0) return false;
  if (name.startsWith("/")) return false;
  if (name.includes(" ") || name.includes("\\")) return false;

  const segments = name.split("/");
  for (const seg of segments) {
    if (seg.length === 0) return false; // empty segment (//, trailing/leading /)
    if (seg === "." || seg === "..") return false;
    if (!SEGMENT_CHAR.test(seg)) return false;
    if (seg.endsWith(".lock")) return false;
  }
  if (segments[segments.length - 1] === "HEAD") return false;
  return true;
}

/** A prefix for ListRefs is empty or a valid ref name, optionally trailing-'/'. */
export function isValidRefPrefix(prefix: string): boolean {
  if (prefix.length === 0) return true;
  const trimmed = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
  return isValidRefName(trimmed);
}

/** A ref hash on the HTTP/JSON edge is 64-char lowercase hex; on the proto wire
 *  it is a raw 32-byte id. Both reduce to "32 bytes". */
export function isValidRefHashHex(value: string): boolean {
  return HEX64.test(value);
}

// ---------------------------------------------------------------------------
// CAS state machine — proto-aligned (RefExpectation: ANY / MISSING / MATCH).
//
// Mirrors mkit.repo.v1.RefExpectation (and mkit-rpc ssh.proto). The wire
// numbers are load-bearing.
// ---------------------------------------------------------------------------

export enum RefExpectation {
  UNSPECIFIED = 0,
  ANY = 1,
  MISSING = 2,
  MATCH = 3,
}

/**
 * Result of evaluating a CAS update. `conflict` distinguishes a precondition
 * failure (client should rebase + retry) from `invalid` (a malformed request,
 * e.g. UNSPECIFIED expectation or a non-empty expected_id where it must be
 * empty).
 */
export type CasDecision =
  | { kind: "committed" }
  | { kind: "conflict"; reason: "exists" | "missing" | "mismatch" }
  | { kind: "invalid"; reason: string };

/**
 * Pure CAS decision. Ids are compared as opaque strings — at the proto edge
 * pass lowercase-hex of the 32-byte ids; at a future Rust port pass the raw
 * bytes encoded consistently. `current` is null when the ref is absent.
 * `expected` is the MATCH target (ignored / required-empty otherwise).
 *
 *   ANY      → always commit (clobber); expected MUST be empty.
 *   MISSING  → commit iff current == null (else conflict "exists"); expected MUST be empty.
 *   MATCH    → commit iff current == expected (else conflict "missing"/"mismatch"); expected REQUIRED.
 */
export function evaluateCas(
  current: string | null,
  expectation: RefExpectation,
  expected: string | null,
): CasDecision {
  switch (expectation) {
    case RefExpectation.ANY:
      if (expected) return { kind: "invalid", reason: "expected_id must be empty for ANY" };
      return { kind: "committed" };

    case RefExpectation.MISSING:
      if (expected) return { kind: "invalid", reason: "expected_id must be empty for MISSING" };
      return current === null ? { kind: "committed" } : { kind: "conflict", reason: "exists" };

    case RefExpectation.MATCH:
      if (!expected) return { kind: "invalid", reason: "expected_id required for MATCH" };
      if (current === null) return { kind: "conflict", reason: "missing" };
      if (current !== expected) return { kind: "conflict", reason: "mismatch" };
      return { kind: "committed" };

    case RefExpectation.UNSPECIFIED:
    default:
      return { kind: "invalid", reason: "expectation is UNSPECIFIED (protocol error)" };
  }
}
