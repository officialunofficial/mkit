import { describe, expect, it } from "vitest";
import {
  RefExpectation,
  evaluateCas,
  isValidRefName,
  isValidRefPrefix,
  isValidRefHashHex,
} from "../src/lib/refs";

const ID_A = "a".repeat(64);
const ID_B = "b".repeat(64);

describe("evaluateCas — ref CAS state machine (RefExpectation)", () => {
  describe("ANY (clobber)", () => {
    it("commits over an existing ref", () => {
      expect(evaluateCas(ID_A, RefExpectation.ANY, null)).toEqual({ kind: "committed" });
    });
    it("commits when the ref is absent", () => {
      expect(evaluateCas(null, RefExpectation.ANY, null)).toEqual({ kind: "committed" });
    });
    it("is invalid if expected_id is supplied", () => {
      expect(evaluateCas(ID_A, RefExpectation.ANY, ID_A)).toMatchObject({ kind: "invalid" });
    });
  });

  describe("MISSING (create only)", () => {
    it("commits when the ref is absent", () => {
      expect(evaluateCas(null, RefExpectation.MISSING, null)).toEqual({ kind: "committed" });
    });
    it("conflicts ('exists') when the ref already exists", () => {
      expect(evaluateCas(ID_A, RefExpectation.MISSING, null)).toEqual({
        kind: "conflict",
        reason: "exists",
      });
    });
    it("is invalid if expected_id is supplied", () => {
      expect(evaluateCas(null, RefExpectation.MISSING, ID_A)).toMatchObject({ kind: "invalid" });
    });
  });

  describe("MATCH (compare-and-swap)", () => {
    it("commits when current equals expected", () => {
      expect(evaluateCas(ID_A, RefExpectation.MATCH, ID_A)).toEqual({ kind: "committed" });
    });
    it("conflicts ('mismatch') when current differs", () => {
      expect(evaluateCas(ID_B, RefExpectation.MATCH, ID_A)).toEqual({
        kind: "conflict",
        reason: "mismatch",
      });
    });
    it("conflicts ('missing') when the ref does not exist", () => {
      expect(evaluateCas(null, RefExpectation.MATCH, ID_A)).toEqual({
        kind: "conflict",
        reason: "missing",
      });
    });
    it("is invalid when expected_id is empty", () => {
      expect(evaluateCas(ID_A, RefExpectation.MATCH, null)).toMatchObject({ kind: "invalid" });
    });
  });

  describe("UNSPECIFIED", () => {
    it("is a protocol error (invalid)", () => {
      expect(evaluateCas(null, RefExpectation.UNSPECIFIED, null)).toMatchObject({ kind: "invalid" });
    });
  });
});

describe("isValidRefName — SPEC-REFS §3 grammar", () => {
  it.each(["main", "refs/heads/main", "feat/v1.0-beta", "release/2024_09", "refs/tags/v1"])(
    "accepts valid: %s",
    (name) => expect(isValidRefName(name)).toBe(true),
  );

  it.each([
    ["empty", ""],
    ["leading slash", "/main"],
    ["double slash", "refs//heads"],
    ["trailing slash", "refs/heads/"],
    ["dotdot segment", "feat/../x"],
    ["dot segment", "refs/./main"],
    ["backslash", "feat\\branch"],
    ["at sign (git-only)", "main@v1"],
    ["space", "my branch"],
    [".lock suffix", "refs/heads/main.lock"],
    ["final HEAD", "refs/heads/HEAD"],
    ["bare HEAD", "HEAD"],
    ["plus", "feat+x"],
    ["tilde", "feat~1"],
  ])("rejects %s", (_label, name) => expect(isValidRefName(name)).toBe(false));
});

describe("isValidRefPrefix", () => {
  it("accepts empty", () => expect(isValidRefPrefix("")).toBe(true));
  it("accepts a trailing slash", () => expect(isValidRefPrefix("refs/heads/")).toBe(true));
  it("accepts no trailing slash", () => expect(isValidRefPrefix("refs/heads")).toBe(true));
  it("rejects an invalid inner name", () => expect(isValidRefPrefix("refs/../x")).toBe(false));
});

describe("isValidRefHashHex", () => {
  it("accepts 64-char lowercase hex", () => expect(isValidRefHashHex(ID_A)).toBe(true));
  it("rejects short / uppercase", () => {
    expect(isValidRefHashHex("abc")).toBe(false);
    expect(isValidRefHashHex("A".repeat(64))).toBe(false);
  });
});
