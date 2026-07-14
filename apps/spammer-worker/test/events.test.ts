// test/events.test.ts
//
// Unit tests for events.ts's commit/remix push logic — specifically the CAS
// conflict/retry behavior that, until now, was only exercised by the one-off
// `scratch-verify-*.ts` scripts used during development (real network calls
// against the throwaway `spammer-test` room, then deleted). Uses
// `test/helpers/fake-wasm.ts`'s in-memory fake instead of the real wasm/
// network, so this runs offline in the "unit" vitest project and is fully
// deterministic.

import { describe, expect, it, vi } from "vitest";
import { emitCommit, emitRemix, forkRefName, MAIN_REF, type EmitContext } from "../src/events";
import type { Identity } from "../src/identities";
import { makeFakeWasm } from "./helpers/fake-wasm";

const BASE_URL = "https://example.invalid";

function identity(index: number): Identity {
  const hex = index.toString(16).padStart(2, "0");
  return { index, seedHex: hex.repeat(32), pubkeyHex: hex.repeat(32) };
}

describe("events.ts — forkRefName", () => {
  it("joins the first 12 hex chars of the upstream commit and the forker pubkey", () => {
    expect(forkRefName("abcdef0123456789", "0011223344556677")).toBe("forks/abcdef012345-001122334455");
  });
});

describe("events.ts — emitCommit", () => {
  it("pushes a root commit (MISSING expectation) when the ref doesn't exist yet", async () => {
    const fake = makeFakeWasm();
    const ctx: EmitContext = { wasm: fake.wasm, baseUrl: BASE_URL };
    const room = "test-room";

    const result = await emitCommit(ctx, room, identity(0), 0);

    expect(result.committed).toBe(true);
    if (result.committed) {
      expect(result.parentHash).toBeNull();
      expect(fake.getRef(room, MAIN_REF)).toBe(result.commitHash);
    }
  });

  it("chains a second commit onto the first via MATCH", async () => {
    const fake = makeFakeWasm();
    const ctx: EmitContext = { wasm: fake.wasm, baseUrl: BASE_URL };
    const room = "test-room";

    const first = await emitCommit(ctx, room, identity(1), 0);
    const second = await emitCommit(ctx, room, identity(1), 1);

    expect(first.committed && second.committed).toBe(true);
    if (first.committed && second.committed) {
      expect(second.parentHash).toBe(first.commitHash);
      expect(fake.getRef(room, MAIN_REF)).toBe(second.commitHash);
    }
  });

  it("retries once after a CAS conflict (a real visitor's write landing first) and succeeds", async () => {
    const fake = makeFakeWasm();
    const ctx: EmitContext = { wasm: fake.wasm, baseUrl: BASE_URL };
    const room = "test-room";

    // Simulate: this identity's view of the head is stale ("stale-head"), but
    // a concurrent writer already advanced the real ref to
    // "concurrent-write-hash" by the time our update_ref actually runs.
    fake.forceRef(room, MAIN_REF, "concurrent-write-hash");
    const originalGetRef = fake.wasm.repo.get_ref.bind(fake.wasm.repo);
    let getRefCalls = 0;
    fake.wasm.repo.get_ref = (async (baseUrl: string, r: string, ref: string) => {
      getRefCalls += 1;
      // First read (emitCommit's initial head check) sees the stale value;
      // every subsequent read (the retry's re-read) sees the real, current one.
      return getRefCalls === 1 ? "stale-head" : originalGetRef(baseUrl, r, ref);
    }) as typeof fake.wasm.repo.get_ref;

    const result = await emitCommit(ctx, room, identity(2), 0);

    expect(getRefCalls).toBe(2);
    expect(result.committed).toBe(true);
    if (result.committed) {
      expect(result.parentHash).toBe("concurrent-write-hash");
      expect(fake.getRef(room, MAIN_REF)).toBe(result.commitHash);
    }
  });

  it("gives up after one retry when the conflict persists, logging a warning without throwing", async () => {
    const fake = makeFakeWasm();
    const ctx: EmitContext = { wasm: fake.wasm, baseUrl: BASE_URL };
    const room = "test-room";
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);

    fake.wasm.repo.update_ref = (async () => ({
      conflict: true,
      currentIdHex: "still-conflicting",
    })) as typeof fake.wasm.repo.update_ref;

    const result = await emitCommit(ctx, room, identity(3), 0);

    expect(result.committed).toBe(false);
    if (!result.committed) {
      expect(result.currentIdHex).toBe("still-conflicting");
    }
    expect(warnSpy).toHaveBeenCalledOnce();
    warnSpy.mockRestore();
  });
});

describe("events.ts — emitRemix", () => {
  it("pushes onto its own dedicated fork ref, never touching main", async () => {
    const fake = makeFakeWasm();
    const ctx: EmitContext = { wasm: fake.wasm, baseUrl: BASE_URL };
    const room = "test-room";
    const upstreamCommitHash = "upstream-commit-hash";
    const forker = identity(4);

    const result = await emitRemix(ctx, room, forker, upstreamCommitHash, 0);

    expect(result.committed).toBe(true);
    if (result.committed) {
      const expectedRef = forkRefName(upstreamCommitHash, forker.pubkeyHex);
      expect(result.ref).toBe(expectedRef);
      expect(fake.getRef(room, expectedRef)).toBe(result.remixHash);
    }
    expect(fake.getRef(room, MAIN_REF)).toBeUndefined();
  });

  it("chains a repeat remix of the same upstream by the same identity via MATCH", async () => {
    const fake = makeFakeWasm();
    const ctx: EmitContext = { wasm: fake.wasm, baseUrl: BASE_URL };
    const room = "test-room";
    const upstreamCommitHash = "upstream-commit-hash";
    const forker = identity(5);

    const first = await emitRemix(ctx, room, forker, upstreamCommitHash, 0);
    const second = await emitRemix(ctx, room, forker, upstreamCommitHash, 1);

    expect(first.committed && second.committed).toBe(true);
    if (first.committed && second.committed) {
      expect(first.ref).toBe(second.ref);
      expect(second.parentHash).toBe(first.remixHash);
    }
  });
});
