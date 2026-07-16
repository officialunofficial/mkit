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
import { pick, REACTION_EMOJI } from "../src/content";
import { emitChatText, emitCommit, emitReaction, emitRemix, forkRefName, MAIN_REF, type EmitContext } from "../src/events";
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

  // #852: `emitRemix` already accepts an arbitrary `upstreamCommitHash` — this
  // is verification, not new machinery. The fork-ref naming scheme
  // (`forkRefName`) only ever consumes the upstream hash + forker pubkey, and
  // never looks at which ref that hash currently lives on, so a commit that
  // lives on some OTHER real ref (a feature branch, never `main`'s or any
  // fork ref's own head in this fake) must remix identically to any other
  // upstream hash.
  it("remixes an arbitrary real commit hash that lives on a non-main, non-fork feature branch — lands on the correctly-named fork ref and chains via CAS on repeat", async () => {
    const fake = makeFakeWasm();
    const ctx: EmitContext = { wasm: fake.wasm, baseUrl: BASE_URL };
    const room = "test-room";
    const forker = identity(6);

    // Simulate a real user's commit sitting on their own feature branch —
    // NOT `main`'s head, NOT any fork ref's head — to prove the fork-ref
    // scheme cares only about the commit hash, not its origin ref.
    const featureBranchRef = "alice/feature-branch";
    const upstreamCommitHash = "real-user-feature-commit-hash";
    fake.forceRef(room, featureBranchRef, upstreamCommitHash);

    const first = await emitRemix(ctx, room, forker, upstreamCommitHash, 0);
    expect(first.committed).toBe(true);
    if (first.committed) {
      const expectedRef = forkRefName(upstreamCommitHash, forker.pubkeyHex);
      expect(first.ref).toBe(expectedRef);
      expect(first.parentHash).toBeNull();
      expect(fake.getRef(room, expectedRef)).toBe(first.remixHash);
    }
    // The feature branch itself is untouched — remixing never writes back to
    // the upstream's own ref.
    expect(fake.getRef(room, featureBranchRef)).toBe(upstreamCommitHash);
    expect(fake.getRef(room, MAIN_REF)).toBeUndefined();

    // A repeat remix of the SAME upstream by the SAME identity chains onto
    // its own prior head via CAS MATCH, exactly like the same-ref case above.
    const second = await emitRemix(ctx, room, forker, upstreamCommitHash, 1);
    expect(second.committed).toBe(true);
    if (first.committed && second.committed) {
      expect(second.ref).toBe(first.ref);
      expect(second.parentHash).toBe(first.remixHash);
      expect(fake.getRef(room, first.ref)).toBe(second.remixHash);
    }
  });
});

describe("events.ts — emitChatText", () => {
  it("posts exactly the given text, not a phrase-pool pick", async () => {
    const fake = makeFakeWasm();
    const ctx: EmitContext = { wasm: fake.wasm, baseUrl: BASE_URL };
    const room = "test-room";
    const replier = identity(7);
    const text = "nice push, real1234abcd by key5678efgh on alice/feature-branch";

    const result = await emitChatText(ctx, room, replier, text);

    expect(result.accepted).toBe(true);
    expect(fake.chats).toEqual([{ room, text }]);
  });

  it("shares the signing path with emitChat: both funnel through post_message with the caller's exact text", async () => {
    const fake = makeFakeWasm();
    const ctx: EmitContext = { wasm: fake.wasm, baseUrl: BASE_URL };
    const room = "test-room";
    const replier = identity(8);

    await emitChatText(ctx, room, replier, "reply one");
    await emitChatText(ctx, room, replier, "reply two");

    expect(fake.chats).toEqual([
      { room, text: "reply one" },
      { room, text: "reply two" },
    ]);
  });
});

describe("events.ts — emitReaction", () => {
  it("reacts to an arbitrary real commit hash regardless of its origin ref", async () => {
    const fake = makeFakeWasm();
    const ctx: EmitContext = { wasm: fake.wasm, baseUrl: BASE_URL };
    const room = "test-room";
    const reactor = identity(9);

    // Again: a commit on a feature branch that is neither `main` nor a fork
    // ref — `emitReaction` must not care.
    fake.forceRef(room, "bob/experiment", "another-real-user-commit-hash");
    const targetIdHex = "another-real-user-commit-hash";

    const counter = 2;
    const result = await emitReaction(ctx, room, reactor, targetIdHex, counter);

    expect(result.active).toBe(true);
    expect(fake.reactions).toEqual([{ room, targetIdHex, emoji: pick(REACTION_EMOJI, counter) }]);
  });
});
