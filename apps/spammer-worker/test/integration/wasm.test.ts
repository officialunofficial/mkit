import { describe, expect, it } from "vitest";
import { getWasm } from "../../src/wasm";

// Runs inside the real Workers isolate (see vitest.config.ts's "integration"
// project) so `wasm.ts`'s bare `.wasm` imports go through Wrangler's actual
// bundler transform — the same code path `wrangler dev`/`deploy` uses, not a
// Node-only stand-in. Smoke-checks step 2 of PLAN.md: both wasm modules
// instantiate, and their exported functions return well-formed output.

const HEX_64 = /^[0-9a-f]{64}$/;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

describe("getWasm", () => {
  it("initializes both modules and exposes blake3_hex", async () => {
    const { mkit } = await getWasm();
    const digest = mkit.blake3_hex(new TextEncoder().encode("mkit-spammer:v1:seed:0"));

    expect(digest).toMatch(HEX_64); // BLAKE3 is a 32-byte digest → 64 hex chars.
  });

  it("exposes ed25519_pubkey_from_seed, deriving a 32-byte pubkey from a 32-byte seed", async () => {
    const { mkit } = await getWasm();
    const seed = new Uint8Array(32).fill(1); // any well-formed 32-byte seed
    const pubkey = mkit.ed25519_pubkey_from_seed(seed);

    expect(pubkey).toBeInstanceOf(Uint8Array);
    expect(pubkey.length).toBe(32);
    expect(bytesToHex(pubkey)).toMatch(HEX_64);
  });

  it("memoizes: a second call resolves the same promise instance", () => {
    const first = getWasm();
    const second = getWasm();

    expect(second).toBe(first);
  });

  it("exposes the mkit-repo-client write surface (put_object/update_ref/post_message/react)", async () => {
    const { repo } = await getWasm();

    expect(typeof repo.put_object).toBe("function");
    expect(typeof repo.update_ref).toBe("function");
    expect(typeof repo.post_message).toBe("function");
    expect(typeof repo.react).toBe("function");
  });
});
