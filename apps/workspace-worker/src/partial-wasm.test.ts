import { readFileSync } from "node:fs";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { describe, expect, it } from "vitest";
import { fromHex } from "./mkit";
import {
    defaultEditAndExportPartial,
    editAndExportPartial,
    parseWasmError,
    verifyPartialSnapshot,
} from "./partial-wasm";

const GOLDEN = fileURLToPath(new NodeURL("../../../rust/tests/golden/partial_workspace/", import.meta.url));
const PLAIN = readFileSync(`${GOLDEN}plain_file.bin`);
const CHUNKED = readFileSync(`${GOLDEN}chunked_file.bin`);
const BASE = "17963c328bb4a65dfffb659125df822a5a8b0aaca309c245c569420e243f8d90";
const PATHS = JSON.stringify([["7368616c6c6f772e747874"]]);
const CHUNKED_PATHS = JSON.stringify([["6368756e6b65642e62696e"]]);
const SEED = fromHex("41".repeat(32));
const AUTHOR = new TextEncoder().encode("browser-agent");
const MESSAGE = new TextEncoder().encode("partial edit");
const REPLACEMENTS = JSON.stringify([
    { path: ["7368616c6c6f772e747874"], bytes_hex: "7761736d20706172697479" },
]);

describe("executed wasm partial adapters", () => {
    it("verifies a snapshot with no signing seed", () => {
        const snapshot = verifyPartialSnapshot(PLAIN, BASE, PATHS);
        expect(snapshot.coverage).toBe("selected-only");
        expect(snapshot.files).toHaveLength(1);
        expect(snapshot.files[0]!.pathJson).toBe('["7368616c6c6f772e747874"]');
        expect(snapshot.files[0]!.mode).toBe("blob");
        expect(snapshot.files[0]!.bytes.byteLength).toBeGreaterThan(0);
    });

    it("materializes a chunked selected representation", () => {
        const snapshot = verifyPartialSnapshot(CHUNKED, BASE, CHUNKED_PATHS, "{}");
        expect(snapshot.coverage).toBe("selected-only");
        expect(snapshot.files[0]!.bytes.byteLength).toBeGreaterThan(1024);
        expect(() => verifyPartialSnapshot(CHUNKED, BASE, CHUNKED_PATHS)).toThrow(
            /exceeds the configured workspace bound/,
        );
    });

    it("rejects stricter limits and malformed options", () => {
        expect(() =>
            verifyPartialSnapshot(PLAIN, BASE, PATHS, JSON.stringify({ max_bundle_bytes: 100 })),
        ).toThrow();
        expect(() =>
            verifyPartialSnapshot(PLAIN, BASE, PATHS, JSON.stringify({ unknown: 1 })),
        ).toThrow();
        expect(() =>
            verifyPartialSnapshot(PLAIN, BASE, PATHS, JSON.stringify({ max_bundle_bytes: 1.5 })),
        ).toThrow();
        const huge = `{"max_bundle_bytes":1${" ".repeat(16 * 1024)}}`;
        expect(() => verifyPartialSnapshot(PLAIN, BASE, PATHS, huge)).toThrow(/16 KiB/);
    });

    it("shares edit/export bytes between default and omitted limits", () => {
        const limited = editAndExportPartial(
            PLAIN,
            BASE,
            PATHS,
            REPLACEMENTS,
            "opaque",
            AUTHOR,
            MESSAGE,
            1_750_000_000,
            SEED,
            "{}",
        );
        const defaults = defaultEditAndExportPartial(
            PLAIN,
            BASE,
            PATHS,
            REPLACEMENTS,
            "opaque",
            AUTHOR,
            MESSAGE,
            1_750_000_000,
            SEED,
        );
        expect(limited.candidateHex).toBe(defaults.candidateHex);
        expect(limited.rootHex).toBe(defaults.rootHex);
        expect(limited.coverage).toBe("selected-only");
        expect(Buffer.from(limited.updateBytes)).toEqual(Buffer.from(defaults.updateBytes));
        expect(limited.updateBytes.byteLength).toBeGreaterThan(32);
    });

    it("records local memory near the chunked fixture", () => {
        const before = process.memoryUsage();
        const snapshot = verifyPartialSnapshot(CHUNKED, BASE, CHUNKED_PATHS, "{}");
        const after = process.memoryUsage();
        expect(snapshot.files[0]!.bytes.byteLength).toBeGreaterThan(0);
        expect(after.heapUsed).toBeGreaterThan(0);
        expect(after.rss).toBeGreaterThan(before.rss - 32 * 1024 * 1024);
    });

    it("classifies wasm adapter errors", () => {
        expect(parseWasmError(new Error('{"code":"base_mismatch","message":"no"}'))).toEqual({
            code: "base_mismatch",
            message: "no",
        });
    });
});


