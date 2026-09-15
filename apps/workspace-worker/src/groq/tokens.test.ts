import { describe, expect, it, vi } from "vitest";
import { countRequestTokens, MAX_TOKENIZED_BYTES } from "./tokens";

// Node externalizes node_modules WASM before the app's Vite loader. Compile the
// exact installed binary here; production receives the same compiled module
// through Wrangler. No tokenizer implementation is mocked.
vi.mock("../../node_modules/tiktoken/lite/tiktoken_bg.wasm", async () => {
    const { readFileSync } = await import("node:fs");
    const { URL } = await import("node:url");
    const { runInThisContext } = await import("node:vm");
    // Workers intentionally omit dynamic compilation from their global types;
    // this Node-only adapter supplies the compiled module the platform provides.
    const compile: (bytes: Uint8Array) => Promise<WebAssembly.Module> =
        runInThisContext("WebAssembly.compile");
    return {
        default: await compile(
            readFileSync(
                new URL("../../node_modules/tiktoken/lite/tiktoken_bg.wasm", import.meta.url),
            ),
        ),
    };
});

describe("gpt-oss request token admission", () => {
    // Pinned o200k ordinary-BPE counts, including JSON's surrounding quotes.
    it.each([
        ["hello world", 4],
        ["こんにちは世界 🌍", 6],
        ["const sum = (a, b) => a + b;\nconsole.log(sum(2, 3));", 25],
        ["<|endoftext|><|start|>", 11],
    ])(
        "counts JSON-encoded text %j without treating content as protocol tokens",
        (text, expected) => {
            expect(countRequestTokens(text)).toBe(expected);
        },
    );

    it("counts conversation framing without adding the directory protocol reserve twice", () => {
        expect(
            countRequestTokens({ history: [{ role: "user", content: "hello world" }], tools: [] }),
        ).toBe(17);
    });

    it("admits a realistic multi-file coding conversation that the byte-as-token estimate rejected", () => {
        const code = "export function add(a: number, b: number) { return a + b; }\n".repeat(55);
        const conversation = {
            instructions: "Read the files, make the requested change, and run the tests.",
            history: [
                { role: "user", content: "Read both files and add tests for the sum function." },
                { type: "function_call_output", call_id: "read-source", output: code },
                { type: "function_call_output", call_id: "read-tests", output: code },
            ],
            tools: [
                {
                    type: "function",
                    name: "read_file",
                    parameters: { type: "object", properties: { path: { type: "string" } } },
                },
            ],
        };
        const bytes = new TextEncoder().encode(JSON.stringify(conversation)).length;
        const tokens = countRequestTokens(conversation);
        expect(bytes + 1024 + 512).toBeGreaterThan(7500);
        expect(tokens + 1024 + 512).toBeLessThan(7500);
        expect(tokens).toBeLessThan(bytes / 2);
        expect(countRequestTokens(conversation)).toBe(tokens);
    });

    it("includes tools and instructions rather than counting only message text", () => {
        const history = [{ role: "user", content: "Hi" }];
        const bare = countRequestTokens({ history });
        const full = countRequestTokens({
            history,
            tools: [{ type: "function", name: "read_file" }],
            instructions: "Read files before editing.",
        });
        expect(full).toBeGreaterThan(bare);
    });

    it("bounds UTF-8 bytes and rejects unserializable input", () => {
        expect(() => countRequestTokens("a".repeat(MAX_TOKENIZED_BYTES))).toThrow("limit");
        expect(() => countRequestTokens("界".repeat(MAX_TOKENIZED_BYTES / 2))).toThrow("limit");
        expect(() => countRequestTokens(undefined)).toThrow("not JSON serializable");
        const circular: { self?: unknown } = {};
        circular.self = circular;
        expect(() => countRequestTokens(circular)).toThrow();
    });
});
