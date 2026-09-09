import { init, Tiktoken } from "tiktoken/lite/init";
import ranks from "tiktoken/encoders/o200k_base";
import wasmModule from "../../node_modules/tiktoken/lite/tiktoken_bg.wasm";

// Compile/upload this static WASM module through Wrangler's CompiledWasm rule.
// No network fetch, dynamic compilation, or model credentials are involved.
await init((imports) => WebAssembly.instantiate(wasmModule, imports));

let tokenizer: Tiktoken | undefined;
export const MAX_TOKENIZED_BYTES = 64 * 1024;

/** Ordinary o200k tokens in the serialized conversation, tools and instructions.
 *
 * gpt-oss's official o200k_harmony tokenizer shares o200k_base's regex and
 * mergeable ranks: https://github.com/openai/gpt-oss/blob/main/gpt_oss/tokenizer.py
 * Groq converts the JSON into Harmony, so this is a local admission estimate,
 * not provider billing. JSON includes metadata/punctuation beyond message text.
 * The directory adds its 512-token protocol reserve ONCE, then reconciles with
 * provider-reported usage. Hidden prompts or future templates can still differ.
 */
export function countRequestTokens(conversation: unknown): number {
    const serialized = JSON.stringify(conversation);
    if (serialized === undefined) throw new Error("Conversation is not JSON serializable");
    // The bridge already caps history; keep this helper independently bounded
    // before invoking BPE, including for long unbroken or multibyte text.
    if (
        serialized.length > MAX_TOKENIZED_BYTES ||
        new TextEncoder().encode(serialized).length > MAX_TOKENIZED_BYTES
    ) {
        throw new Error("Conversation exceeds token counting limit");
    }
    // One immutable vocabulary per isolate. The Rust/WASM encoder uses ~27 MiB
    // linear memory for o200k, versus ~72 MiB JS heap for js-tiktoken's maps.
    tokenizer ??= new Tiktoken(ranks.bpe_ranks, ranks.special_tokens, ranks.pat_str);
    // User/file content that resembles special tokens remains ordinary text.
    return tokenizer.encode_ordinary(serialized).length;
}
