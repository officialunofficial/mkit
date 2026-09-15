/** Stateless Responses protocol validation shared by the private bridge and tests. */
export type JsonObject = Record<string, unknown>;

export class GroqError extends Error {
    constructor(
        public readonly code: string,
        message: string,
        public readonly status?: number,
        public readonly retryAfterSeconds?: number,
    ) {
        super(message);
        this.name = "GroqError";
    }
}

export const LIMITS = Object.freeze({
    requests: 12,
    historyBytes: 24_000,
    historyItems: 512,
    frameBytes: 1024 * 1024,
    streamBytes: 2 * 1024 * 1024,
    outputTokens: 4096,
    requestTimeoutMs: 30_000,
});
export type Limits = { [K in keyof typeof LIMITS]: number };

export function object(value: unknown): JsonObject {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new GroqError("invalid_protocol", "Expected a protocol object.");
    }
    return value as JsonObject;
}

export function byteLength(value: unknown): number {
    return new TextEncoder().encode(typeof value === "string" ? value : JSON.stringify(value))
        .byteLength;
}

export type Conversation = { history: JsonObject[]; tools: JsonObject[]; instructions?: string };

export function reconstruct(frame: JsonObject, previous: Conversation | undefined): Conversation {
    if (frame.type !== "response.create")
        throw new GroqError("invalid_protocol", "Unsupported request frame.");
    if (frame.previous_response_id !== undefined && !previous) {
        throw new GroqError(
            "unknown_continuation",
            "The response continuation is unknown; restore the last saved session.",
        );
    }
    const history = [...(previous?.history ?? [])];
    let tools = [...(previous?.tools ?? [])];
    if (frame.input !== undefined && !Array.isArray(frame.input)) {
        throw new GroqError("invalid_protocol", "Expected an input array.");
    }
    for (const value of frame.input ?? []) {
        const item = object(value);
        if (item.type === "additional_tools") {
            if (!Array.isArray(item.tools))
                throw new GroqError("invalid_protocol", "Expected tool definitions.");
            tools = item.tools.map(object);
        } else {
            // IDs are nanocodex's local history identity, not Groq's stored item references.
            const { id: _id, ...copy } = item;
            history.push(copy);
        }
    }
    if (frame.tools !== undefined) {
        if (!Array.isArray(frame.tools))
            throw new GroqError("invalid_protocol", "Expected tool definitions.");
        tools = frame.tools.map(object);
    }
    const instructions =
        typeof frame.instructions === "string" ? frame.instructions : previous?.instructions;
    return { history, tools, ...(instructions ? { instructions } : {}) };
}

export function validateHistory(conversation: Conversation, limits: Limits): void {
    if (
        conversation.history.length > limits.historyItems ||
        byteLength(conversation) > limits.historyBytes
    ) {
        throw new GroqError(
            "history_limit",
            "This conversation is full. Select New conversation to continue.",
        );
    }
}

export type GroqUsage = {
    provider: "groq";
    model: string;
    inputTokens: number;
    outputTokens: number;
    totalTokens: number;
};

export function usageOf(response: JsonObject, model: string): GroqUsage | undefined {
    if (response.usage === undefined || response.usage === null) return undefined;
    const usage = object(response.usage);
    for (const key of ["input_tokens", "output_tokens", "total_tokens"]) {
        if (!Number.isSafeInteger(usage[key]) || Number(usage[key]) < 0) {
            throw new GroqError(
                "invalid_usage",
                "The model service returned invalid token accounting.",
            );
        }
    }
    return {
        provider: "groq",
        model,
        inputTokens: Number(usage.input_tokens),
        outputTokens: Number(usage.output_tokens),
        totalTokens: Number(usage.total_tokens),
    };
}

export function completedResponse(frame: JsonObject): JsonObject | undefined {
    if (["error", "response.failed", "response.incomplete"].includes(String(frame.type))) {
        const response =
            frame.response && typeof frame.response === "object"
                ? object(frame.response)
                : undefined;
        const failure =
            response?.error && typeof response.error === "object" ? object(response.error) : frame;
        // Classify known failures, but never expose provider bodies or generated arguments.
        if (
            String(failure.code) === "tool_use_failed" ||
            String(failure.message).includes("tool_use_failed")
        )
            throw new GroqError(
                "upstream_tool_call",
                "The agent could not finish a file or command request. Try a smaller change.",
            );
        const details = response?.incomplete_details;
        if (
            details &&
            typeof details === "object" &&
            object(details).reason === "max_output_tokens"
        )
            throw new GroqError(
                "output_limit",
                "The agent reached its response limit. Try a smaller change.",
            );
        throw new GroqError(
            "upstream_incomplete",
            "The model service interrupted the response. Please try again.",
        );
    }
    if (frame.type !== "response.completed") return undefined;
    const response = object(frame.response);
    if (
        typeof response.id !== "string" ||
        response.status !== "completed" ||
        !Array.isArray(response.output)
    ) {
        throw new GroqError(
            "invalid_completion",
            "The model service returned an invalid completed response.",
        );
    }
    for (const output of response.output) {
        const item = object(output);
        if (item.type === "function_call") {
            if (
                typeof item.call_id !== "string" ||
                typeof item.name !== "string" ||
                typeof item.arguments !== "string"
            ) {
                throw new GroqError(
                    "invalid_tool_call",
                    "The model service returned an incomplete function call.",
                );
            }
            // A partial streamed call must never reach the tool dispatcher.
            try {
                object(JSON.parse(item.arguments));
            } catch {
                throw new GroqError(
                    "invalid_tool_call",
                    "The model service returned invalid function arguments.",
                );
            }
        }
    }
    return response;
}

export function retryAfter(headers: Headers, now = Date.now()): number | undefined {
    const value = headers.get("retry-after");
    if (!value) return undefined;
    const seconds = Number(value);
    const parsed = Number.isFinite(seconds) ? seconds : (Date.parse(value) - now) / 1000;
    return Number.isFinite(parsed) ? Math.max(0, Math.ceil(parsed)) : undefined;
}

/** Incremental SSE parser: CRLF, multiline data, UTF-8 and chunk boundaries are independent. */
export async function* sseFrames(
    body: ReadableStream<Uint8Array>,
    maxBytes: number,
): AsyncGenerator<JsonObject> {
    const reader = body.getReader();
    const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
    let total = 0;
    let pending = "";
    let data: string[] = [];
    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > maxBytes)
                throw new GroqError("stream_limit", "The model response exceeded its size limit.");
            pending += decoder.decode(value, { stream: true });
            let newline: number;
            while ((newline = pending.indexOf("\n")) !== -1) {
                const line = pending.slice(0, newline).replace(/\r$/, "");
                pending = pending.slice(newline + 1);
                if (line === "") {
                    if (data.length) {
                        const payload = data.join("\n");
                        data = [];
                        if (payload === "[DONE]") return;
                        try {
                            yield object(JSON.parse(payload));
                        } catch (error) {
                            if (error instanceof GroqError) throw error;
                            throw new GroqError(
                                "invalid_stream",
                                "The model service returned invalid event data.",
                            );
                        }
                    }
                } else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
            }
        }
        pending += decoder.decode();
        if (pending.trim() || data.length)
            throw new GroqError(
                "truncated_stream",
                "The model service ended an incomplete event stream.",
            );
    } finally {
        await reader.cancel().catch(() => {});
        reader.releaseLock();
    }
}
