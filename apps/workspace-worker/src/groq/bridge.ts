import { INPUT_TOKEN_RESERVE, MINUTE_TOKENS } from "../model-budget";
import { countRequestTokens } from "./tokens";
import {
    byteLength,
    completedResponse,
    GroqError,
    LIMITS,
    object,
    reconstruct,
    retryAfter,
    sseFrames,
    usageOf,
    validateHistory,
    type Conversation,
    type GroqUsage,
    type JsonObject,
    type Limits,
} from "./protocol";

export const GROQ_MODEL = "openai/gpt-oss-120b";

export type BridgeOptions = {
    apiKey: string;
    model?: string;
    signal: AbortSignal;
    limits?: Partial<Limits>;
    beforeRequest?: (budget: { inputTokens: number; maxOutputTokens: number }) => Promise<void>;
    onUsage?: (usage: GroqUsage) => void | Promise<void>;
    fetcher?: typeof fetch;
};

/** Private, per-agent Responses peer. It never accepts an HTTP request or exposes a URL. */
export class GroqBridge {
    readonly limits: Limits;
    readonly model: string;
    readonly usage: GroqUsage;
    private latest?: { id: string; conversation: Conversation };
    private requests = 0;
    private busy = false;

    constructor(private readonly options: BridgeOptions) {
        this.model = options.model ?? GROQ_MODEL;
        if (this.model !== GROQ_MODEL)
            throw new GroqError(
                "unsupported_model",
                "The agent model configuration is unavailable.",
            );
        this.limits = { ...LIMITS, ...options.limits };
        // Configuration may lower the ceilings; callers cannot disable resource bounds.
        for (const key of Object.keys(LIMITS) as Array<keyof Limits>) {
            if (
                !Number.isSafeInteger(this.limits[key]) ||
                this.limits[key] < 1 ||
                this.limits[key] > LIMITS[key]
            ) {
                throw new GroqError("invalid_limit", `Invalid agent limit: ${key}.`);
            }
        }
        this.usage = {
            provider: "groq",
            model: this.model,
            inputTokens: 0,
            outputTokens: 0,
            totalTokens: 0,
        };
    }

    async receive(data: unknown, emit: (event: JsonObject) => void): Promise<void> {
        if (this.busy)
            throw new GroqError("concurrent_request", "Only one model request may run at a time.");
        this.options.signal.throwIfAborted();
        if (typeof data !== "string" || byteLength(data) > this.limits.frameBytes) {
            throw new GroqError("frame_limit", "Agent request exceeded its frame size limit.");
        }
        let frame: JsonObject;
        try {
            frame = object(JSON.parse(data));
        } catch {
            throw new GroqError("invalid_protocol", "Invalid agent request.");
        }
        const parent =
            frame.previous_response_id === this.latest?.id ? this.latest?.conversation : undefined;
        const conversation = reconstruct(frame, parent);
        validateHistory(conversation, this.limits);
        this.busy = true;
        try {
            if (frame.generate === false) {
                const response = {
                    id: `warmup-${crypto.randomUUID()}`,
                    status: "completed",
                    output: [],
                    usage: null,
                };
                this.latest = { id: response.id, conversation };
                emit({ type: "response.completed", response });
                return;
            }
            const inputTokens = countRequestTokens(conversation);
            const maxOutputTokens = Math.min(
                this.limits.outputTokens,
                MINUTE_TOKENS - INPUT_TOKEN_RESERVE - inputTokens,
            );
            if (maxOutputTokens < Math.min(1024, this.limits.outputTokens))
                throw new GroqError(
                    "history_limit",
                    "This conversation is full. Select New conversation to continue.",
                );
            let response!: Response,
                signal!: AbortSignal,
                started = 0;
            for (let attempt = 0; attempt < 2; attempt++) {
                if (++this.requests > this.limits.requests)
                    throw new GroqError(
                        "request_limit",
                        "This task reached its model request limit.",
                    );
                await this.options.beforeRequest?.({
                    inputTokens,
                    maxOutputTokens,
                });
                this.options.signal.throwIfAborted();
                signal = AbortSignal.any([
                    this.options.signal,
                    AbortSignal.timeout(this.limits.requestTimeoutMs),
                ]);
                started = Date.now();
                console.info(
                    JSON.stringify({
                        event: "groq_request",
                        phase: "start",
                        request: this.requests,
                    }),
                );
                response = await (this.options.fetcher ?? fetch)(
                    "https://api.groq.com/openai/v1/responses",
                    {
                        method: "POST",
                        headers: {
                            Authorization: `Bearer ${this.options.apiKey}`,
                            "Content-Type": "application/json",
                        },
                        body: JSON.stringify({
                            model: this.model,
                            input: conversation.history,
                            tools: conversation.tools,
                            ...(conversation.instructions
                                ? { instructions: conversation.instructions }
                                : {}),
                            tool_choice: "auto",
                            parallel_tool_calls: false,
                            max_output_tokens: maxOutputTokens,
                            reasoning: { effort: "low" },
                            stream: true,
                        }),
                        signal,
                    },
                );
                console.info(
                    JSON.stringify({
                        event: "groq_request",
                        phase: "headers",
                        status: response.status,
                        ms: Date.now() - started,
                    }),
                );
                const retry = retryAfter(response.headers);
                if (
                    response.status !== 429 ||
                    attempt !== 0 ||
                    !this.options.beforeRequest ||
                    retry === undefined ||
                    retry > 60
                )
                    break;
                await response.body?.cancel();
                await delay((retry + 1) * 1000, this.options.signal);
            }
            if (!response.ok) {
                await response.body?.cancel();
                throw new GroqError(
                    response.status === 429 ? "rate_limited" : "upstream_error",
                    response.status === 429
                        ? "The model service is at its usage limit. Try again later."
                        : `The model service request failed (HTTP ${response.status}).`,
                    response.status,
                    retryAfter(response.headers),
                );
            }
            if (
                !response.body ||
                !response.headers.get("content-type")?.includes("text/event-stream")
            ) {
                await response.body?.cancel();
                throw new GroqError(
                    "invalid_stream",
                    "The model service did not return an event stream.",
                );
            }
            let completed = false;
            for await (const event of sseFrames(response.body, this.limits.streamBytes)) {
                signal.throwIfAborted();
                const output = completedResponse(event);
                if (output) {
                    const usage = usageOf(output, this.model);
                    if (usage) {
                        this.usage.inputTokens += usage.inputTokens;
                        this.usage.outputTokens += usage.outputTokens;
                        this.usage.totalTokens += usage.totalTokens;
                        await this.options.onUsage?.(usage);
                    }
                    const outputItems = (output.output as unknown[]).map(object);
                    const next = {
                        ...conversation,
                        history: [...conversation.history, ...outputItems],
                    };
                    validateHistory(next, this.limits);
                    this.latest = { id: String(output.id), conversation: next };
                    console.info(
                        JSON.stringify({
                            event: "groq_request",
                            phase: "completed",
                            ms: Date.now() - started,
                        }),
                    );
                    completed = true;
                    emit(event);
                    break;
                }
                // Forward genuine streaming text and complete items. Function arguments are
                // assembled by Groq and validated on completion, never executed from a delta.
                if (typeof event.type === "string" && event.type.startsWith("response."))
                    emit(event);
            }
            if (!completed)
                throw new GroqError(
                    "truncated_stream",
                    "The model service ended before completing the response.",
                );
        } catch (error) {
            if (error instanceof GroqError) throw error;
            if (this.options.signal.aborted)
                throw new GroqError("cancelled", "The task was cancelled.");
            if (error instanceof Error && error.name === "TimeoutError")
                throw new GroqError("timeout", "The model service took too long to respond.");
            // Provider bodies and arbitrary network errors may contain request credentials.
            throw new GroqError("transport_error", "The model connection failed.");
        } finally {
            this.busy = false;
        }
    }
}

export { GroqError, type GroqUsage } from "./protocol";

function delay(milliseconds: number, signal: AbortSignal): Promise<void> {
    signal.throwIfAborted();
    return new Promise((resolve, reject) => {
        const abort = () => {
            clearTimeout(timer);
            reject(signal.reason);
        };
        const timer = setTimeout(() => {
            signal.removeEventListener("abort", abort);
            resolve();
        }, milliseconds);
        signal.addEventListener("abort", abort, { once: true });
        if (signal.aborted) abort();
    });
}
