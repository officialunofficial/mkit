import { describe, expect, it } from "vitest";
import { GroqBridge } from "./bridge";
import {
    completedResponse,
    GroqError,
    LIMITS,
    reconstruct,
    retryAfter,
    sseFrames,
    type JsonObject,
} from "./protocol";

const encoder = new TextEncoder();
const completed = (id = "response-1", output: JsonObject[] = []) => ({
    type: "response.completed",
    response: {
        id,
        status: "completed",
        output,
        usage: { input_tokens: 12, output_tokens: 4, total_tokens: 16 },
    },
});
function streamResponse(events: JsonObject[]) {
    return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""), {
        headers: { "content-type": "text/event-stream" },
    });
}
const user = (text: string) => ({ role: "user", content: [{ type: "input_text", text }] });

describe("private Groq Responses bridge", () => {
    it("warms up locally and reconstructs instructions, tools, and complete function history", async () => {
        const requests: JsonObject[] = [];
        const usages: number[] = [];
        const budgets: number[] = [];
        const bridge = new GroqBridge({
            apiKey: "test-key",
            signal: new AbortController().signal,
            beforeRequest: async (budget) => {
                budgets.push(budget.inputTokens);
            },
            onUsage: (usage) => {
                usages.push(usage.totalTokens);
            },
            fetcher: async (_url, init) => {
                requests.push(JSON.parse(String(init?.body)));
                return streamResponse([
                    completed(
                        `response-${requests.length}`,
                        requests.length === 1
                            ? [
                                  {
                                      type: "function_call",
                                      call_id: "call-1",
                                      name: "read_file",
                                      arguments: '{"path":"README.md"}',
                                  },
                              ]
                            : [],
                    ),
                ]);
            },
        });
        const events: JsonObject[] = [];
        await bridge.receive(
            JSON.stringify({
                type: "response.create",
                generate: false,
                instructions: "Be concise",
                input: [
                    { type: "additional_tools", tools: [{ type: "function", name: "read_file" }] },
                    user("Read README.md"),
                ],
            }),
            (event) => events.push(event),
        );
        expect(requests).toHaveLength(0);
        const warmup = events[0].response as JsonObject;
        await bridge.receive(
            JSON.stringify({ type: "response.create", previous_response_id: warmup.id, input: [] }),
            (event) => events.push(event),
        );
        await bridge.receive(
            JSON.stringify({
                type: "response.create",
                previous_response_id: "response-1",
                input: [{ type: "function_call_output", call_id: "call-1", output: "Hello" }],
            }),
            (event) => events.push(event),
        );
        expect(requests[1].input).toEqual([
            user("Read README.md"),
            {
                type: "function_call",
                call_id: "call-1",
                name: "read_file",
                arguments: '{"path":"README.md"}',
            },
            { type: "function_call_output", call_id: "call-1", output: "Hello" },
        ]);
        expect(requests[1]).toMatchObject({
            model: "openai/gpt-oss-120b",
            instructions: "Be concise",
            stream: true,
        });
        expect(requests[1]).not.toHaveProperty("previous_response_id");
        expect(usages).toEqual([16, 16]);
        expect(bridge.usage).toMatchObject({
            provider: "groq",
            model: "openai/gpt-oss-120b",
            totalTokens: 32,
        });
        expect(budgets).toHaveLength(2);
    });

    it("rejects unknown continuation without inference and bounds history and request count", async () => {
        let requests = 0;
        const bridge = new GroqBridge({
            apiKey: "test-key",
            signal: new AbortController().signal,
            limits: { requests: 1 },
            fetcher: async () => {
                requests++;
                return streamResponse([completed()]);
            },
        });
        await expect(
            bridge.receive(
                JSON.stringify({
                    type: "response.create",
                    previous_response_id: "lost",
                    input: [],
                }),
                () => {},
            ),
        ).rejects.toMatchObject({ code: "unknown_continuation" });
        await expect(
            bridge.receive(
                JSON.stringify({
                    type: "response.create",
                    input: [user("x".repeat(LIMITS.historyBytes))],
                }),
                () => {},
            ),
        ).rejects.toMatchObject({ code: "history_limit" });
        await bridge.receive(
            JSON.stringify({ type: "response.create", input: [user("Hi")] }),
            () => {},
        );
        await expect(
            bridge.receive(
                JSON.stringify({ type: "response.create", input: [user("Hi")] }),
                () => {},
            ),
        ).rejects.toMatchObject({ code: "request_limit" });
        expect(requests).toBe(1);
    });

    it("retains 429 metadata without exposing provider bodies or credentials", async () => {
        const bridge = new GroqBridge({
            apiKey: "do-not-expose",
            signal: new AbortController().signal,
            fetcher: async () =>
                new Response("secret do-not-expose", {
                    status: 429,
                    headers: { "retry-after": "23" },
                }),
        });
        await expect(
            bridge.receive(JSON.stringify({ type: "response.create", input: [] }), () => {}),
        ).rejects.toMatchObject({
            code: "rate_limited",
            status: 429,
            retryAfterSeconds: 23,
            message: "The model service is at its usage limit. Try again later.",
        });
        expect(
            retryAfter(
                new Headers({ "retry-after": "Wed, 09 Sep 2026 00:01:00 GMT" }),
                Date.parse("2026-09-09T00:00:00Z"),
            ),
        ).toBe(60);
    });

    it("aborts in-flight inference when a task is cancelled", async () => {
        const controller = new AbortController();
        let reached!: () => void;
        const started = new Promise<void>((resolve) => {
            reached = resolve;
        });
        const bridge = new GroqBridge({
            apiKey: "test",
            signal: controller.signal,
            fetcher: async (_url, init) =>
                new Promise<Response>((_resolve, reject) => {
                    init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), {
                        once: true,
                    });
                    reached();
                }),
        });
        const work = bridge.receive(
            JSON.stringify({ type: "response.create", input: [] }),
            () => {},
        );
        await started;
        controller.abort();
        await expect(work).rejects.toMatchObject({ code: "cancelled" });
    });

    it("streams text before completion and rejects truncated responses", async () => {
        let stream!: ReadableStreamDefaultController<Uint8Array>;
        const body = new ReadableStream<Uint8Array>({
            start(controller) {
                stream = controller;
            },
        });
        const bridge = new GroqBridge({
            apiKey: "test",
            signal: new AbortController().signal,
            fetcher: async () =>
                new Response(body, { headers: { "content-type": "text/event-stream" } }),
        });
        let gotDelta!: () => void;
        const delta = new Promise<void>((resolve) => {
            gotDelta = resolve;
        });
        const events: JsonObject[] = [];
        const work = bridge.receive(
            JSON.stringify({ type: "response.create", input: [] }),
            (event) => {
                events.push(event);
                gotDelta();
            },
        );
        stream.enqueue(
            encoder.encode('data: {"type":"response.output_text.delta","delta":"hello"}\n\n'),
        );
        await delta;
        expect(events).toEqual([{ type: "response.output_text.delta", delta: "hello" }]);
        stream.close();
        await expect(work).rejects.toMatchObject({ code: "truncated_stream" });
    });
});

describe("Responses protocol boundaries", () => {
    it("parses split UTF-8 and multiline CRLF SSE events", async () => {
        const bytes = encoder.encode(
            'event: response.output_text.delta\r\ndata: {"type":"response.output_text.delta",\r\ndata: "delta":"🌱"}\r\n\r\ndata: [DONE]\r\n\r\n',
        );
        const body = new ReadableStream<Uint8Array>({
            start(controller) {
                for (const byte of bytes) controller.enqueue(new Uint8Array([byte]));
                controller.close();
            },
        });
        const frames = [];
        for await (const frame of sseFrames(body, 4096)) frames.push(frame);
        expect(frames).toEqual([{ type: "response.output_text.delta", delta: "🌱" }]);
    });

    it("never accepts an incomplete tool call as a completed response", () => {
        expect(() =>
            completedResponse(
                completed("x", [
                    { type: "function_call", call_id: "a", name: "write_file", arguments: "{" },
                ]),
            ),
        ).toThrow(GroqError);
        expect(() =>
            reconstruct({ type: "response.create", previous_response_id: "missing" }, undefined),
        ).toThrow(GroqError);
    });

    it("bounds the stream even when no SSE line break arrives", async () => {
        const body = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(encoder.encode("x".repeat(100)));
                controller.close();
            },
        });
        await expect(
            (async () => {
                for await (const _frame of sseFrames(body, 50)) {
                    /* consume */
                }
            })(),
        ).rejects.toMatchObject({ code: "stream_limit" });
    });
});

it.each([true, false])(
    "retries a short provider limit only once with fresh admission (success=%s)",
    async (success) => {
        let attempts = 0,
            admissions = 0;
        const bridge = new GroqBridge({
            apiKey: "test",
            signal: new AbortController().signal,
            beforeRequest: async () => {
                admissions++;
            },
            fetcher: async () =>
                ++attempts === 2 && success
                    ? streamResponse([completed()])
                    : new Response("provider body", {
                          status: 429,
                          headers: { "retry-after": "0" },
                      }),
        });
        const run = bridge.receive(
            JSON.stringify({ type: "response.create", input: [user("Hello")] }),
            () => {},
        );
        if (success) await run;
        else await expect(run).rejects.toMatchObject({ status: 429 });
        expect(attempts).toBe(2);
        expect(admissions).toBe(2);
    },
);

it("leaves enough output room for a documentation file without spending it on extra reasoning", async () => {
    const budgets: number[] = [];
    const bridge = new GroqBridge({
        apiKey: "test",
        signal: new AbortController().signal,
        beforeRequest: async (budget) => {
            budgets.push(budget.maxOutputTokens);
        },
        fetcher: async (_url, init) => {
            const request = JSON.parse(String(init?.body));
            if (request.max_output_tokens < 3305 || request.reasoning?.effort !== "low")
                return streamResponse([
                    {
                        type: "error",
                        code: "server_error",
                        message:
                            "Failed to parse tool call arguments as JSON, code=tool_use_failed, failed_generation=REDACTED",
                    },
                ]);
            return streamResponse([
                completed("documentation", [
                    {
                        type: "function_call",
                        call_id: "write",
                        name: "write_file",
                        arguments: JSON.stringify({ path: "README.md", content: "Documentation" }),
                    },
                ]),
            ]);
        },
    });
    const events: JsonObject[] = [];
    await bridge.receive(
        JSON.stringify({ type: "response.create", input: [user("add documentation")] }),
        (event) => events.push(event),
    );
    expect(events.at(-1)?.type).toBe("response.completed");
    expect(budgets).toEqual([4096]);
});

it("reports malformed provider tool calls without echoing provider error bodies", () => {
    expect(() =>
        completedResponse({
            type: "error",
            code: "server_error",
            message: "tool_use_failed secret-provider-body",
        }),
    ).toThrowError(expect.objectContaining({ code: "upstream_tool_call" }));
});

it("fits output allowance around a longer history within the shared request budget", async () => {
    let budget: { inputTokens: number; maxOutputTokens: number } | undefined;
    let requested = 0;
    const bridge = new GroqBridge({
        apiKey: "test",
        signal: new AbortController().signal,
        beforeRequest: async (value) => {
            budget = value;
        },
        fetcher: async (_url, init) => {
            requested = JSON.parse(String(init?.body)).max_output_tokens;
            return streamResponse([completed()]);
        },
    });
    await bridge.receive(
        JSON.stringify({ type: "response.create", input: [user("word123456 ".repeat(1100))] }),
        () => {},
    );
    expect(requested).toBeLessThan(4096);
    expect(requested).toBeGreaterThanOrEqual(1024);
    expect(budget!.maxOutputTokens).toBe(requested);
    expect(budget!.inputTokens + requested + 512).toBeLessThanOrEqual(7500);
});
