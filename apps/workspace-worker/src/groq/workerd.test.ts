import { it, expect } from "vitest";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions, Response as MiniflareResponse } from "miniflare";
import { readFileSync } from "node:fs";
import { fileURLToPath, URL as NodeURL } from "node:url";

it("runs the real wrapper and private WebSocketPair in workerd, then restores its snapshot", async () => {
    const root = fileURLToPath(new NodeURL("../", import.meta.url));
    const bundled = await build({
        stdin: {
            contents: `
      import { runAgent } from './nanocodex';
      export default { async fetch(request) {
        const input = await request.json();
        const events = [], writes = [], usages = [];
        const controller = new AbortController();
        try {
        const result = await runAgent({
          apiKey: 'test-service-key', prompt: input.prompt, snapshot: input.snapshot,
          signal: controller.signal,
          onEvent: event => { events.push(event); if (input.cancel && event.type.includes('delta')) controller.abort(); },
          onUsage: usage => usages.push(usage),
          tools: { write_file: {
            description: 'Write a project file',
            parameters: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] },
            handler: input => { writes.push(input); return 'Saved hello.txt'; },
          } },
        });
        return Response.json({ ...result, events, writes, usages });
        } catch (error) { return Response.json({ code: error.code, retryAfterSeconds: error.retryAfterSeconds }, { status: 409 }); }
      } };
    `,
            resolveDir: root,
            sourcefile: "workerd-smoke.ts",
            loader: "ts",
        },
        bundle: true,
        write: false,
        format: "esm",
        platform: "browser",
        target: "es2022",
        plugins: [
            {
                name: "static-wasm",
                setup(builder) {
                    builder.onResolve({ filter: /tiktoken_bg\.wasm$/ }, () => ({
                        path: "./tiktoken.wasm",
                        external: true,
                    }));
                    builder.onResolve(
                        { filter: /(?:^nanocodex\/wasm$|\/nanocodex\.wasm$)/ },
                        () => ({ path: "./nanocodex.wasm", external: true }),
                    );
                },
            },
        ],
    });
    const requests: Record<string, unknown>[] = [];
    const mf = new Miniflare(
        convertV4MiniflareOptions({
            name: "nanocodex-smoke",
            modulesRoot: "/",
            compatibilityDate: "2026-09-09",
            compatibilityFlags: ["nodejs_compat"],
            modules: [
                { type: "ESModule", path: "/worker.mjs", contents: bundled.outputFiles[0].text },
                {
                    type: "CompiledWasm",
                    path: "/tiktoken.wasm",
                    contents: readFileSync(
                        fileURLToPath(
                            new NodeURL(
                                "../../node_modules/tiktoken/lite/tiktoken_bg.wasm",
                                import.meta.url,
                            ),
                        ),
                    ),
                },
                {
                    type: "CompiledWasm",
                    path: "/nanocodex.wasm",
                    contents: readFileSync(fileURLToPath(import.meta.resolve("nanocodex/wasm"))),
                },
            ],
            outboundService: async (request) => {
                expect(request.url).toBe("https://api.groq.com/openai/v1/responses");
                expect(request.headers.get("authorization")).toBe("Bearer test-service-key");
                const input = (await request.json()) as Record<string, unknown>;
                requests.push(input);
                if (JSON.stringify(input.input).includes("Rate limit this task")) {
                    return new MiniflareResponse("sensitive provider error", {
                        status: 429,
                        headers: { "retry-after": "17" },
                    });
                }
                const item =
                    requests.length === 1
                        ? {
                              type: "function_call",
                              id: "call-item",
                              call_id: "call-1",
                              name: "write_file",
                              arguments: '{"path":"hello.txt","content":"Hello"}',
                              status: "completed",
                          }
                        : {
                              type: "message",
                              id: `message-${requests.length}`,
                              role: "assistant",
                              status: "completed",
                              content: [
                                  {
                                      type: "output_text",
                                      text: "Created hello.txt",
                                      annotations: [],
                                  },
                              ],
                          };
                const events = [
                    {
                        type: "response.created",
                        response: { id: `r-${requests.length}`, status: "in_progress", output: [] },
                    },
                    ...(requests.length === 1
                        ? []
                        : [
                              {
                                  type: "response.output_item.added",
                                  output_index: 0,
                                  item: { ...item, content: [], status: "in_progress" },
                              },
                              {
                                  type: "response.output_text.delta",
                                  output_index: 0,
                                  delta: "Created hello.txt",
                              },
                          ]),
                    { type: "response.output_item.done", output_index: 0, item },
                    {
                        type: "response.completed",
                        response: {
                            id: `r-${requests.length}`,
                            status: "completed",
                            output: [item],
                            usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
                        },
                    },
                ];
                const sent = JSON.stringify(input.input).includes("Cancel this task")
                    ? events.slice(0, 3)
                    : events;
                return new MiniflareResponse(
                    sent.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""),
                    { headers: { "content-type": "text/event-stream" } },
                );
            },
        }),
    );
    try {
        const firstResponse = await mf.dispatchFetch("http://localhost/", {
            method: "POST",
            body: JSON.stringify({ prompt: "Create hello.txt" }),
        });
        if (firstResponse.status !== 200) throw new Error(await firstResponse.text());
        expect(firstResponse.status).toBe(200);
        const first = (await firstResponse.json()) as Record<string, unknown>;
        expect(first.finalMessage).toBe("Created hello.txt");
        expect(first.writes).toEqual([{ path: "hello.txt", content: "Hello" }]);
        expect(first.usage).toMatchObject({
            provider: "groq",
            model: "openai/gpt-oss-120b",
            totalTokens: 30,
        });
        expect(JSON.stringify(first.events)).not.toContain("estimated_cost");
        expect(JSON.stringify(first.events)).not.toContain("gpt-5.6");
        const secondResponse = await mf.dispatchFetch("http://localhost/", {
            method: "POST",
            body: JSON.stringify({
                prompt: "Which file did you create?",
                snapshot: first.snapshot,
            }),
        });
        expect(secondResponse.status).toBe(200);
        const second = (await secondResponse.json()) as Record<string, unknown>;
        expect(second.finalMessage).toBe("Created hello.txt");
        expect(JSON.stringify(requests.at(-1)?.input)).toContain("Saved hello.txt");
        expect(JSON.stringify(requests.at(-1)?.input)).toContain("Which file did you create?");
        const cancelled = await mf.dispatchFetch("http://localhost/", {
            method: "POST",
            body: JSON.stringify({ prompt: "Cancel this task", cancel: true }),
        });
        expect(await cancelled.json()).toMatchObject({ code: "cancelled" });
        const limited = await mf.dispatchFetch("http://localhost/", {
            method: "POST",
            body: JSON.stringify({ prompt: "Rate limit this task" }),
        });
        expect(await limited.json()).toEqual({ code: "rate_limited", retryAfterSeconds: 17 });
    } finally {
        await mf.dispose();
    }
}, 30_000);
