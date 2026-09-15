import { afterEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";
import { Agent, type SessionSnapshot } from "nanocodex/browser";
import { GroqBridge } from "./bridge";
import { type JsonObject } from "./protocol";

// This loads the published binary, not a mock or a recompiled/forked nanocodex.
const module = readFileSync(fileURLToPath(import.meta.resolve("nanocodex/wasm")));
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
    for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function response(events: JsonObject[]): Response {
    return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""), {
        headers: { "content-type": "text/event-stream" },
    });
}
function answer(id: string, text: string): JsonObject[] {
    const item = {
        type: "message",
        id: `msg-${id}`,
        status: "completed",
        role: "assistant",
        content: [{ type: "output_text", text, annotations: [] }],
    };
    return [
        { type: "response.created", response: { id, status: "in_progress", output: [] } },
        {
            type: "response.output_item.added",
            output_index: 0,
            item: { ...item, status: "in_progress", content: [] },
        },
        { type: "response.output_text.delta", output_index: 0, delta: text },
        { type: "response.output_item.done", output_index: 0, item },
        {
            type: "response.completed",
            response: {
                id,
                status: "completed",
                output: [item],
                usage: { input_tokens: 10, output_tokens: 3, total_tokens: 13 },
            },
        },
    ];
}
async function peer(fetcher: typeof fetch) {
    const server = new WebSocketServer({ host: "127.0.0.1", port: 0 });
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const abort = new AbortController();
    const bridge = new GroqBridge({ apiKey: "fake-for-test", signal: abort.signal, fetcher });
    let failure: unknown;
    server.on("connection", (socket) => {
        socket.on("message", (bytes) => {
            void bridge
                .receive(bytes.toString(), (event) => socket.send(JSON.stringify(event)))
                .catch((error) => {
                    failure = error;
                    socket.close(1011, "test bridge failed");
                });
        });
    });
    cleanups.push(async () => {
        abort.abort();
        for (const socket of server.clients) socket.terminate();
        await new Promise<void>((resolve) => server.close(() => resolve()));
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Missing peer port");
    return {
        url: `ws://127.0.0.1:${address.port}`,
        bridge,
        check() {
            if (failure) throw failure;
        },
    };
}

describe("unchanged nanocodex 0.5.0 browser binary", () => {
    it("streams, dispatches a direct tool, and resumes a saved session with full history", async () => {
        const inputs: JsonObject[][] = [];
        const broker = await peer(async (_url, init) => {
            const request = JSON.parse(String(init?.body));
            inputs.push(request.input);
            if (inputs.length === 1) {
                const item = {
                    type: "function_call",
                    id: "fc-1",
                    call_id: "call-1",
                    name: "write_file",
                    arguments: '{"path":"hello.txt","content":"Hello"}',
                    status: "completed",
                };
                return response([
                    { type: "response.output_item.done", output_index: 0, item },
                    {
                        type: "response.completed",
                        response: {
                            id: "tool-1",
                            status: "completed",
                            output: [item],
                            usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
                        },
                    },
                ]);
            }
            return response(answer(`answer-${inputs.length}`, "Created hello.txt"));
        });
        const written: unknown[] = [];
        const events: string[] = [];
        async function run(snapshot?: SessionSnapshot) {
            const agent = await Agent.create({
                module,
                hostAuth: true,
                websocketUrl: broker.url,
                resume: snapshot,
                toolMode: "direct",
                thinking: "low",
                instructions: "Use write_file then report success.",
                tools: {
                    write_file: {
                        description: "Write a project file",
                        parameters: {
                            type: "object",
                            properties: { path: { type: "string" }, content: { type: "string" } },
                            required: ["path", "content"],
                        },
                        handler: (input) => {
                            written.push(input);
                            return "Wrote hello.txt";
                        },
                    },
                },
            });
            const watcher = agent.events.watch();
            watcher.onEvent((event) => events.push(event.type));
            const turn = agent.turn.prompt({
                input: snapshot ? "Which file did you create?" : "Write hello.txt with Hello",
            });
            try {
                return await turn.result();
            } finally {
                turn.dispose();
                watcher.off();
                await agent.session.shutdown();
                agent.dispose();
            }
        }
        const first = await run();
        expect(first.finalMessage).toContain("hello.txt");
        expect(written).toEqual([{ path: "hello.txt", content: "Hello" }]);
        expect(events.some((event) => event.includes("delta"))).toBe(true);
        const second = await run(first.snapshot);
        expect(second.finalMessage).toContain("hello.txt");
        expect(JSON.stringify(inputs.at(-1))).toContain("Wrote hello.txt");
        expect(JSON.stringify(inputs.at(-1))).toContain("Which file did you create?");
        expect(broker.bridge.usage.totalTokens).toBe(41);
        broker.check();
    });

    it("isolates two concurrent browser agents and their private peers", async () => {
        const [one, two] = await Promise.all([
            peer(async () => response(answer("one", "project-one"))),
            peer(async () => response(answer("two", "project-two"))),
        ]);
        const agents = await Promise.all(
            [one, two].map((broker) =>
                Agent.create({
                    module,
                    hostAuth: true,
                    websocketUrl: broker.url,
                    toolMode: "direct",
                    tools: {},
                    thinking: "low",
                }),
            ),
        );
        try {
            const turns = agents.map((agent) => agent.turn.prompt({ input: "Name this project" }));
            const results = await Promise.all(turns.map((turn) => turn.result()));
            expect(results.map((result) => result.finalMessage)).toEqual([
                "project-one",
                "project-two",
            ]);
            for (const turn of turns) turn.dispose();
            one.check();
            two.check();
        } finally {
            for (const agent of agents) {
                await agent.session.shutdown();
                agent.dispose();
            }
        }
    });
});
