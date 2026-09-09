import { Agent, type AgentEvent, type SessionSnapshot, type ToolMap } from "nanocodex/browser";
import wasmModule from "../vendor/nanocodex.wasm";
import { GroqBridge, GroqError, type BridgeOptions, type GroqUsage } from "./groq/bridge";
import { byteLength, type Limits } from "./groq/protocol";

export type { SessionSnapshot, ToolMap, GroqUsage };
export { GroqError };

export type AgentRunOptions = {
    prompt: string;
    snapshot?: SessionSnapshot;
    tools: ToolMap;
    apiKey: string;
    model?: string;
    signal: AbortSignal;
    limits?: Partial<Limits>;
    onEvent?: (event: AgentEvent) => void;
    onUsage?: BridgeOptions["onUsage"];
    beforeRequest?: BridgeOptions["beforeRequest"];
};

/** Run the published nanocodex WASM unchanged, with a private Groq protocol peer. */
export async function runAgent(options: AgentRunOptions): Promise<{
    finalMessage: string;
    snapshot: SessionSnapshot;
    usage: GroqUsage;
}> {
    options.signal.throwIfAborted();
    const controller = new AbortController();
    const signal = AbortSignal.any([options.signal, controller.signal]);
    const bridge = new GroqBridge({ ...options, signal });
    if (!options.prompt.trim() || byteLength(options.prompt) > 8_000) {
        throw new GroqError("prompt_limit", "Provide a task of at most 8,000 bytes.");
    }
    if (options.snapshot && byteLength(options.snapshot) > bridge.limits.historyBytes) {
        throw new GroqError(
            "history_limit",
            "The saved conversation is full. Select New conversation to continue.",
        );
    }
    let failure: unknown;
    const sockets = new Set<WebSocket>();
    const pending = new Set<Promise<void>>();
    const agent = await Agent.create({
        module: wasmModule,
        hostAuth: true,
        // The URL is metadata only: createWebSocket below never makes a network connection.
        websocketUrl: "wss://nanocodex.internal/responses",
        thinking: "low",
        toolMode: "direct",
        tools: options.tools,
        resume: options.snapshot,
        instructions:
            "You help create general code projects in an mkit workspace. Inspect files before editing. Use the provided file and command tools to complete the task, verify the result when practical, and briefly describe what changed. All workspace files are public. Never request, read, or write service credentials. Work only within the project workspace.",
        createWebSocket() {
            const pair = new WebSocketPair();
            const client = pair[0];
            const server = pair[1];
            client.accept();
            server.accept();
            sockets.add(client);
            sockets.add(server);
            server.addEventListener("message", (event) => {
                const work = bridge
                    .receive(event.data, (frame) => server.send(JSON.stringify(frame)))
                    .catch((error) => {
                        failure ??= error;
                        controller.abort(error);
                        try {
                            if (server.readyState === WebSocket.OPEN) {
                                server.send(
                                    JSON.stringify({
                                        type: "error",
                                        error: {
                                            type: "bridge_error",
                                            message: "The model request failed.",
                                        },
                                    }),
                                );
                                server.close(1011, "model request failed");
                            }
                        } catch {
                            /* Cancellation may close the private peer before this handler. */
                        }
                    });
                pending.add(work);
                void work.finally(() => pending.delete(work));
            });
            return { socket: client, serverModel: bridge.model };
        },
    });
    const watcher = agent.events.watch();
    const unsubscribe = watcher.onEvent((event) => {
        // nanocodex estimates OpenAI prices for its internal model label. Never expose
        // those costs or labels as Groq billing. Only our actual provider usage is saved.
        if (event.type.includes("usage") || event.type.includes("model")) return;
        const clean = JSON.parse(
            JSON.stringify(event, (key, value) =>
                ["usage", "estimated_cost", "cost_status", "model", "server_model"].includes(key)
                    ? undefined
                    : value,
            ),
        ) as AgentEvent;
        options.onEvent?.(clean);
    });
    const turn = agent.turn.prompt({ input: options.prompt });
    const cancel = () => {
        void turn.cancel().catch(() => {});
    };
    signal.addEventListener("abort", cancel, { once: true });
    if (signal.aborted) cancel();
    try {
        const result = await turn.result();
        if (failure) throw failure;
        signal.throwIfAborted();
        if (byteLength(result.snapshot) > bridge.limits.historyBytes) {
            throw new GroqError(
                "history_limit",
                "The completed conversation exceeded its saved history limit.",
            );
        }
        return {
            finalMessage: result.finalMessage,
            snapshot: result.snapshot,
            usage: { ...bridge.usage },
        };
    } catch (error) {
        if (failure) throw failure;
        if (options.signal.aborted) throw new GroqError("cancelled", "The task was cancelled.");
        throw error;
    } finally {
        signal.removeEventListener("abort", cancel);
        controller.abort();
        unsubscribe();
        watcher.off();
        for (const socket of sockets)
            if (socket.readyState === WebSocket.OPEN) socket.close(1000, "task finished");
        await Promise.allSettled(pending);
        turn.dispose();
        await agent.session.shutdown();
        agent.dispose();
    }
}
