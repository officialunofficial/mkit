import { beforeEach, describe, expect, it, vi } from "vitest";
import { runWorkspaceTask } from "./workspace-runner";
import { runAgent, type SessionSnapshot } from "./nanocodex";
import type { WorkspaceState } from "./workspace-state";
import type { SandboxWorkspace } from "./sandbox-files";
import type { WorkspaceTask } from "./contracts";
vi.mock("./nanocodex", async () => ({
    runAgent: vi.fn(),
    GroqError: (await import("./groq/protocol")).GroqError,
}));
const snapshot: SessionSnapshot = {
    version: 1,
    model: "model",
    lineage_id: "lineage",
    prompt_cache_key: "cache",
    workspace: "/workspace/project",
    canonical_context: {},
    history: [],
};
const task: WorkspaceTask = {
    id: "task",
    status: "running",
    prompt: "private prompt",
    createdAt: 1,
};
const files = { "main.js": { hash: "a".repeat(64), size: 3, mode: "blob" } };
function harness() {
    const data = new Map<string, unknown>([
        ["task", { ...task }],
        ["files", {}],
        ["generation", "one"],
        ["meta", { head: "old", updatedAt: 1 }],
    ]);
    const storage = {
        get: vi.fn(async (key: string) => data.get(key)),
        put: vi.fn(async (writes: Record<string, unknown>) => {
            for (const [key, value] of Object.entries(writes)) data.set(key, value);
        }),
        transaction: async (callback: (value: unknown) => Promise<unknown>) => callback(storage),
    };
    const state = {
        storage,
        files: vi.fn(async () => data.get("files")),
        summary: vi.fn(async () => data.get("meta")),
        requireAgent: vi.fn(async () => {
            if (data.get("revoked")) throw new Error("Agent revoked");
        }),
        publishedVersion: vi.fn(async () => ({
            writes: { meta: { head: "new", updatedAt: 4 }, "manifest:new": data.get("files") },
        })),
        message: vi.fn((role: string, text: string) => ({ message: { role, text } })),
    };
    const sandbox = {
        ensure: vi.fn().mockResolvedValue(undefined),
        capture: vi.fn().mockResolvedValue(files),
        write: vi.fn().mockResolvedValue(undefined),
        read: vi.fn().mockResolvedValue("hi"),
        exec: vi.fn().mockResolvedValue({ stdout: "ok", stderr: "", exitCode: 0 }),
    };
    const directory = {
        reserveModel: vi.fn().mockResolvedValue({ retryAfter: 0 }),
        settleModel: vi.fn().mockResolvedValue(undefined),
        publish: vi.fn().mockResolvedValue(undefined),
    };
    const env = {
        DIRECTORY: { getByName: vi.fn(() => directory) },
        GROQ_API_KEY: "server-only-secret",
        GROQ_MODEL: "openai/gpt-oss-120b",
    };
    let queue = Promise.resolve();
    function serial<T>(fn: () => Promise<T>): Promise<T> {
        const result = queue.then(fn);
        queue = result.then(
            () => {},
            () => {},
        );
        return result;
    }
    const controller = new AbortController();
    const input = {
        state: state as unknown as WorkspaceState,
        sandbox: sandbox as unknown as SandboxWorkspace,
        env: env as unknown as Env,
        serial,
        task,
        signal: controller.signal,
    };
    return { data, storage, state, sandbox, directory, controller, input };
}
const context = { callId: "call", parentCallId: "", sessionId: "session" };
beforeEach(() => vi.clearAllMocks());
describe("durable workspace task execution", () => {
    it("saves tool edits and publishes completion, snapshot, and owner answer together", async () => {
        const h = harness();
        vi.mocked(runAgent).mockImplementation(async (options) => {
            await options.beforeRequest?.({ inputTokens: 100, maxOutputTokens: 100 });
            await options.onUsage?.({
                provider: "groq",
                model: "openai/gpt-oss-120b",
                inputTokens: 12,
                outputTokens: 8,
                totalTokens: 20,
            });
            await options.tools.write_file.handler({ path: "main.js", content: "new" }, context);
            return {
                finalMessage: "Created main.js",
                snapshot: snapshot,
                usage: {
                    provider: "groq",
                    model: "openai/gpt-oss-120b",
                    inputTokens: 12,
                    outputTokens: 8,
                    totalTokens: 20,
                },
            };
        });
        await runWorkspaceTask(h.input);
        expect(h.sandbox.write).toHaveBeenCalledWith("main.js", "new");
        expect(h.state.publishedVersion).toHaveBeenCalledWith(files, "Complete agent task");
        expect(h.data.get("task")).toMatchObject({ status: "completed", versionHash: "new" });
        expect(h.directory.settleModel).toHaveBeenCalledWith(expect.stringContaining("task:"), 20);
        expect(h.directory.publish).toHaveBeenCalled();
        const completion = h.storage.put.mock.calls.find(([writes]) => "snapshot" in writes)?.[0];
        expect(completion).toMatchObject({
            task: { status: "completed" },
            "manifest:new": files,
            message: { role: "assistant", text: "Created main.js" },
        });
        expect(JSON.stringify(h.sandbox.write.mock.calls)).not.toContain("server-only-secret");
    });
    it("retains partial edits after a model failure without publishing a completed version", async () => {
        const h = harness();
        vi.mocked(runAgent).mockImplementation(async (options) => {
            await options.tools.write_file.handler({ path: "main.js", content: "new" }, context);
            throw new Error("Provider failed");
        });
        await runWorkspaceTask(h.input);
        expect(h.data.get("files")).toEqual(files);
        expect(h.data.get("task")).toMatchObject({ status: "failed", error: "Provider failed" });
        expect(h.state.publishedVersion).not.toHaveBeenCalled();
    });
    it("allows cancellation during a running command, retaining partial files without signing", async () => {
        const h = harness();
        let finish!: () => void;
        h.sandbox.exec.mockImplementation(
            () =>
                new Promise((resolve) => {
                    finish = () => resolve({ stdout: "", stderr: "", exitCode: 0 });
                }),
        );
        vi.mocked(runAgent).mockImplementation(async (options) => {
            await options.tools.command.handler({ command: "long-running" }, context);
            throw new Error("Should have been cancelled");
        });
        const run = runWorkspaceTask(h.input);
        await vi.waitFor(() => expect(h.sandbox.exec).toHaveBeenCalled());
        await h.input.serial(async () => {
            h.data.set("task", { ...task, status: "cancelled" });
            h.controller.abort();
        });
        finish();
        await run;
        expect(h.data.get("files")).toEqual(files);
        expect(h.data.get("task")).toMatchObject({ status: "cancelled" });
        expect(h.state.publishedVersion).not.toHaveBeenCalled();
    });
    it("rejects stale capture and never overwrites the newer durable draft", async () => {
        const h = harness();
        h.sandbox.capture.mockImplementation(async () => {
            h.data.set("generation", "newer");
            h.data.set("files", { newer: true });
            return files;
        });
        vi.mocked(runAgent).mockImplementation(async (options) => {
            await options.tools.write_file.handler({ path: "main.js", content: "new" }, context);
            throw new Error("unreachable");
        });
        await runWorkspaceTask(h.input);
        expect(h.data.get("files")).toEqual({ newer: true });
        expect(h.state.publishedVersion).not.toHaveBeenCalled();
        expect(h.data.get("task")).toMatchObject({ status: "failed" });
    });
    it("does not publish a version if delegation is revoked after the model finishes", async () => {
        const h = harness();
        vi.mocked(runAgent).mockImplementation(async () => {
            h.data.set("revoked", true);
            return {
                finalMessage: "done",
                snapshot: snapshot,
                usage: {
                    provider: "groq",
                    model: "openai/gpt-oss-120b",
                    inputTokens: 0,
                    outputTokens: 0,
                    totalTokens: 0,
                },
            };
        });
        await runWorkspaceTask(h.input);
        expect(h.state.publishedVersion).not.toHaveBeenCalled();
        expect(h.data.get("task")).toMatchObject({ status: "failed", error: "Agent revoked" });
    });
});
it("bounds free-tier waiting to one minute and one admission retry", async () => {
    vi.useFakeTimers();
    try {
        const h = harness();
        h.directory.reserveModel.mockResolvedValue({ retryAfter: 120 });
        vi.mocked(runAgent).mockImplementation(async (options) => {
            await options.beforeRequest?.({ inputTokens: 100, maxOutputTokens: 100 });
            throw new Error("Unexpected admission");
        });
        const running = runWorkspaceTask(h.input);
        await vi.waitFor(() => expect(h.directory.reserveModel).toHaveBeenCalledTimes(1));
        await vi.advanceTimersByTimeAsync(60_000);
        await running;
        expect(h.directory.reserveModel).toHaveBeenCalledTimes(2);
        expect(h.data.get("task")).toMatchObject({
            status: "failed",
            error: "The shared model allowance is busy. Your changes are saved; try again later.",
        });
        expect(h.state.publishedVersion).not.toHaveBeenCalled();
    } finally {
        vi.useRealTimers();
    }
});
it("returns file pages instead of overflowing provider history with a large file", async () => {
    const h = harness();
    h.sandbox.read.mockResolvedValue("x".repeat(10_000));
    vi.mocked(runAgent).mockImplementation(async (options) => {
        const page = await options.tools.read_file.handler({ path: "main.js" }, context);
        expect(page).toMatchObject({
            content: "x".repeat(2000),
            nextOffset: 2000,
            totalCharacters: 10_000,
        });
        const next = await options.tools.read_file.handler(
            { path: "main.js", offset: 2000, limit: 100 },
            context,
        );
        expect(next).toMatchObject({ content: "x".repeat(100), nextOffset: 2100 });
        throw new Error("test stops after reading");
    });
    await runWorkspaceTask(h.input);
});
it("preserves the daily model cap error and never treats it as admission", async () => {
    const h = harness();
    h.directory.reserveModel.mockImplementation(async () => ({
        retryAfter: 0,
        error: { status: 429, message: "Daily allowance used up." },
    }));
    const admitted = vi.fn();
    vi.mocked(runAgent).mockImplementation(async (options) => {
        await options.beforeRequest?.({ inputTokens: 100, maxOutputTokens: 100 });
        admitted();
        throw new Error("Unexpected model call");
    });
    await runWorkspaceTask(h.input);
    expect(admitted).not.toHaveBeenCalled();
    expect(h.directory.reserveModel).toHaveBeenCalledTimes(1);
    expect(h.data.get("task")).toMatchObject({
        status: "failed",
        error: "Daily allowance used up.",
    });
    expect(h.state.publishedVersion).not.toHaveBeenCalled();
});
