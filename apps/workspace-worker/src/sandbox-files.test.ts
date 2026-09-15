import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
    mkdtemp,
    realpath,
    mkdir,
    readFile,
    writeFile,
    chmod,
    symlink,
    link,
    rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SANDBOX_FILES_PROGRAM, SandboxWorkspace, shellQuote } from "./sandbox-files";
import { getBlob, putBlob, type ObjectStorage } from "./objects";

const sdk = vi.hoisted(() => ({ getSandbox: vi.fn() }));
vi.mock("@cloudflare/sandbox", async () => {
    // Exercise the installed SDK's real SSE parser. Bundle away Worker-only
    // classes so this filesystem test can also run under Node without Docker.
    const { build } = await import("esbuild");
    const bundled = await build({
        stdin: {
            contents: "export { parseSSEStream } from '@cloudflare/sandbox'",
            resolveDir: process.cwd(),
        },
        bundle: true,
        format: "esm",
        platform: "node",
        write: false,
        plugins: [
            {
                name: "worker-only-classes",
                setup(builder) {
                    builder.onResolve(
                        { filter: /^(cloudflare:workers|@cloudflare\/containers)$/ },
                        (args) => ({ path: args.path, namespace: "worker-stub" }),
                    );
                    builder.onLoad({ filter: /.*/, namespace: "worker-stub" }, () => ({
                        contents:
                            "export class Container {}; export class ContainerProxy {}; export class RpcTarget {}; export const tracing = {}; export const getContainer = () => {}; export const switchPort = () => {};",
                    }));
                },
            },
        ],
    });
    const parser = await import(
        /* @vite-ignore */ `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].text).toString("base64")}`
    );
    return { ...sdk, parseSSEStream: parser.parseSSEStream };
});
const execute = promisify(execFile);
let directory: string;
let root: string;
let marker: string;
beforeEach(async () => {
    directory = await realpath(await mkdtemp(join(tmpdir(), "mkit-sandbox-files-")));
    root = join(directory, "project");
    marker = join(directory, "generation");
    await mkdir(root);
    await writeFile(marker, "one");
});
afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
    vi.clearAllMocks();
});
async function helper(payload: Record<string, unknown>) {
    try {
        const result = await execute(
            "python3",
            ["-I", "-c", SANDBOX_FILES_PROGRAM, JSON.stringify({ root, marker, ...payload })],
            { maxBuffer: 8 * 1024 * 1024 },
        );
        return JSON.parse(result.stdout);
    } catch (error) {
        throw new Error((error as { stderr: string }).stderr);
    }
}
class MemoryObjects implements ObjectStorage {
    readonly objects = new Map<string, Uint8Array>();
    async get(key: string) {
        const value = this.objects.get(key);
        return value
            ? { size: value.length, arrayBuffer: async () => new Uint8Array(value).buffer }
            : null;
    }
    async put(key: string, value: Uint8Array) {
        this.objects.set(key, value.slice());
    }
}
function sandboxMock() {
    const exec = vi.fn(async (command: string) => {
        const result = await execute(
            "/bin/sh",
            [
                "-c",
                command
                    .replace("/usr/bin/python3", "python3")
                    .replaceAll("/workspace/project", root)
                    .replaceAll("/tmp/mkit-generation", marker),
            ],
            { maxBuffer: 8 * 1024 * 1024 },
        );
        return { ...result, exitCode: 0, success: true };
    });
    const sandbox = {
        exec,
        createSession: vi.fn(),
        getSession: vi.fn(),
        deleteSession: vi.fn().mockResolvedValue({ success: true }),
        destroy: vi.fn().mockResolvedValue(undefined),
    };
    sdk.getSandbox.mockReturnValue(sandbox);
    return sandbox;
}

describe("safe filesystem capture", () => {
    it("captures binary data and executable modes, excluding dependency and cache directories", async () => {
        await writeFile(join(root, "binary.dat"), Buffer.from([0, 255, 128]));
        await writeFile(join(root, "run.sh"), "echo hello");
        await chmod(join(root, "run.sh"), 0o755);
        await mkdir(join(root, "node_modules"));
        await writeFile(join(root, "node_modules", "ignored"), "dependency");
        const files = await helper({ action: "capture", generation: "one" });
        expect(files).toEqual({
            "binary.dat": { content: "AP+A", mode: "blob" },
            "run.sh": { content: Buffer.from("echo hello").toString("base64"), mode: "exec" },
        });
    });
    it("refuses stale generation and oversized source files without dropping them", async () => {
        await expect(helper({ action: "capture", generation: "two" })).rejects.toThrow(
            "stale capture",
        );
        await writeFile(join(root, "large.txt"), Buffer.alloc(256 * 1024 + 1));
        await expect(helper({ action: "capture", generation: "one" })).rejects.toThrow("256 KiB");
    });
    it("refuses symlinks and hard links that could capture outside files", async () => {
        const outside = join(directory, "outside");
        await writeFile(outside, "not project content");
        await symlink(outside, join(root, "escape"));
        await expect(helper({ action: "capture", generation: "one" })).rejects.toThrow("regular");
        await expect(helper({ action: "read", path: "escape" })).rejects.toThrow("regular");
        await rm(join(root, "escape"));
        await link(outside, join(root, "escape"));
        await expect(helper({ action: "capture", generation: "one" })).rejects.toThrow("regular");
    });
    it("never writes through a symlinked directory or a symlinked file", async () => {
        const outside = join(directory, "outside");
        await mkdir(outside);
        await writeFile(join(outside, "file"), "original");
        await symlink(outside, join(root, "nested"));
        await expect(
            helper({ action: "write", path: "nested/file", content: "bmV3" }),
        ).rejects.toThrow();
        await symlink(join(outside, "file"), join(root, "file"));
        await expect(helper({ action: "write", path: "file", content: "bmV3" })).rejects.toThrow();
        expect(await readFile(join(outside, "file"), "utf8")).toBe("original");
        await expect(
            helper({ action: "write", path: "../outside/file", content: "bmV3" }),
        ).rejects.toThrow("Invalid workspace path");
    });
    it("clears symlinks on reset without clearing their target", async () => {
        const outside = join(directory, "outside");
        await mkdir(outside);
        await writeFile(join(outside, "file"), "original");
        await symlink(outside, join(root, "nested"));
        await helper({ action: "reset" });
        expect(await readFile(join(outside, "file"), "utf8")).toBe("original");
        expect(await readFile(marker, "utf8")).toBe("");
    });
    it("keeps shell metacharacters literal in helper arguments", async () => {
        const value = `quotes'\"\n$(touch should-not-exist); text`;
        const result = await execute("/bin/sh", ["-c", `printf %s ${shellQuote(value)}`], {
            cwd: root,
        });
        expect(result.stdout).toBe(value);
    });
});

describe("durable object hydration", () => {
    it("rehydrates bounded chunks, preserves existing matching generations, and captures real blobs", async () => {
        const sandbox = sandboxMock();
        const objects = new MemoryObjects();
        const bytes = new Uint8Array(100 * 1024).fill(255);
        const hash = await putBlob(objects, bytes);
        const workspace = new SandboxWorkspace(
            {} as DurableObjectNamespace<import("@cloudflare/sandbox").Sandbox>,
            "id",
            objects,
        );
        await workspace.ensure({ "src/binary": { hash, size: bytes.length, mode: "exec" } }, "two");
        expect(new Uint8Array(await readFile(join(root, "src/binary")))).toEqual(bytes);
        await writeFile(join(root, "draft.txt"), "kept");
        await workspace.ensure({ "src/binary": { hash, size: bytes.length, mode: "exec" } }, "two");
        expect(await readFile(join(root, "draft.txt"), "utf8")).toBe("kept");
        const captured = await workspace.capture("two");
        expect(await getBlob(objects, captured["src/binary"].hash)).toEqual(bytes);
        expect(captured["src/binary"].mode).toBe("exec");
        expect(captured["draft.txt"].size).toBe(4);
        expect(sandbox.exec.mock.calls.every(([command]) => command.length < 128 * 1024)).toBe(
            true,
        );
    });
    it("propagates cancellation and deletes the underlying command session", async () => {
        const sandbox = sandboxMock();
        const cancelled = vi.fn();
        const execStream = vi.fn(async (_command: string, options: unknown) => {
            structuredClone(options);
            return new ReadableStream<Uint8Array>({ cancel: cancelled });
        });
        sandbox.createSession.mockResolvedValue({ id: "command", execStream });
        const workspace = new SandboxWorkspace(
            {} as DurableObjectNamespace<import("@cloudflare/sandbox").Sandbox>,
            "id",
            new MemoryObjects(),
        );
        const controller = new AbortController();
        const result = workspace.exec("sleep 120", controller.signal);
        await vi.waitFor(() => expect(execStream).toHaveBeenCalled());
        controller.abort();
        await expect(result).rejects.toThrow();
        expect(sandbox.deleteSession).toHaveBeenCalledWith("command");
        expect(cancelled).toHaveBeenCalled();
        expect(execStream.mock.calls[0]?.[1]).toEqual({
            cwd: "/workspace/project",
            timeout: 60000,
        });
    });
});

it("caps runaway command output and terminates its session", async () => {
    const sandbox = sandboxMock();
    sandbox.createSession.mockResolvedValue({
        id: "command",
        execStream: vi.fn(
            async () =>
                new ReadableStream<Uint8Array>({
                    start(controller) {
                        controller.enqueue(
                            new TextEncoder().encode(
                                `data: ${JSON.stringify({ type: "stdout", data: "x".repeat(100 * 1024) })}\n\n`,
                            ),
                        );
                    },
                }),
        ),
    });
    const workspace = new SandboxWorkspace(
        {} as DurableObjectNamespace<import("@cloudflare/sandbox").Sandbox>,
        "id",
        new MemoryObjects(),
    );
    const result = await workspace.exec("yes");
    expect(result.exitCode).toBe(137);
    expect(new TextEncoder().encode(result.stdout + result.stderr).length).toBeLessThanOrEqual(
        64 * 1024,
    );
    expect(sandbox.deleteSession).toHaveBeenCalledWith("command");
});
it("creates the PTY session explicitly instead of assuming getSession checks existence", async () => {
    const sandbox = sandboxMock();
    const terminal = vi.fn().mockResolvedValue(new Response("terminal"));
    sandbox.createSession.mockResolvedValue({ terminal });
    const workspace = new SandboxWorkspace(
        {} as DurableObjectNamespace<import("@cloudflare/sandbox").Sandbox>,
        "id",
        new MemoryObjects(),
    );
    await workspace.terminal(new Request("https://mkit.sh/terminal"));
    expect(sandbox.createSession).toHaveBeenCalledWith({
        id: "project",
        cwd: "/workspace/project",
        commandTimeoutMs: 60000,
    });
    expect(terminal).toHaveBeenCalled();
});
it("stops the persistent terminal and propagates unexpected cleanup failures", async () => {
    const sandbox = sandboxMock();
    const workspace = new SandboxWorkspace(
        {} as DurableObjectNamespace<import("@cloudflare/sandbox").Sandbox>,
        "id",
        new MemoryObjects(),
    );
    await workspace.stopTerminal();
    expect(sandbox.deleteSession).toHaveBeenCalledWith("project");
    sandbox.deleteSession.mockRejectedValueOnce(
        Object.assign(new Error("missing"), { name: "SessionNotFoundError" }),
    );
    await expect(workspace.stopTerminal()).resolves.toBeUndefined();
    sandbox.deleteSession.mockRejectedValueOnce(new Error("transport failed"));
    await expect(workspace.stopTerminal()).rejects.toThrow("transport failed");
});
it("accepts only the actual SDK missing-project message when its error class is lost", async () => {
    const sandbox = sandboxMock();
    const workspace = new SandboxWorkspace(
        {} as DurableObjectNamespace<import("@cloudflare/sandbox").Sandbox>,
        "id",
        new MemoryObjects(),
    );
    sandbox.deleteSession.mockRejectedValueOnce(new Error("Session 'project' not found"));
    await expect(workspace.stopTerminal()).resolves.toBeUndefined();
    sandbox.deleteSession.mockRejectedValueOnce({ message: "Session 'project' not found" });
    await expect(workspace.stopTerminal()).resolves.toBeUndefined();
    sandbox.deleteSession.mockRejectedValueOnce(new Error("Session 'other' not found"));
    await expect(workspace.stopTerminal()).rejects.toThrow("Session 'other' not found");
});
it("reads split SSE frames locally and preserves command exit status over serializable RPC options", async () => {
    const sandbox = sandboxMock();
    const events = [
        { type: "start", command: "check" },
        { type: "stdout", data: "normal output\n" },
        { type: "stderr", data: "test failure\n" },
        { type: "complete", exitCode: 7 },
    ];
    const wire = new TextEncoder().encode(
        events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""),
    );
    const execStream = vi.fn(async (_command: string, options: unknown) => {
        expect(options).toEqual({ cwd: "/workspace/project", timeout: 60000 });
        return new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(wire.subarray(0, 17));
                controller.enqueue(wire.subarray(17, 101));
                controller.enqueue(wire.subarray(101));
                controller.close();
            },
        });
    });
    sandbox.createSession.mockResolvedValue({ id: "command", execStream });
    const workspace = new SandboxWorkspace(
        {} as DurableObjectNamespace<import("@cloudflare/sandbox").Sandbox>,
        "id",
        new MemoryObjects(),
    );
    await expect(workspace.exec("check")).resolves.toEqual({
        stdout: "normal output\n",
        stderr: "test failure\n",
        exitCode: 7,
    });
    expect(sandbox.deleteSession).toHaveBeenCalledWith("command");
});
it("cancels a late RPC stream after the caller has already aborted", async () => {
    const sandbox = sandboxMock();
    let resolveStream!: (stream: ReadableStream<Uint8Array>) => void;
    const execStream = vi.fn(
        () =>
            new Promise<ReadableStream<Uint8Array>>((resolve) => {
                resolveStream = resolve;
            }),
    );
    sandbox.createSession.mockResolvedValue({ id: "command", execStream });
    const workspace = new SandboxWorkspace(
        {} as DurableObjectNamespace<import("@cloudflare/sandbox").Sandbox>,
        "id",
        new MemoryObjects(),
    );
    const controller = new AbortController();
    const running = workspace.exec("check", controller.signal);
    await vi.waitFor(() => expect(execStream).toHaveBeenCalled());
    controller.abort();
    await expect(running).rejects.toThrow();
    const cancelled = vi.fn();
    resolveStream(new ReadableStream<Uint8Array>({ cancel: cancelled }));
    await vi.waitFor(() => expect(cancelled).toHaveBeenCalled());
    expect(sandbox.deleteSession).toHaveBeenCalledWith("command");
});

it("opens a fresh sandbox connection after the previous Durable Object instance retires", async () => {
    const oldSandbox = sandboxMock();
    const workspace = new SandboxWorkspace(
        {} as DurableObjectNamespace<import("@cloudflare/sandbox").Sandbox>,
        "id",
        new MemoryObjects(),
    );
    await workspace.stopTerminal();
    oldSandbox.deleteSession.mockRejectedValue(
        new Error(
            "Connection closed: this Durable Object instance is no longer active. Reconnect or retry the request.",
        ),
    );
    const currentSandbox = sandboxMock();
    await expect(workspace.stopTerminal()).resolves.toBeUndefined();
    expect(currentSandbox.deleteSession).toHaveBeenCalledWith("project");
});
