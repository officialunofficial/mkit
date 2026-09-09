import type { WorkspaceTask } from "./contracts";
import { record, text } from "./http";
import { runAgent, GroqError, type SessionSnapshot, type ToolMap } from "./nanocodex";
import { MAX_FILE_BYTES, validatePath } from "./objects";
import type { SandboxWorkspace } from "./sandbox-files";
import type { WorkspaceState } from "./workspace-state";

type RunInput = {
    state: WorkspaceState;
    sandbox: SandboxWorkspace;
    env: Env;
    serial: <T>(fn: () => Promise<T>) => Promise<T>;
    signal: AbortSignal;
    task: WorkspaceTask;
};

/** Task execution belongs to the Durable Object, never the browser connection.
 * Every filesystem mutation checkpoints its bounded draft before the next model
 * request; only a successfully finished, still-authorized task publishes a version. */
export async function runWorkspaceTask({
    state,
    sandbox,
    env,
    serial,
    signal,
    task,
}: RunInput): Promise<void> {
    let generation: string | undefined;
    const currentTask = () => state.storage.get<WorkspaceTask>("task");
    async function requireRunning(): Promise<void> {
        signal.throwIfAborted();
        const current = await currentTask();
        if (current?.id !== task.id || current.status !== "running")
            throw new Error("Task is no longer running.");
        await state.requireAgent();
    }
    async function checkpoint(): Promise<void> {
        if (!generation || (await state.storage.get<string>("generation")) !== generation)
            throw new Error("Workspace changed during this task.");
        const files = await sandbox.capture(generation);
        if ((await state.storage.get<string>("generation")) !== generation)
            throw new Error("Workspace changed during capture.");
        const meta = await state.summary();
        await state.storage.put({
            files,
            meta: { ...meta, updatedAt: Math.max(Date.now(), meta.updatedAt + 1) },
        });
    }
    const parameters = (properties: Record<string, unknown>, required: string[]) => ({
        type: "object",
        properties,
        required,
        additionalProperties: false,
    });
    const pathInput = { type: "string", description: "Path relative to the project root." };
    const tools: ToolMap = {
        list_files: {
            description:
                "List a page of project files and sizes. Continue with nextOffset when present.",
            parameters: parameters({ offset: { type: "integer", minimum: 0 } }, []),
            handler: (input) =>
                serial(async () => {
                    await requireRunning();
                    const offset = pageNumber(record(input).offset, 0, 256);
                    const all = Object.entries(await state.files()).sort(([a], [b]) =>
                        a.localeCompare(b),
                    );
                    const files = [];
                    let bytes = 0;
                    for (const [path, file] of all.slice(offset)) {
                        const item = { path, size: file.size, executable: file.mode === "exec" };
                        const size = new TextEncoder().encode(JSON.stringify(item)).length;
                        if (files.length >= 32 || bytes + size > 4000) break;
                        files.push(item);
                        bytes += size;
                    }
                    const next = offset + files.length;
                    return {
                        files,
                        nextOffset: next < all.length ? next : null,
                        totalFiles: all.length,
                    };
                }),
        },
        read_file: {
            description:
                "Read a page of a UTF-8 file. Offsets and limits count characters; continue with nextOffset. Binary files are not returned as text.",
            parameters: parameters(
                {
                    path: pathInput,
                    offset: { type: "integer", minimum: 0 },
                    limit: { type: "integer", minimum: 1, maximum: 4000 },
                },
                ["path"],
            ),
            handler: (input) =>
                serial(async () => {
                    await requireRunning();
                    const value = record(input),
                        path = text(value.path, 1024, "file path");
                    validatePath(path);
                    const offset = pageNumber(value.offset, 0, MAX_FILE_BYTES),
                        limit = pageNumber(value.limit, 2000, 4000);
                    if (limit < 1) throw new Error("Read limit must be positive.");
                    const content = await sandbox.read(path),
                        end = Math.min(offset + limit, content.length);
                    return {
                        path,
                        content: content.slice(offset, end),
                        nextOffset: end < content.length ? end : null,
                        totalCharacters: content.length,
                    };
                }),
        },
        write_file: {
            description:
                "Create or replace a UTF-8 project file. Its parent directories are created if needed.",
            parameters: parameters({ path: pathInput, content: { type: "string" } }, [
                "path",
                "content",
            ]),
            handler: (input) =>
                serial(async () => {
                    await requireRunning();
                    const value = record(input),
                        path = text(value.path, 1024, "file path");
                    validatePath(path);
                    if (
                        typeof value.content !== "string" ||
                        new TextEncoder().encode(value.content).length > MAX_FILE_BYTES
                    )
                        throw new Error("File content exceeds 256 KiB.");
                    await sandbox.write(path, value.content);
                    await checkpoint();
                    await requireRunning();
                    return { path, saved: true };
                }),
        },
        command: {
            description:
                "Run a shell command in the project directory. Commands stop after 60 seconds or 64 KiB of output. File changes are saved after execution.",
            parameters: parameters({ command: { type: "string" } }, ["command"]),
            handler: async (input) => {
                await serial(requireRunning);
                const command = text(record(input).command, 8000, "command");
                // Let cancellation and revocation commit while the process is running.
                // The coordinator rejects other edits/terminal access while this task is active.
                try {
                    return await sandbox.exec(command, signal);
                } finally {
                    await serial(async () => {
                        if ((await currentTask())?.id !== task.id)
                            throw new Error("Task was replaced.");
                        await checkpoint();
                        await requireRunning();
                    });
                }
            },
        },
    };
    const directory = env.DIRECTORY.getByName("global");
    let reservation: string | undefined;
    try {
        await serial(async () => {
            await requireRunning();
            generation = await state.storage.get<string>("generation");
            if (!generation) throw new Error("Workspace generation is missing.");
            await sandbox.ensure(await state.files(), generation);
        });
        const snapshot = await state.storage.get<SessionSnapshot>("snapshot");
        const result = await runAgent({
            prompt: task.prompt,
            ...(snapshot ? { snapshot } : {}),
            tools,
            apiKey: env.GROQ_API_KEY,
            model: env.GROQ_MODEL,
            signal,
            beforeRequest: async (budget) => {
                await requireRunning();
                const id = `${task.id}:${crypto.randomUUID()}`;
                const reserve = async () => {
                    try {
                        const result = await directory.reserveModel(
                            id,
                            budget.inputTokens,
                            budget.maxOutputTokens,
                        );
                        if (result.error)
                            throw new GroqError(
                                "rate_limited",
                                result.error.message,
                                result.error.status,
                            );
                        return result;
                    } catch (error) {
                        throw new GroqError(
                            "rate_limited",
                            error instanceof Error
                                ? error.message
                                : "The shared model allowance is used up.",
                            429,
                        );
                    }
                };
                let admission = await reserve();
                if (admission.retryAfter > 0) {
                    await delay(Math.min(admission.retryAfter * 1000, 60_000), signal);
                    await requireRunning();
                    admission = await reserve();
                    if (admission.retryAfter > 0)
                        throw new GroqError(
                            "rate_limited",
                            "The shared model allowance is busy. Your changes are saved; try again later.",
                            429,
                            admission.retryAfter,
                        );
                }
                reservation = id;
            },
            onUsage: async (usage) => {
                if (reservation) {
                    await directory.settleModel(reservation, usage.totalTokens);
                    reservation = undefined;
                }
            },
        });
        await serial(async () => {
            await requireRunning();
            await checkpoint();
            const publication = await state.publishedVersion(
                await state.files(),
                "Complete agent task",
            );
            await requireRunning();
            const meta = publication.writes?.meta as { head: string };
            await state.storage.transaction(async (storage) => {
                const current = await storage.get<WorkspaceTask>("task");
                if (current?.id !== task.id || current.status !== "running")
                    throw new Error("Task is no longer running.");
                await storage.put({
                    ...publication.writes,
                    task: {
                        ...current,
                        status: "completed",
                        finishedAt: Date.now(),
                        versionHash: meta.head,
                    },
                    snapshot: result.snapshot,
                    ...state.message(
                        "assistant",
                        result.finalMessage || "Task completed. A version was saved.",
                    ),
                });
            });
            await directory.publish(await state.summary());
        });
    } catch (error) {
        // Failed provider calls retain their conservative reservation because token
        // usage is unknown. Never refund a possibly executed request as zero tokens.
        await serial(async () => {
            const current = await currentTask();
            if (current?.id !== task.id || !["running", "cancelled"].includes(current.status))
                return;
            let captureError: unknown;
            if (generation && (await state.storage.get<string>("generation")) === generation) {
                try {
                    await checkpoint();
                } catch (failure) {
                    captureError = failure;
                }
            }
            const cancelled = signal.aborted || current.status === "cancelled";
            const message = cancelled
                ? "The task was cancelled. Completed file changes remain saved."
                : error instanceof Error
                  ? error.message
                  : "The task could not finish.";
            await state.storage.put({
                task: {
                    ...current,
                    status: cancelled ? "cancelled" : "failed",
                    finishedAt: Date.now(),
                    error: message.slice(0, 2000),
                },
                ...state.message(
                    "system",
                    captureError
                        ? `${message}\nThe latest runtime files could not be captured; the previous saved draft is retained.`
                        : message,
                ),
            });
        });
    }
}

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

function pageNumber(value: unknown, fallback: number, max: number): number {
    if (value === undefined) return fallback;
    if (!Number.isSafeInteger(value) || typeof value !== "number" || value < 0 || value > max)
        throw new Error("Invalid page offset or limit.");
    return value;
}
