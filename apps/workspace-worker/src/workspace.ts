import { DurableObject } from "cloudflare:workers";
import {
    authenticate,
    randomToken,
    verifyGrant,
    type AuthenticatedOperation,
} from "./auth";
import { browserSessionCookie, requestBrowserSession } from "./browser-session";
import type {
    AgentGrant,
    PreparedWorkspace,
    WorkspaceSource,
    WorkspaceSummary,
    WorkspaceTask,
} from "./contracts";
import { errorResponse, HttpError, json, record, text } from "./http";
import { decoder, encoder, fromHex, hex, mkit } from "./mkit";
import {
    assertHash,
    getBlob,
    putBlob,
    validateManifest,
    validatePath,
    type FileManifest,
} from "./objects";
import { SandboxWorkspace } from "./sandbox-files";
import { WorkspaceState, type Mutation } from "./workspace-state";
import { runWorkspaceTask } from "./workspace-runner";
import { applyVersionEdits, versionRequest } from "./version-edits";

export class Workspace extends DurableObject<Env> {
    private state = new WorkspaceState(this.ctx.storage, this.env.OBJECTS);
    private queue: Promise<unknown> = Promise.resolve();
    private active?: AbortController;
    private terminals = new Map<
        WebSocket,
        { upstream: WebSocket; session: string; until: number }
    >();
    private sandbox?: SandboxWorkspace;

    private serial = <T>(fn: () => Promise<T>): Promise<T> => {
        const next = this.queue.then(fn, fn);
        this.queue = next.catch(() => {});
        return next;
    };
    private async box(): Promise<SandboxWorkspace> {
        return (this.sandbox ??= new SandboxWorkspace(
            this.env.Sandbox,
            (await this.state.summary()).id,
            this.env.OBJECTS,
        ));
    }
    async prepare(
        id: string,
        ownerPublicKey: string,
        source: WorkspaceSource,
        files: FileManifest,
    ): Promise<PreparedWorkspace> {
        return this.serial(async () => {
            const existing = await this.ctx.storage.get<AgentGrant>("preparedGrant");
            if (existing) return { id, grant: existing };
            validateManifest(files);
            const seed = randomToken(),
                agentPublicKey = hex(mkit.ed25519_pubkey_from_seed(fromHex(seed))),
                now = Date.now();
            const grant: AgentGrant = {
                version: 1,
                workspaceId: id,
                ownerPublicKey,
                agentPublicKey,
                source,
                permissions: ["files", "commands", "versions"],
                createdAt: now,
                expiresAt: now + 30 * 86400000,
            };
            const meta: WorkspaceSummary = {
                id,
                title: "Untitled remix",
                ownerPublicKey,
                agentPublicKey,
                source,
                head: null,
                createdAt: now,
                updatedAt: now,
                public: true,
            };
            await this.ctx.storage.put({
                meta,
                seed,
                preparedGrant: grant,
                files,
                generation: randomToken(),
            });
            return { id, grant };
        });
    }
    async remixSource(
        commitHash?: string,
    ): Promise<{ source: WorkspaceSource; files: FileManifest }> {
        await this.state.requireActive();
        const meta = await this.state.summary(),
            hash = commitHash ?? meta.head!;
        assertHash(hash);
        return {
            source: {
                kind: "workspace",
                repository: meta.id,
                workspaceId: meta.id,
                commitHash: hash,
            },
            files: JSON.parse(JSON.stringify(await this.state.files(hash))),
        };
    }
    private async owner(request: Request): Promise<boolean> {
        const digest = requestBrowserSession(request);
        return !!digest && this.ownsSession(digest);
    }
    private async ownsSession(digest: string): Promise<boolean> {
        const session = await this.env.DIRECTORY.getByName("global").readBrowserSession(digest);
        return !!session && session.publicKey === (await this.state.summary()).ownerPublicKey;
    }
    private async loginResponse(request: Request, auth: AuthenticatedOperation, response: Response): Promise<Response> {
        // Cookie issuance has its own short replay receipt in the directory.
        // Do not persist bearer tokens in workspace mutation response receipts.
        const headers = new Headers(response.headers);
        headers.delete("Set-Cookie");
        if (!(await this.owner(request))) {
            const login = await this.env.DIRECTORY.getByName("global").createBrowserSession(auth);
            if ("error" in login) throw new HttpError(login.error.status, login.error.message);
            headers.set("Set-Cookie", browserSessionCookie(login.token, new URL(request.url).protocol === "https:"));
        }
        return new Response(response.body, { status: response.status, headers });
    }
    private closeTerminals(session?: string): void {
        for (const [socket, data] of this.terminals) {
            if (session && data.session !== session) continue;
            try {
                socket.close(1000, "Session closed");
                data.upstream.close(1000, "Session closed");
            } catch {}
            this.terminals.delete(socket);
        }
    }
    private async stopTerminals(): Promise<void> {
        if (!this.terminals.size && !(await this.ctx.storage.get("terminalOpen"))) return;
        try {
            const box = await this.box();
            await box.stopTerminal();
            const generation = (await this.ctx.storage.get<string>("generation"))!;
            const files = await box.capture(generation);
            if ((await this.ctx.storage.get("generation")) === generation)
                await this.ctx.storage.put("files", files);
            await this.ctx.storage.delete("terminalOpen");
        } catch (error) {
            const alarm = await this.ctx.storage.getAlarm();
            await this.ctx.storage.setAlarm(Math.min(alarm ?? Infinity, Date.now() + 10000));
            throw error;
        } finally {
            this.closeTerminals();
        }
    }
    private async publish(): Promise<void> {
        await this.ctx.storage.put("publishPending", true);
        try {
            await this.env.DIRECTORY.getByName("global").publish(await this.state.summary());
            await this.ctx.storage.delete("publishPending");
        } catch {
            const alarm = await this.ctx.storage.getAlarm();
            await this.ctx.storage.setAlarm(Math.min(alarm ?? Infinity, Date.now() + 30000));
        }
    }
    async fetch(request: Request): Promise<Response> {
        try {
            const url = new URL(request.url),
                action = url.pathname.split("/")[4] ?? "";
            if (request.method === "GET" && action === "terminal")
                return await this.terminal(request);
            if (request.method === "GET") {
                await this.state.requireActive();
                const version = url.searchParams.get("version") ?? undefined;
                if (version) assertHash(version);
                if (!action) return json(await this.state.view(await this.owner(request), version));
                if (action === "file") {
                    const path = text(url.searchParams.get("path"), 1024, "path");
                    validatePath(path);
                    const entry = (await this.state.files(version))[path];
                    if (!entry) throw new HttpError(404, "File not found.");
                    const bytes = await getBlob(this.env.OBJECTS, entry.hash);
                    let content = "",
                        editable = true;
                    try {
                        content = decoder.decode(bytes);
                        if (content.includes("\0")) editable = false;
                    } catch {
                        editable = false;
                    }
                    return json({
                        path,
                        content: editable ? content : "Binary file — preserved in signed versions.",
                        hash: entry.hash,
                        editable,
                    });
                }
            }
            if (request.method === "DELETE" && action === "session") {
                if (request.headers.get("Origin") !== this.env.AUTH_AUDIENCE)
                    throw new HttpError(403, "Invalid origin.");
                const session = requestBrowserSession(request);
                if (session) {
                    await this.env.DIRECTORY.getByName("global").removeBrowserSession(session);
                    await this.serial(async () => {
                        if ([...this.terminals.values()].some((value) => value.session === session))
                            await this.stopTerminals();
                    });
                }
                return json({}, 200, {
                    "Set-Cookie": browserSessionCookie("", url.protocol === "https:"),
                });
            }
            if (request.method !== "POST") throw new HttpError(404, "Workspace route not found.");
            const meta = await this.state.summary(),
                auth = await authenticate(request, this.env.AUTH_AUDIENCE, meta.id, Date.now(), action === "versions" ? 8 * 1024 * 1024 : undefined);
            if (auth.publicKey !== meta.ownerPublicKey)
                throw new HttpError(
                    403,
                    "This workspace belongs to another identity. Remix it to make changes.",
                );
            if (action === "cancel" || action === "revoke") {
                const previous = await this.state.replay(auth);
                if (previous) return previous;
                this.active?.abort(new Error("Task cancelled"));
            }
            return await this.serial(async () => {
                const previous = await this.state.replay(auth);
                if (previous) {
                    // Historical activation receipts may contain the old workspace cookie.
                    if (action === "activate") previous.headers.delete("Set-Cookie");
                    return action === "session"
                        ? this.loginResponse(request, auth, previous) : previous;
                }
                const body = record(auth.body);
                let mutation: Mutation,
                    teardown = false;
                if (action === "activate") {
                    if (await this.ctx.storage.get("activated"))
                        throw new HttpError(409, "Workspace is already active.");
                    const grant = verifyGrant(body, await this.state.preparedGrant());
                    mutation = await this.state.publishedVersion(
                        await this.state.files(),
                        "Remix project",
                        true,
                    );
                    mutation.writes = { ...mutation.writes, activated: true, grant };
                } else {
                    await this.state.requireActive();
                    mutation = { writes: {} };
                    if (
                        action !== "session" &&
                        action !== "cancel" &&
                        action !== "revoke" &&
                        action !== "conversation"
                    )
                        await this.state.requireAgent();
                    const task = await this.ctx.storage.get<WorkspaceTask>("task"),
                        busy = task?.status === "queued" || task?.status === "running";
                    if (action === "file" || action === "restore" || action === "versions") {
                        if (busy)
                            throw new HttpError(
                                409,
                                "Wait for the agent to finish or cancel its task before editing.",
                            );
                        const checkpoint = action === "versions" ? versionRequest(body) : undefined;
                        await this.stopTerminals();
                        let files: FileManifest;
                        if (checkpoint) {
                            files = await applyVersionEdits(await this.state.files(), checkpoint.edits, this.env.OBJECTS);
                        } else if (action === "restore") {
                            const hash = text(body.versionHash, 64, "version");
                            assertHash(hash);
                            files = await this.state.files(hash);
                        } else {
                            const path = text(body.path, 1024, "path");
                            validatePath(path);
                            if (typeof body.content !== "string")
                                throw new HttpError(400, "Invalid file content.");
                            files = { ...(await this.state.files()) };
                            if (body.expectedHash !== (files[path]?.hash ?? null))
                                throw new HttpError(
                                    409,
                                    "This file changed. Reload it before saving.",
                                );
                            const bytes = encoder.encode(body.content);
                            const entry = {
                                hash: await putBlob(this.env.OBJECTS, bytes),
                                size: bytes.length,
                                mode: files[path]?.mode ?? ("blob" as const),
                            };
                            files[path] = entry;
                            validateManifest(files);
                        }
                        mutation = await this.state.publishedVersion(
                            files,
                            checkpoint?.message ?? (action === "restore" ? "Restore saved version" : `Save ${body.path}`),
                        );
                        mutation.writes = { ...mutation.writes, generation: randomToken() };
                    } else if (action === "tasks") {
                        if (busy) throw new HttpError(409, "An agent task is already running.");
                        const prompt = text(body.prompt, 8000, "task");
                        if (encoder.encode(prompt).length > 8000)
                            throw new HttpError(400, "Keep the task under 8,000 bytes.");
                        const admission = await this.env.DIRECTORY.getByName("global").admitTask(
                            auth.publicKey,
                            auth.nonce,
                        );
                        if (admission.error)
                            throw new HttpError(
                                admission.error.status,
                                admission.error.message,
                                admission.error.retryAfter,
                            );
                        await this.stopTerminals();
                        const task: WorkspaceTask = {
                            id: crypto.randomUUID(),
                            prompt,
                            status: "queued",
                            createdAt: Date.now(),
                        };
                        mutation = {
                            writes: { task, ...this.state.message("user", prompt) },
                            alarm: Date.now() + 1,
                        };
                    } else if (action === "cancel" || action === "revoke") {
                        this.active?.abort(new Error("Task cancelled"));
                        teardown = true;
                        mutation.writes = {
                            ...(action === "revoke" ? { revoked: true } : {}),
                            ...(busy
                                ? { task: { ...task, status: "cancelled", finishedAt: Date.now() } }
                                : {}),
                        };
                    } else if (action === "conversation") {
                        if (busy)
                            throw new HttpError(
                                409,
                                "Wait for the task to finish or cancel it first.",
                            );
                        const keys = [
                            ...(await this.ctx.storage.list({ prefix: "message:" })).keys(),
                        ];
                        mutation = { deletes: ["snapshot", "task", ...keys] };
                    } else if (action !== "session")
                        throw new HttpError(404, "Workspace route not found.");
                }
                const response = await this.state.apply(auth, mutation);
                if (teardown) {
                    try {
                        await this.stopTerminals();
                    } catch {
                        /* Durable terminal cleanup retries via its alarm. */
                    }
                }
                if (mutation.writes?.meta) await this.publish();
                return action === "session"
                    ? this.loginResponse(request, auth, response) : response;
            });
        } catch (error) {
            return errorResponse(error);
        }
    }
    private async captureTerminalDraft(): Promise<void> {
        if (!this.terminals.size || !this.sandbox) return;
        const generation = (await this.ctx.storage.get<string>("generation"))!;
        const files = await this.sandbox.capture(generation);
        if ((await this.ctx.storage.get("generation")) === generation)
            await this.ctx.storage.put("files", files);
    }
    private async terminal(request: Request): Promise<Response> {
        return this.serial(async () => {
            await this.state.requireActive();
            await this.state.requireAgent();
            if (
                request.headers.get("Origin") !== this.env.AUTH_AUDIENCE ||
                !(await this.owner(request))
            )
                throw new HttpError(403, "Unlock your passkey to open the terminal.");
            if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket")
                throw new HttpError(426, "WebSocket required.");
            const task = await this.ctx.storage.get<WorkspaceTask>("task");
            if (task?.status === "running" || task?.status === "queued")
                throw new HttpError(
                    409,
                    "The agent is using the terminal. Reconnect when its task finishes.",
                );
            if (this.terminals.size >= 2)
                throw new HttpError(429, "Close another terminal before opening this one.");
            const box = await this.box(),
                generation = (await this.ctx.storage.get<string>("generation"))!;
            await box.ensure(await this.state.files(), generation);
            const response = await box.terminal(request),
                upstream = response.webSocket;
            if (!upstream) throw new HttpError(502, "The terminal could not start.");
            upstream.binaryType = "arraybuffer";
            upstream.accept();
            await this.ctx.storage.put("terminalOpen", true);
            const pair = new WebSocketPair(),
                client = pair[0],
                server = pair[1],
                session = requestBrowserSession(request)!;
            server.binaryType = "arraybuffer";
            server.accept();
            this.terminals.set(server, { upstream, session, until: Date.now() + 20 * 60000 });
            server.addEventListener("message", (event) => {
                this.ctx.waitUntil(
                    (async () => {
                        if (!this.terminals.has(server)) return;
                        await this.state.requireAgent();
                        if (!(await this.owner(request))) {
                            await this.serial(() => this.stopTerminals());
                            return;
                        }
                        if (
                            typeof event.data === "string"
                                ? event.data.length > 65536
                                : event.data.byteLength > 65536
                        ) {
                            await this.serial(() => this.stopTerminals());
                            return;
                        }
                        upstream.send(event.data);
                    })().catch(() =>
                        this.serial(() => this.stopTerminals()).catch(() => this.closeTerminals()),
                    ),
                );
            });
            upstream.addEventListener("message", (event) => {
                if (!this.terminals.has(server)) return;
                const size =
                    typeof event.data === "string" ? event.data.length : event.data.byteLength;
                if (size > 65536) {
                    this.ctx.waitUntil(this.serial(() => this.stopTerminals()).catch(() => {}));
                    return;
                }
                server.send(event.data);
            });
            const close = () =>
                this.ctx.waitUntil(
                    this.serial(async () => {
                        await this.stopTerminals();
                    }).catch(() => this.closeTerminals(session)),
                );
            server.addEventListener("close", close);
            upstream.addEventListener("close", close);
            server.addEventListener("error", close);
            upstream.addEventListener("error", close);
            await this.ctx.storage.setAlarm(Date.now() + 10000);
            return new Response(null, { status: 101, webSocket: client });
        });
    }
    async alarm(): Promise<void> {
        const task = await this.serial(async () => {
            if (await this.ctx.storage.get("publishPending")) await this.publish();
            const task = await this.ctx.storage.get<WorkspaceTask>("task");
            if (task?.status === "running" && !this.active) {
                await this.ctx.storage.put({
                    task: {
                        ...task,
                        status: "failed",
                        finishedAt: Date.now(),
                        error: "The worker restarted during this task. Saved files are preserved; submit a new task to continue.",
                    },
                    ...this.state.message(
                        "system",
                        "Task interrupted by a worker restart. Saved files are preserved.",
                    ),
                });
                return undefined;
            }
            if (task?.status === "queued") {
                try {
                    await this.state.requireAgent();
                } catch {
                    await this.ctx.storage.put("task", {
                        ...task,
                        status: "failed",
                        finishedAt: Date.now(),
                        error: "Agent authorization has expired or been revoked.",
                    });
                    return undefined;
                }
                const running = { ...task, status: "running" as const };
                this.active = new AbortController();
                await this.ctx.storage.put("task", running);
                // Recovery alarm marks a crashed run interrupted; uncertain shell commands are never replayed.
                await this.ctx.storage.setAlarm(Date.now() + 6 * 60000);
                return running;
            }
            if (!this.terminals.size && (await this.ctx.storage.get("terminalOpen")))
                await this.stopTerminals();
            if (this.terminals.size) {
                try {
                    await this.state.requireAgent();
                } catch {
                    await this.stopTerminals();
                }
            }
            for (const [, terminal] of this.terminals) {
                if (
                    terminal.until <= Date.now() ||
                    !(await this.ownsSession(terminal.session))
                )
                    await this.stopTerminals();
            }
            await this.captureTerminalDraft();
            if (this.terminals.size) await this.ctx.storage.setAlarm(Date.now() + 10000);
            return undefined;
        });
        if (!task) return;
        const active = this.active!,
            timer = setTimeout(
                () => active.abort(new Error("Task reached its five-minute limit")),
                5 * 60000,
            );
        try {
            await runWorkspaceTask({
                state: this.state,
                sandbox: await this.box(),
                env: this.env,
                serial: this.serial,
                signal: active.signal,
                task,
            });
        } finally {
            clearTimeout(timer);
            this.active = undefined;
        }
    }
}
