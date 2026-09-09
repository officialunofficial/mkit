import { INPUT_TOKEN_RESERVE, refill, waitForCapacity, type ModelBucket } from "./model-budget";
import { DurableObject } from "cloudflare:workers";
import type { AuthenticatedOperation } from "./auth";
import { type PreparedWorkspace, type RemixRequest, type WorkspaceSummary } from "./contracts";
import { HttpError, errorResponse, json } from "./http";
import { encoder, mkit } from "./mkit";
import { importDemo } from "./source";
import { BrowserSessions, type BrowserSession } from "./browser-session";

type Preparation = {
    digest: string;
    id: string;
    status: "pending" | "ready" | "failed";
    result?: PreparedWorkspace;
};
type Usage = { requests: number; tokens: number };

/** Public discovery and account-wide admission; never stores owner conversations. */
export class WorkspaceDirectory extends DurableObject<Env> {
    private browserSessions = new BrowserSessions(this.ctx.storage);

    async createBrowserSession(auth: AuthenticatedOperation): Promise<
        { session: BrowserSession; token: string } | { error: { status: number; message: string } }
    > {
        try { return await this.browserSessions.create(auth); }
        catch (error) {
            if (error instanceof HttpError) return { error: { status: error.status, message: error.message } };
            throw error;
        }
    }
    async readBrowserSession(digest: string): Promise<BrowserSession | null> {
        return this.browserSessions.read(digest);
    }
    async removeBrowserSession(digest: string): Promise<void> {
        await this.browserSessions.remove(digest);
    }

    async fetch(request: Request): Promise<Response> {
        try {
            const { auth, source } = (await request.json()) as {
                auth: AuthenticatedOperation;
                source: RemixRequest;
            };
            return json(await this.prepare(auth, source));
        } catch (error) {
            console.warn(
                "Preparation failed",
                error instanceof Error ? error.message.slice(0, 500) : "unknown",
            );
            return errorResponse(error);
        }
    }

    async list(): Promise<WorkspaceSummary[]> {
        return (await this.ctx.storage.get<WorkspaceSummary[]>("recent")) ?? [];
    }

    async publish(summary: WorkspaceSummary): Promise<void> {
        await this.ctx.storage.transaction(async (storage) => {
            const recent = (await storage.get<WorkspaceSummary[]>("recent")) ?? [];
            const previous = recent.find((item) => item.id === summary.id);
            if (previous && previous.updatedAt > summary.updatedAt) return;
            await storage.put(
                "recent",
                [...recent.filter((item) => item.id !== summary.id), summary]
                    .sort((a, b) => b.updatedAt - a.updatedAt)
                    .slice(0, 50),
            );
        });
    }

    async prepare(
        auth: AuthenticatedOperation,
        sourceRequest: RemixRequest,
    ): Promise<PreparedWorkspace> {
        const key = `prepare:${auth.publicKey}:${auth.nonce}`;
        const id = mkit.blake3_hex(encoder.encode(`${auth.publicKey}:${auth.nonce}`)).slice(0, 32);
        const existing = await this.ctx.storage.transaction(async (storage) => {
            const prior = await storage.get<Preparation>(key);
            if (prior) {
                if (prior.digest !== auth.digest)
                    throw new HttpError(409, "This operation was already used for another remix.");
                return prior;
            }
            const day = Math.floor(Date.now() / 86400000);
            const ownerKey = `creates:${day}:${auth.publicKey}`,
                totalKey = `creates:${day}:all`;
            const owner = (await storage.get<number>(ownerKey)) ?? 0;
            const total = (await storage.get<number>(totalKey)) ?? 0;
            if (owner >= 3 || total >= 50)
                throw new HttpError(
                    429,
                    "Today’s remix allowance is used up. Try again tomorrow.",
                    3600,
                );
            await storage.put({
                [ownerKey]: owner + 1,
                [totalKey]: total + 1,
                [key]: { id, digest: auth.digest, status: "pending" },
            });
            return undefined;
        });
        if (existing?.result) return existing.result;
        if (existing)
            throw new HttpError(
                409,
                existing.status === "pending"
                    ? "This remix is being prepared."
                    : "That remix could not be prepared. Start a new remix.",
            );
        try {
            const source =
                sourceRequest.kind === "demo"
                    ? await importDemo(this.env.REPOSITORY, this.env.OBJECTS, sourceRequest)
                    : await this.env.WORKSPACES.getByName(sourceRequest.workspaceId).remixSource(
                          sourceRequest.commitHash,
                      );
            const received = await this.env.WORKSPACES.getByName(id).prepare(
                id,
                auth.publicKey,
                source.source,
                JSON.parse(JSON.stringify(source.files)),
            );
            const result: PreparedWorkspace = {
                ...received,
                grant: { ...received.grant, permissions: ["files", "commands", "versions"] },
            };
            await this.ctx.storage.put(key, {
                id,
                digest: auth.digest,
                status: "ready",
                result,
            } satisfies Preparation);
            return result;
        } catch (error) {
            await this.ctx.storage.put(key, {
                id,
                digest: auth.digest,
                status: "failed",
            } satisfies Preparation);
            throw error;
        }
    }

    async admitTask(
        owner: string,
        operation: string,
    ): Promise<{ error?: { status: number; message: string; retryAfter?: number } }> {
        try {
            await this.admitTaskInternal(owner, operation);
            return {};
        } catch (error) {
            if (error instanceof HttpError)
                return {
                    error: {
                        status: error.status,
                        message: error.message,
                        retryAfter: error.retryAfter,
                    },
                };
            throw error;
        }
    }
    private async admitTaskInternal(owner: string, operation: string): Promise<void> {
        await this.ctx.storage.transaction(async (storage) => {
            const key = `task:${owner}:${operation}`;
            if (await storage.get(key)) return;
            const dayKey = `tasks:${Math.floor(Date.now() / 86400000)}:${owner}`;
            const count = (await storage.get<number>(dayKey)) ?? 0;
            if (count >= 12)
                throw new HttpError(
                    429,
                    "Today’s agent allowance is used up. Your files are still available.",
                    3600,
                );
            await storage.put({ [dayKey]: count + 1, [key]: true });
        });
    }

    async reserveModel(
        id: string,
        inputTokens: number,
        maxOutputTokens: number,
    ): Promise<{ retryAfter: number; error?: { status: number; message: string } }> {
        try {
            return await this.reserveModelInternal(id, inputTokens, maxOutputTokens);
        } catch (error) {
            if (error instanceof HttpError)
                return {
                    retryAfter: error.retryAfter ?? 0,
                    error: { status: error.status, message: error.message },
                };
            throw error;
        }
    }
    private async reserveModelInternal(
        id: string,
        inputTokens: number,
        maxOutputTokens: number,
    ): Promise<{ retryAfter: number }> {
        if (
            !Number.isSafeInteger(inputTokens) ||
            inputTokens < 0 ||
            !Number.isSafeInteger(maxOutputTokens) ||
            maxOutputTokens < 1
        )
            throw new HttpError(400, "Invalid model budget.");
        const reserved = inputTokens + maxOutputTokens + INPUT_TOKEN_RESERVE;
        if (reserved > 7500)
            throw new HttpError(
                429,
                "This conversation is too large for the free model allowance. Select New conversation to continue.",
                60,
            );
        return this.ctx.storage.transaction(async (storage) => {
            const now = Date.now(),
                day = Math.floor(now / 86400000);
            const dayKey = `models:${day}`,
                minuteKey = "modelBucket";
            const usage = (await storage.get<Usage>(dayKey)) ?? { requests: 0, tokens: 0 };
            const minuteUsage = refill(await storage.get<ModelBucket>(minuteKey), now);
            const maxRequests = Number(this.env.MAX_DAILY_MODEL_REQUESTS),
                maxTokens = Number(this.env.MAX_DAILY_MODEL_TOKENS);
            if (usage.requests >= maxRequests || usage.tokens + reserved > maxTokens)
                throw new HttpError(
                    429,
                    "The shared daily model allowance is used up. Your work is saved; try again tomorrow.",
                    3600,
                );
            const retryAfter = waitForCapacity(minuteUsage, reserved);
            if (retryAfter > 0) return { retryAfter };
            await storage.put({
                [dayKey]: { requests: usage.requests + 1, tokens: usage.tokens + reserved },
                [minuteKey]: {
                    ...minuteUsage,
                    requests: minuteUsage.requests + 1,
                    tokens: minuteUsage.tokens + reserved,
                },
                [`reservation:${id}`]: { dayKey, minuteKey, reserved },
            });
            return { retryAfter: 0 };
        });
    }

    async settleModel(id: string, actualTokens: number): Promise<void> {
        if (!Number.isSafeInteger(actualTokens) || actualTokens < 0) return;
        await this.ctx.storage.transaction(async (storage) => {
            const key = `reservation:${id}`;
            const reservation = await storage.get<{
                dayKey: string;
                minuteKey: string;
                reserved: number;
            }>(key);
            if (!reservation) return;
            for (const usageKey of [reservation.dayKey, reservation.minuteKey]) {
                const stored = await storage.get<Usage & { at?: number }>(usageKey);
                const usage =
                    usageKey === "modelBucket" && stored
                        ? refill(stored as ModelBucket, Date.now())
                        : stored;
                if (usage)
                    await storage.put(usageKey, {
                        ...usage,
                        tokens: Math.max(0, usage.tokens - reservation.reserved + actualTokens),
                    });
            }
            await storage.delete(key);
        });
    }
}
