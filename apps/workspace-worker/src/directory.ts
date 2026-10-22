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

/** Public discovery and browser sessions; never stores owner conversations. */
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
}
