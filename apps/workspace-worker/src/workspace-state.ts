import { type AuthenticatedOperation } from "./auth";
import type {
    AgentGrant,
    SignedAgentGrant,
    WorkspaceChange,
    WorkspaceMessage,
    WorkspaceSummary,
    WorkspaceTask,
    WorkspaceVersion,
    WorkspaceView,
} from "./contracts";
import { HttpError, json } from "./http";
import { makeVersion, type FileManifest } from "./objects";

type ReadStorage = Pick<DurableObjectStorage, "get" | "list">;
export type Mutation = {
    writes?: Record<string, unknown>;
    deletes?: string[];
    headers?: Record<string, string>;
    alarm?: number;
};
type Receipt = {
    digest: string;
    expiresAt?: number;
    body?: WorkspaceView;
    parts?: number;
    headers?: Record<string, string>;
};
type ReceiptResponse = { body: WorkspaceView; headers?: Record<string, string> };
// SQLite's key/value row limit is 2 MB. Owner views can exceed it once a
// conversation, version list and long file paths are combined. Persist the exact
// replay response in bounded rows, all under the mutation's transaction.
const RECEIPT_PART_CHARS = 32 * 1024;
const MAX_RECEIPT_PARTS = 64;
const receiptPartKey = (nonce: string, index: number) =>
    `receipt-part:${nonce}:${String(index).padStart(4, "0")}`;

async function receiptResponse(
    storage: ReadStorage,
    nonce: string,
    receipt: Receipt,
): Promise<ReceiptResponse> {
    // Existing inline receipts remain replayable after upgrading the service.
    if (receipt.body) return { body: receipt.body, headers: receipt.headers };
    if (
        !Number.isSafeInteger(receipt.parts) ||
        !receipt.parts ||
        receipt.parts < 1 ||
        receipt.parts > MAX_RECEIPT_PARTS
    )
        throw new Error("Invalid stored operation receipt");
    const parts: string[] = [];
    for (let index = 0; index < receipt.parts; index++) {
        const part = await storage.get<string>(receiptPartKey(nonce, index));
        if (typeof part !== "string" || part.length > RECEIPT_PART_CHARS)
            throw new Error("Incomplete stored operation receipt");
        parts.push(part);
    }
    return { body: JSON.parse(parts.join("")) as WorkspaceView, headers: receipt.headers };
}

export class WorkspaceState {
    constructor(
        readonly storage: DurableObjectStorage,
        readonly objects: R2Bucket,
    ) {}

    async summary(storage: ReadStorage = this.storage): Promise<WorkspaceSummary> {
        const meta = await storage.get<WorkspaceSummary>("meta");
        if (!meta) throw new HttpError(404, "Workspace not found.");
        return meta;
    }

    async files(versionHash?: string, storage: ReadStorage = this.storage): Promise<FileManifest> {
        const key = versionHash ? `manifest:${versionHash}` : "files";
        const files = await storage.get<FileManifest>(key);
        if (!files) throw new HttpError(404, "Version not found.");
        return files;
    }

    async requireActive(storage: ReadStorage = this.storage): Promise<void> {
        if (!(await storage.get("activated"))) throw new HttpError(404, "Workspace not found.");
    }

    async requireAgent(): Promise<SignedAgentGrant> {
        const grant = await this.storage.get<SignedAgentGrant>("grant");
        if (!grant || grant.grant.expiresAt <= Date.now() || (await this.storage.get("revoked")))
            throw new HttpError(
                403,
                "Agent access is disabled or expired. Remix this project to start a new authorized workspace.",
            );
        return grant;
    }

    async view(
        isOwner: boolean,
        versionHash?: string,
        storage: ReadStorage = this.storage,
    ): Promise<WorkspaceView> {
        const workspace = await this.summary(storage);
        const files = await this.files(versionHash, storage);
        const working = versionHash ? await this.files(undefined, storage) : files;
        const saved = workspace.head ? await this.files(workspace.head, storage) : {};
        const changes: WorkspaceChange[] = [];
        for (const path of new Set([...Object.keys(saved), ...Object.keys(working)])) {
            const before = Object.hasOwn(saved, path) ? saved[path] : undefined;
            const after = Object.hasOwn(working, path) ? working[path] : undefined;
            if (before?.hash === after?.hash && before?.mode === after?.mode) continue;
            changes.push({
                path,
                status: !before ? "added" : !after ? "deleted" : "modified",
                beforeHash: before?.hash ?? null,
                afterHash: after?.hash ?? null,
            });
        }
        changes.sort((a, b) => a.path.localeCompare(b.path));
        const versions = [
            ...(
                await storage.list<WorkspaceVersion>({
                    prefix: "history:",
                    reverse: true,
                    limit: 50,
                })
            ).values(),
        ];
        const grant = (await storage.get<SignedAgentGrant>("grant")) ?? null;
        const messages = isOwner
            ? [
                  ...(
                      await storage.list<WorkspaceMessage>({
                          prefix: "message:",
                          reverse: true,
                          limit: 60,
                      })
                  ).values(),
              ].reverse()
            : [];
        const task = isOwner ? ((await storage.get<WorkspaceTask>("task")) ?? null) : null;
        return {
            workspace,
            files: Object.entries(files)
                .map(([path, file]) => ({ path, hash: file.hash, size: file.size, mode: file.mode }))
                .sort((a, b) => a.path.localeCompare(b.path)),
            changes,
            versions,
            messages,
            task,
            isOwner,
            grant,
            agentEnabled:
                !!grant && grant.grant.expiresAt > Date.now() && !(await storage.get("revoked")),
        };
    }

    async publishedVersion(files: FileManifest, message: string, remix = false): Promise<Mutation> {
        const meta = await this.summary();
        const seedHex = await this.storage.get<string>("seed");
        if (!seedHex) throw new Error("Missing workspace signer");
        const version = await makeVersion(this.objects, {
            manifest: files,
            seedHex,
            parent: meta.head,
            message,
            ...(remix ? { source: meta.source } : {}),
        });
        return {
            writes: {
                meta: {
                    ...meta,
                    head: version.hash,
                    updatedAt: Math.max(Date.now(), meta.updatedAt + 1),
                },
                files,
                [`manifest:${version.hash}`]: files,
                [`version:${version.hash}`]: version,
                [`history:${String(version.createdAt).padStart(13, "0")}:${version.hash}`]: version,
            },
        };
    }

    /** Mutable publication and its authenticated replay response commit together. */
    async apply(auth: AuthenticatedOperation, mutation: Mutation): Promise<Response> {
        const receipt = await this.storage.transaction(async (storage) => {
            const key = `receipt:${auth.nonce}`;
            const previous = await storage.get<Receipt>(key);
            if (previous) {
                if (previous.digest !== auth.digest)
                    throw new HttpError(409, "This operation was used for another request.");
                return receiptResponse(storage, auth.nonce, previous);
            }
            // Signed requests expire after five minutes; their replay bodies need not
            // accumulate forever. Prune bounded batches inside the same transaction.
            const expired: string[] = [];
            for (const [oldKey, old] of await storage.list<Receipt>({
                prefix: "receipt:",
                limit: 20,
            })) {
                if (old.expiresAt !== undefined && old.expiresAt <= Date.now()) {
                    expired.push(oldKey);
                    const nonce = oldKey.slice("receipt:".length);
                    for (let part = 0; part < (old.parts ?? 0); part++)
                        expired.push(receiptPartKey(nonce, part));
                }
            }
            for (const [sessionKey, expires] of await storage.list<number>({
                prefix: "session:",
                limit: 20,
            }))
                if (expires <= Date.now()) expired.push(sessionKey);
            if (mutation.writes) await storage.put(mutation.writes);
            const deletes = [...expired, ...(mutation.deletes ?? [])];
            for (let start = 0; start < deletes.length; start += 128)
                await storage.delete(deletes.slice(start, start + 128));
            if (mutation.alarm !== undefined) await storage.setAlarm(mutation.alarm);
            const body = await this.view(true, undefined, storage);
            const encoded = JSON.stringify(body);
            const parts = Math.ceil(encoded.length / RECEIPT_PART_CHARS);
            if (parts > MAX_RECEIPT_PARTS)
                throw new HttpError(413, "This workspace response is too large to save.");
            const rows: Record<string, string> = {};
            for (let index = 0; index < parts; index++)
                rows[receiptPartKey(auth.nonce, index)] = encoded.slice(
                    index * RECEIPT_PART_CHARS,
                    (index + 1) * RECEIPT_PART_CHARS,
                );
            await storage.put(rows);
            const result: Receipt = {
                digest: auth.digest,
                expiresAt: auth.expiresAt,
                parts,
                headers: mutation.headers,
            };
            await storage.put(key, result);
            return { body, headers: mutation.headers };
        });
        return json(receipt.body, 200, receipt.headers);
    }

    async replay(auth: AuthenticatedOperation): Promise<Response | undefined> {
        const receipt = await this.storage.get<Receipt>(`receipt:${auth.nonce}`);
        if (!receipt) return undefined;
        if (receipt.digest !== auth.digest)
            throw new HttpError(409, "This operation was used for another request.");
        const response = await receiptResponse(this.storage, auth.nonce, receipt);
        return json(response.body, 200, response.headers);
    }

    message(role: WorkspaceMessage["role"], text: string): Record<string, WorkspaceMessage> {
        const id = crypto.randomUUID(),
            createdAt = Date.now();
        return {
            [`message:${String(createdAt).padStart(13, "0")}:${id}`]: {
                id,
                role,
                text: text.slice(0, 12000),
                createdAt,
            },
        };
    }

    async preparedGrant(): Promise<AgentGrant> {
        const grant = await this.storage.get<AgentGrant>("preparedGrant");
        if (!grant) throw new HttpError(404, "Prepared workspace not found.");
        return grant;
    }
}
