import { type AuthenticatedOperation } from "./auth";
import type {
    AgentGrant,
    SignedAgentGrant,
    WorkspaceChange,
    WorkspaceCoverage,
    WorkspaceMessage,
    WorkspaceSummary,
    WorkspaceTask,
    WorkspaceVersion,
    WorkspaceView,
} from "./contracts";
import { PENDING_SUBMISSION, type PartialCandidate } from "./partial-candidate";
import { HttpError, json } from "./http";
import { mkit } from "./mkit";
import { makeVersion, type FileManifest } from "./objects";
import { createPartialCandidate } from "./partial-candidate";

type ReadStorage = Pick<DurableObjectStorage, "get" | "list">;
export type Mutation = {
    writes?: Record<string, unknown>;
    deletes?: string[];
    headers?: Record<string, string>;
    alarm?: number;
    requireAgent?: boolean;
};
type Receipt = {
    digest: string;
    expiresAt?: number;
    body?: WorkspaceView;
    parts?: number;
    headers?: Record<string, string>;
};
type ReceiptResponse = { body: WorkspaceView; headers?: Record<string, string> };
export type PartialState = {
    mode: "public-partial-v1";
    baseCommit: string;
    bundleDigest: string;
    selectedPaths: string[][];
    bundleKey: string;
    original: FileManifest;
};
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
        private readonly now: () => number = Date.now,
    ) {}

    async summary(storage: ReadStorage = this.storage): Promise<WorkspaceSummary> {
        const meta = await storage.get<WorkspaceSummary>("meta");
        if (!meta) throw new HttpError(404, "Workspace not found.");
        return meta;
    }

    async files(versionHash?: string, storage: ReadStorage = this.storage): Promise<FileManifest> {
        if (versionHash && (await this.isPartial(storage)))
            throw new HttpError(400, "This selected workspace does not expose complete version history.");
        const key = versionHash ? `manifest:${versionHash}` : "files";
        const files = await storage.get<FileManifest>(key);
        if (!files) throw new HttpError(404, "Version not found.");
        return files;
    }

    async isPartial(storage: ReadStorage = this.storage): Promise<boolean> {
        return !!(await storage.get<PartialState>("partial"));
    }

    async partialState(storage: ReadStorage = this.storage): Promise<PartialState> {
        const partial = await storage.get<PartialState>("partial");
        if (!partial) throw new HttpError(400, "This workspace is not a public partial workspace.");
        return partial;
    }

    async candidate(storage: ReadStorage = this.storage): Promise<PartialCandidate | null> {
        return (await storage.get<PartialCandidate>("candidate")) ?? null;
    }

    async requireNotPending(): Promise<void> {
        if (await this.candidate()) throw new HttpError(409, PENDING_SUBMISSION);
    }

    async loadBundle(): Promise<Uint8Array> {
        const partial = await this.partialState();
        const object = await this.objects.get(partial.bundleKey);
        if (!object) throw new HttpError(500, "The public bundle is missing.");
        const bytes = new Uint8Array(await object.arrayBuffer());
        if (mkit.blake3_hex(bytes) !== partial.bundleDigest)
            throw new HttpError(500, "Stored bundle digest mismatch.");
        return bytes;
    }

    async completePartial(
        files: FileManifest,
        message: string,
    ): Promise<Mutation & { versionHash?: string; noChanges: boolean }> {
        await this.requireNotPending();
        const meta = await this.summary();
        const partial = await this.partialState();
        const seedHex = await this.storage.get<string>("seed");
        if (!seedHex) throw new Error("Missing workspace signer");
        const bundle = await this.loadBundle();
        await this.requireAgent();
        const result = await createPartialCandidate({
            workspaceId: meta.id,
            objects: this.objects,
            bundle,
            baseCommit: partial.baseCommit,
            selectedPaths: partial.selectedPaths,
            original: partial.original,
            current: files,
            seedHex,
            agentPublicKey: meta.agentPublicKey,
            message,
            beforeSign: async () => {
                await this.requireAgent();
            },
        });
        if (result.status === "no_changes")
            return { writes: { files }, noChanges: true, requireAgent: true };
        return {
            writes: { files, candidate: result.candidate },
            versionHash: result.candidate.id,
            noChanges: false,
            requireAgent: true,
        };
    }

    async requireActive(storage: ReadStorage = this.storage): Promise<void> {
        if (!(await storage.get("activated"))) throw new HttpError(404, "Workspace not found.");
    }

    async requireAgent(storage: ReadStorage = this.storage): Promise<SignedAgentGrant> {
        const grant = await storage.get<SignedAgentGrant>("grant");
        const revoked = await storage.get("revoked");
        // Check the clock after all asynchronous reads, including revocation.
        if (!grant || revoked || grant.grant.expiresAt <= this.now())
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
        const partial = await storage.get<PartialState>("partial");
        const files = await this.files(versionHash, storage);
        const working = versionHash ? await this.files(undefined, storage) : files;
        const saved = partial
            ? partial.original
            : workspace.head
              ? await this.files(workspace.head, storage)
              : {};
        const changes: WorkspaceChange[] = [];
        const changePaths = partial
            ? Object.keys(partial.original)
            : [...Object.keys(saved), ...Object.keys(working)];
        for (const path of new Set(changePaths)) {
            const before = Object.hasOwn(saved, path) ? saved[path] : undefined;
            const after = Object.hasOwn(working, path) ? working[path] : undefined;
            if (before?.hash === after?.hash && before?.mode === after?.mode) continue;
            if (partial && (!before || !after)) continue;
            changes.push({
                path,
                status: !before ? "added" : !after ? "deleted" : "modified",
                beforeHash: before?.hash ?? null,
                afterHash: after?.hash ?? null,
            });
        }
        changes.sort((a, b) => a.path.localeCompare(b.path));
        const versions = partial
            ? []
            : [
                  ...(
                      await storage.list<WorkspaceVersion>({
                          prefix: "history:",
                          reverse: true,
                          limit: 50,
                      })
                  ).values(),
              ];
        const coverage: WorkspaceCoverage | undefined = partial
            ? { content: "selected-files", history: "partial", verification: "selected-only" }
            : undefined;
        const storedCandidate = await storage.get<PartialCandidate>("candidate");
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
            ...(coverage ? { coverage } : {}),
            ...(partial ? { candidateStatus: storedCandidate ? "ready" : "none" } : {}),
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
            if (mutation.requireAgent) await this.requireAgent(storage);
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
