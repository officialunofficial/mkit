import type { WorkspaceSource } from "./contracts";
import {
    assertHash,
    loadTree,
    mkit,
    putObject,
    verifyObject,
    type FileManifest,
    type ObjectStorage,
} from "./objects";

const REPOSITORY = "lobby-v2";
const MAX_RESPONSE_BYTES = 768 * 1024;
type Repository = Pick<Fetcher, "fetch">;

async function boundedBytes(stream: ReadableStream<Uint8Array> | null): Promise<Uint8Array> {
    if (!stream) throw new Error("Repository returned an empty response");
    const reader = stream.getReader();
    const parts: Uint8Array[] = [];
    let length = 0;
    try {
        while (true) {
            const next = await reader.read();
            if (next.done) break;
            length += next.value.length;
            if (length > MAX_RESPONSE_BYTES) {
                await reader.cancel("Response exceeds workspace limit");
                throw new Error("Repository response exceeds workspace limit");
            }
            parts.push(next.value);
        }
    } finally {
        reader.releaseLock();
    }
    const result = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }
    return result;
}

async function rpc(
    repository: Repository,
    method: "GetRef" | "GetObject",
    body: object,
): Promise<Record<string, unknown>> {
    const response = await repository.fetch(
        `https://api.mkit.sh/mkit.repo.v1.RepoService/${method}`,
        {
            method: "POST",
            headers: { "content-type": "application/json", "connect-protocol-version": "1" },
            body: JSON.stringify({ room: REPOSITORY, ...body }),
            signal: AbortSignal.timeout(15_000),
        },
    );
    if (!response.ok) throw new Error(`Repository ${method} failed (${response.status})`);
    let bytes = await boundedBytes(response.body);
    // repo-worker responses can retain gzip bytes after the header is removed.
    // Bound both representations so a compressed response cannot bypass admission.
    if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
        const stream = new Blob([new Uint8Array(bytes).buffer])
            .stream()
            .pipeThrough(new DecompressionStream("gzip"));
        bytes = await boundedBytes(stream);
    }
    const value: unknown = JSON.parse(
        new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes),
    );
    if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error("Invalid repository response");
    return value as Record<string, unknown>;
}

function fromBase64(value: unknown): Uint8Array {
    if (
        typeof value !== "string" ||
        value.length > MAX_RESPONSE_BYTES ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
    ) {
        throw new Error("Invalid repository bytes");
    }
    return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function hex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hashBase64(hash: string): string {
    assertHash(hash);
    return btoa(
        String.fromCharCode(...hash.match(/../g)!.map((pair) => Number.parseInt(pair, 16))),
    );
}

export async function importDemo(
    repository: Repository,
    storage: ObjectStorage,
    options: { ref?: string; commitHash?: string } = {},
): Promise<{ source: WorkspaceSource; files: FileManifest }> {
    const ref = options.ref ?? "main";
    if (!/^[A-Za-z0-9][A-Za-z0-9/._-]{0,127}$/.test(ref)) throw new Error("Invalid demo ref");
    let commitHash = options.commitHash;
    if (commitHash !== undefined) assertHash(commitHash);
    else {
        const response = await rpc(repository, "GetRef", { name: ref });
        if (response.exists !== true) throw new Error("Demo ref does not exist");
        commitHash = hex(fromBase64(response.objectId));
        assertHash(commitHash);
    }
    async function fetchObject(hash: string): Promise<Uint8Array | null> {
        const response = await rpc(repository, "GetObject", { objectId: hashBase64(hash) });
        if (response.found === false || response.found === undefined) return null;
        if (response.found !== true) throw new Error("Invalid repository object response");
        const bytes = fromBase64(response.bytes);
        verifyObject(hash, bytes);
        return bytes;
    }
    const commit = await fetchObject(commitHash);
    if (!commit) throw new Error("Demo version does not exist");
    const kind = mkit.object_kind(commit);
    let treeHash: string;
    if (kind === "commit" && mkit.commit_verify(commit)) {
        const decoded = mkit.commit_decode(commit);
        try {
            treeHash = decoded.tree_hex;
        } finally {
            decoded.free();
        }
    } else if (kind === "remix" && mkit.remix_verify(commit)) {
        const decoded = mkit.remix_decode(commit);
        try {
            treeHash = decoded.tree_hex;
        } finally {
            decoded.free();
        }
    } else throw new Error("Demo version is not a valid signed commit or remix");

    const empty = mkit.tree_encode("[]");
    const emptyHash = empty.hash_hex;
    const emptyBytes = empty.bytes;
    empty.free();
    const files = await loadTree(storage, treeHash, async (hash) => {
        let bytes = await fetchObject(hash);
        // The demo historically omits the canonical empty tree. Its identity
        // uniquely determines these bytes; no other missing object is repairable.
        if (!bytes && hash === emptyHash) bytes = emptyBytes;
        if (!bytes) throw new Error(`Missing demo object ${hash}`);
        verifyObject(hash, bytes);
        await putObject(storage, bytes);
        return bytes;
    });
    await putObject(storage, commit);
    return { source: { kind: "demo", repository: REPOSITORY, ref, commitHash }, files };
}
