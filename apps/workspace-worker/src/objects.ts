import { mkit } from "./mkit";
import type { WorkspaceSource, WorkspaceVersion } from "./contracts";

export { mkit };
export const MAX_FILES = 256;
export const MAX_FILE_BYTES = 256 * 1024;
export const MAX_TOTAL_BYTES = 4 * 1024 * 1024;
export const MAX_OBJECT_BYTES = 512 * 1024;
const MAX_DEPTH = 32;
const MAX_TREE_ENTRIES = MAX_FILES * MAX_DEPTH;

export type FileManifest = Record<string, { hash: string; size: number; mode: "blob" | "exec" }>;
/** Narrow structural subset implemented by R2Bucket and in-memory test stores. */
export interface ObjectStorage {
    get(key: string): Promise<{ size: number; arrayBuffer(): Promise<ArrayBuffer> } | null>;
    put(key: string, value: Uint8Array): Promise<unknown>;
}

export function assertHash(hash: string): void {
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error("Invalid object hash");
}

export function validatePath(path: string): void {
    const parts = path.split("/");
    const utf8 = new TextEncoder().encode(path);
    if (
        !path ||
        utf8.length > 1024 ||
        parts.length > MAX_DEPTH ||
        /[\u0000-\u001f\u007f-\u009f\\]/u.test(path) ||
        new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(utf8) !== path
    ) {
        throw new Error("Invalid workspace path");
    }
    for (const part of parts) {
        if (!part || part === "." || part === ".." || /^\.(mkit|git)$/i.test(part)) {
            throw new Error("Invalid workspace path");
        }
        // Core owns additional canonical entry-name rules (length, reserved device
        // names and trailing dots/spaces). Never normalize an invalid path.
        const encoded = mkit.tree_encode(JSON.stringify([[part, "blob", "0".repeat(64)]]));
        encoded.free();
    }
}

export function validateManifest(files: FileManifest): void {
    const entries = Object.entries(files);
    if (entries.length > MAX_FILES) throw new Error("Workspace exceeds 256 files");
    let total = 0;
    const paths = new Set(entries.map(([path]) => path));
    for (const [path, file] of entries) {
        validatePath(path);
        assertHash(file.hash);
        if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > MAX_FILE_BYTES) {
            throw new Error("File exceeds 256 KiB or has invalid size");
        }
        if (file.mode !== "blob" && file.mode !== "exec") throw new Error("Unsupported file mode");
        const parts = path.split("/");
        for (let i = 1; i < parts.length; i++) {
            if (paths.has(parts.slice(0, i).join("/")))
                throw new Error("File conflicts with a directory");
        }
        total += file.size;
    }
    if (total > MAX_TOTAL_BYTES) throw new Error("Workspace exceeds 4 MiB");
}

export function objectKey(hash: string): string {
    assertHash(hash);
    return `objects/${hash}`;
}

export function verifyObject(hash: string, bytes: Uint8Array): void {
    assertHash(hash);
    if (bytes.length > MAX_OBJECT_BYTES) throw new Error("Object exceeds workspace size limit");
    if (mkit.object_id(bytes) !== hash) throw new Error("Object does not match requested hash");
}

export async function putObject(storage: ObjectStorage, bytes: Uint8Array): Promise<string> {
    if (bytes.length > MAX_OBJECT_BYTES) throw new Error("Object exceeds workspace size limit");
    const hash = mkit.object_id(bytes);
    await storage.put(objectKey(hash), bytes);
    return hash;
}

export async function getObject(storage: ObjectStorage, hash: string): Promise<Uint8Array> {
    const object = await storage.get(objectKey(hash));
    if (!object) throw new Error(`Missing object ${hash}`);
    if (object.size > MAX_OBJECT_BYTES) throw new Error("Object exceeds workspace size limit");
    const bytes = new Uint8Array(await object.arrayBuffer());
    verifyObject(hash, bytes);
    return bytes;
}

export async function putBlob(storage: ObjectStorage, bytes: Uint8Array): Promise<string> {
    if (bytes.length > MAX_FILE_BYTES) throw new Error("File exceeds 256 KiB");
    const blob = mkit.blob_encode(bytes);
    try {
        return await putObject(storage, blob.bytes);
    } finally {
        blob.free();
    }
}

function decodeFile(bytes: Uint8Array): Uint8Array {
    const data = mkit.blob_decode(bytes);
    if (data.length > MAX_FILE_BYTES) throw new Error("File exceeds 256 KiB");
    return data;
}

export async function getBlob(storage: ObjectStorage, hash: string): Promise<Uint8Array> {
    return decodeFile(await getObject(storage, hash));
}

type TreeNode = Map<string, TreeNode | FileManifest[string]>;

export async function buildTree(storage: ObjectStorage, files: FileManifest): Promise<string> {
    validateManifest(files);
    const root: TreeNode = new Map();
    for (const [path, file] of Object.entries(files)) {
        // Size metadata cannot conceal a missing, substituted or oversized blob.
        if ((await getBlob(storage, file.hash)).length !== file.size)
            throw new Error("File size mismatch");
        const parts = path.split("/");
        let node = root;
        for (const part of parts.slice(0, -1)) {
            let child = node.get(part);
            if (!child) {
                child = new Map();
                node.set(part, child);
            }
            if (!(child instanceof Map)) throw new Error("File conflicts with a directory");
            node = child;
        }
        node.set(parts[parts.length - 1], file);
    }
    async function save(node: TreeNode): Promise<string> {
        const entries: [string, string, string][] = [];
        for (const [name, value] of node) {
            entries.push(
                value instanceof Map
                    ? [name, "tree", await save(value)]
                    : [name, value.mode, value.hash],
            );
        }
        const tree = mkit.tree_encode(JSON.stringify(entries));
        try {
            return await putObject(storage, tree.bytes);
        } finally {
            tree.free();
        }
    }
    return save(root);
}

/** Read each object under its independently known ID. Alternate readers support
 * verified source imports while keeping all traversal limits in one place. */
export async function loadTree(
    storage: ObjectStorage,
    hash: string,
    read: (hash: string) => Promise<Uint8Array> = (id) => getObject(storage, id),
): Promise<FileManifest> {
    const files: FileManifest = Object.create(null);
    let count = 0;
    let bytesTotal = 0;
    let entryCount = 0;
    async function walk(id: string, prefix: string, depth: number): Promise<void> {
        if (depth > MAX_DEPTH) throw new Error("Workspace path exceeds depth limit");
        const bytes = await read(id);
        verifyObject(id, bytes);
        const entries: [string, string, string][] = JSON.parse(mkit.tree_decode(bytes));
        entryCount += entries.length;
        if (entryCount > MAX_TREE_ENTRIES) throw new Error("Workspace exceeds tree entry limit");
        for (const [name, mode, child] of entries) {
            const path = prefix ? `${prefix}/${name}` : name;
            validatePath(path);
            if (mode === "tree") {
                await walk(child, path, depth + 1);
            } else {
                if (mode !== "blob" && mode !== "exec")
                    throw new Error("Symlinks are not supported in workspaces");
                if (++count > MAX_FILES) throw new Error("Workspace exceeds 256 files");
                const object = await read(child);
                verifyObject(child, object);
                const data = decodeFile(object);
                bytesTotal += data.length;
                if (bytesTotal > MAX_TOTAL_BYTES) throw new Error("Workspace exceeds 4 MiB");
                files[path] = { hash: child, size: data.length, mode };
            }
        }
    }
    await walk(hash, "", 1);
    validateManifest(files);
    return files;
}

export async function makeVersion(
    storage: ObjectStorage,
    input: {
        manifest: FileManifest;
        seedHex: string;
        parent?: string | null;
        message: string;
        source?: WorkspaceSource;
    },
): Promise<WorkspaceVersion> {
    assertHash(input.seedHex);
    if (input.parent !== undefined && input.parent !== null) assertHash(input.parent);
    if (new TextEncoder().encode(input.message).length > 4096)
        throw new Error("Version message exceeds 4 KiB");
    if (input.source && input.parent)
        throw new Error("A source is only valid for the first remix version");
    if (input.source) assertHash(input.source.commitHash);
    const treeHash = await buildTree(storage, input.manifest);
    const createdAt = Date.now();
    const timestamp = BigInt(Math.floor(createdAt / 1000));
    const encoded = input.source
        ? mkit.remix_encode_and_sign(
              treeHash,
              "",
              JSON.stringify([
                  {
                      upstream_id_hex: mkit.blake3_hex(
                          new TextEncoder().encode(input.source.repository),
                      ),
                      commit_hash_hex: input.source.commitHash,
                  },
              ]),
              input.message,
              timestamp,
              input.seedHex,
          )
        : mkit.commit_encode_and_sign(
              treeHash,
              input.parent ?? "",
              input.message,
              timestamp,
              input.seedHex,
          );
    try {
        const bytes = encoded.bytes;
        const info = input.source ? mkit.remix_decode(bytes) : mkit.commit_decode(bytes);
        try {
            return {
                hash: await putObject(storage, bytes),
                treeHash,
                parent: input.parent ?? null,
                message: input.message,
                signer: info.signer_hex,
                createdAt,
            };
        } finally {
            info.free();
        }
    } finally {
        encoded.free();
    }
}
