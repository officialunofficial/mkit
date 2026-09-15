import { HttpError, record, text } from "./http";
import { encoder } from "./mkit";
import {
    MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, putBlob, validateManifest, validatePath,
    type FileManifest, type ObjectStorage,
} from "./objects";

type VersionEdit = { path: string; bytes: Uint8Array; expectedHash: string | null };

export function versionRequest(body: Record<string, unknown>): { message: string; edits: VersionEdit[] } {
    const message = text(body.message, 200, "version message").trim();
    const input = body.edits === undefined ? [] : body.edits;
    if (!Array.isArray(input) || input.length > MAX_FILES)
        throw new HttpError(400, "A version can edit up to 256 files.");
    const paths = new Set<string>();
    let total = 0;
    const edits = input.map(value => {
        const entry = record(value), path = text(entry.path, 1024, "path");
        try { validatePath(path); }
        catch { throw new HttpError(400, "Invalid workspace path."); }
        if (paths.has(path)) throw new HttpError(400, "A version cannot edit the same path twice.");
        paths.add(path);
        if (typeof entry.content !== "string") throw new HttpError(400, "Invalid file content.");
        const expectedHash = entry.expectedHash;
        if (expectedHash !== null && (typeof expectedHash !== "string" || !/^[0-9a-f]{64}$/.test(expectedHash)))
            throw new HttpError(400, "Invalid expected file hash.");
        const bytes = encoder.encode(entry.content);
        total += bytes.length;
        if (bytes.length > MAX_FILE_BYTES || total > MAX_TOTAL_BYTES)
            throw new HttpError(413, "Version edits exceed the workspace file limits.");
        return { path, bytes, expectedHash };
    });
    return { message, edits };
}

/** Check every precondition and manifest limit before writing any edited objects. */
export async function applyVersionEdits(
    current: FileManifest, edits: VersionEdit[], objects: ObjectStorage,
): Promise<FileManifest> {
    const files: FileManifest = Object.assign(Object.create(null), current);
    for (const edit of edits) {
        const before = Object.hasOwn(current, edit.path) ? current[edit.path] : undefined;
        if (edit.expectedHash !== (before?.hash ?? null))
            throw new HttpError(409, `The file ${edit.path} changed. Reload it before saving.`);
        files[edit.path] = {
            hash: before?.hash ?? "0".repeat(64),
            size: edit.bytes.length,
            mode: before?.mode ?? "blob",
        };
    }
    try { validateManifest(files); }
    catch { throw new HttpError(400, "The edited files exceed workspace limits or contain conflicting paths."); }
    for (const edit of edits)
        files[edit.path] = { ...files[edit.path], hash: await putBlob(objects, edit.bytes) };
    return files;
}
