import { HttpError } from "./http";
import { encoder, fromHex, mkit } from "./mkit";
import { getBlob, putObject, type FileManifest, type ObjectStorage } from "./objects";
import { pathFromHex } from "./partial-source";
import { PartialNoChanges, bytesHex, editAndExportPartial } from "./partial-wasm";

export const PENDING_SUBMISSION =
    "PendingSubmission: export this candidate before making more changes.";

export type PartialCandidate = {
    id: string;
    digest: string;
    key: string;
    rootHex: string;
    baseCommit: string;
    coverage: "selected-only";
};

export function candidateStorageKey(workspaceId: string, candidateHex: string): string {
    return `partial/${workspaceId}/update/${candidateHex}`;
}

export async function createPartialCandidate(input: {
    workspaceId: string;
    objects: ObjectStorage;
    bundle: Uint8Array;
    baseCommit: string;
    selectedPaths: string[][];
    original: FileManifest;
    current: FileManifest;
    seedHex: string;
    agentPublicKey: string;
    message: string;
    beforeSign?: () => Promise<void>;
}): Promise<{ status: "no_changes" } | { status: "ready"; candidate: PartialCandidate }> {
    const replacements = await replacementRecords(
        input.objects,
        input.selectedPaths,
        input.original,
        input.current,
    );
    await input.beforeSign?.();
    if (!replacements.length) return { status: "no_changes" };
    let exported;
    try {
        exported = editAndExportPartial(
            input.bundle,
            input.baseCommit,
            JSON.stringify(input.selectedPaths),
            JSON.stringify(replacements),
            "ed25519",
            fromHex(input.agentPublicKey),
            encoder.encode(input.message),
            Math.floor(Date.now() / 1000),
            fromHex(input.seedHex),
        );
    } catch (error) {
        if (error instanceof PartialNoChanges) return { status: "no_changes" };
        throw error;
    }
    if (exported.coverage !== "selected-only")
        throw new HttpError(500, "Partial export coverage must be selected-only.");
    const commitId = await putObject(input.objects, exported.signedCommitBytes);
    if (commitId !== exported.candidateHex)
        throw new HttpError(500, "Signed candidate identity mismatch.");
    const key = candidateStorageKey(input.workspaceId, exported.candidateHex);
    await input.objects.put(key, exported.updateBytes);
    const stored = await input.objects.get(key);
    if (!stored) throw new HttpError(500, "The partial update could not be saved.");
    const storedBytes = new Uint8Array(await stored.arrayBuffer());
    const digest = mkit.blake3_hex(storedBytes);
    if (digest !== mkit.blake3_hex(exported.updateBytes) || storedBytes.length !== exported.updateBytes.length)
        throw new HttpError(500, "Stored candidate digest mismatch.");
    return {
        status: "ready",
        candidate: {
            id: exported.candidateHex,
            digest,
            key,
            rootHex: exported.rootHex,
            baseCommit: input.baseCommit,
            coverage: "selected-only",
        },
    };
}

async function replacementRecords(
    objects: ObjectStorage,
    selectedPaths: string[][],
    original: FileManifest,
    current: FileManifest,
): Promise<{ path: string[]; bytes_hex: string }[]> {
    const originalPaths = new Set(Object.keys(original));
    const currentPaths = new Set(Object.keys(current));
    if (originalPaths.size !== currentPaths.size)
        throw new HttpError(400, "Partial capture cannot add or remove selected paths.");
    const replacements: { path: string[]; bytes_hex: string }[] = [];
    for (const components of selectedPaths) {
        const path = pathFromHex(components);
        const before = original[path];
        const after = current[path];
        if (!before || !after || !originalPaths.has(path) || !currentPaths.has(path))
            throw new HttpError(400, "Partial capture cannot rename selected paths.");
        if (after.mode !== before.mode)
            throw new HttpError(400, "Partial capture cannot change file modes.");
        if (after.hash === before.hash) continue;
        const bytes = await getBlob(objects, after.hash);
        if (bytes.length !== after.size) throw new HttpError(400, "File size mismatch.");
        replacements.push({ path: components, bytes_hex: bytesHex(bytes) });
    }
    for (const path of currentPaths)
        if (!originalPaths.has(path))
            throw new HttpError(400, "Partial capture cannot add selected paths.");
    return replacements;
}
