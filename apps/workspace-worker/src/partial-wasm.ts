import { HttpError } from "./http";
import { hex, mkit } from "./mkit";
import { MAX_FILE_BYTES, MAX_TOTAL_BYTES } from "./objects";

export const CONSUMER_BUNDLE_BYTES = 12 * 1024 * 1024;
export const CONSUMER_WITNESS_BYTES = 6 * 1024 * 1024;
export const MAX_LIMITS_JSON_BYTES = 16 * 1024;
export const MAX_REPLACEMENTS_JSON_BYTES = 12 * 1024 * 1024;

export function consumerLimitsJson(): string {
    return JSON.stringify({
        max_selected_file_bytes: MAX_FILE_BYTES,
        max_total_selected_bytes: MAX_TOTAL_BYTES,
        max_bundle_bytes: CONSUMER_BUNDLE_BYTES,
        max_witness_bytes: CONSUMER_WITNESS_BYTES,
    });
}

export type WasmError = { code: string; message: string };

export function parseWasmError(error: unknown): WasmError {
    if (error instanceof Error) {
        try {
            const parsed = JSON.parse(error.message) as { code?: unknown; message?: unknown };
            if (typeof parsed.code === "string" && typeof parsed.message === "string")
                return { code: parsed.code, message: parsed.message };
        } catch {
            /* not a wasm adapter payload */
        }
        return { code: "wasm_error", message: error.message };
    }
    return { code: "wasm_error", message: "Partial verification failed." };
}

export class PartialNoChanges extends HttpError {
    constructor() {
        super(409, "No selected files changed.");
    }
}

export function throwWasm(error: unknown): never {
    const parsed = parseWasmError(error);
    if (parsed.code === "no_changes") throw new PartialNoChanges();
    const status =
        parsed.code === "invalid_limits" || parsed.code === "invalid_selected_paths"
            ? 400
            : parsed.code === "workspace_too_large" ||
                parsed.code === "witness_too_large" ||
                parsed.code === "submission_too_large"
              ? 413
              : 400;
    throw new HttpError(status, parsed.message);
}

type SnapshotFile = {
    path_json: string;
    mode: string;
    representation_id_hex: string;
    bytes: Uint8Array;
    free(): void;
};

type Snapshot = {
    coverage: string;
    file_count: number;
    file(index: number): SnapshotFile | undefined;
    free(): void;
};

type EditResult = {
    root_hex: string;
    candidate_hex: string;
    signed_commit_bytes: Uint8Array;
    update_bytes: Uint8Array;
    coverage: string;
    free(): void;
};

const wasm = mkit as typeof mkit & {
    partial_verify_snapshot: (
        bundle: Uint8Array,
        expectedBaseHex: string,
        selectedPathsJson: string,
        limitsJson?: string | null,
    ) => Snapshot;
    partial_edit_and_export_with_limits: (
        bundle: Uint8Array,
        expectedBaseHex: string,
        selectedPathsJson: string,
        replacementsJson: string,
        authorKind: string,
        authorBytes: Uint8Array,
        message: Uint8Array,
        timestamp: bigint,
        seed: Uint8Array,
        limitsJson?: string | null,
    ) => EditResult;
    partial_edit_and_export: (
        bundle: Uint8Array,
        expectedBaseHex: string,
        selectedPathsJson: string,
        replacementsJson: string,
        authorKind: string,
        authorBytes: Uint8Array,
        message: Uint8Array,
        timestamp: bigint,
        seed: Uint8Array,
    ) => EditResult;
};

export type VerifiedSelectedFile = {
    pathJson: string;
    mode: "blob" | "exec";
    representationId: string;
    bytes: Uint8Array;
};

export function verifyPartialSnapshot(
    bundle: Uint8Array,
    expectedBaseHex: string,
    selectedPathsJson: string,
    limitsJson = consumerLimitsJson(),
): { coverage: string; files: VerifiedSelectedFile[] } {
    if (limitsJson.length > MAX_LIMITS_JSON_BYTES)
        throw new HttpError(400, "Partial limits JSON exceeds 16 KiB.");
    let snapshot: Snapshot | undefined;
    try {
        snapshot = wasm.partial_verify_snapshot(
            bundle,
            expectedBaseHex,
            selectedPathsJson,
            limitsJson,
        );
        const files: VerifiedSelectedFile[] = [];
        for (let index = 0; index < snapshot.file_count; index++) {
            const file = snapshot.file(index);
            if (!file) throw new HttpError(500, "Incomplete verified snapshot.");
            try {
                if (file.mode !== "blob" && file.mode !== "exec")
                    throw new HttpError(400, "Selected path is not a regular or executable file.");
                files.push({
                    pathJson: file.path_json,
                    mode: file.mode,
                    representationId: file.representation_id_hex,
                    bytes: Uint8Array.from(file.bytes),
                });
            } finally {
                file.free();
            }
        }
        return { coverage: snapshot.coverage, files };
    } catch (error) {
        if (error instanceof HttpError) throw error;
        throwWasm(error);
    } finally {
        snapshot?.free();
    }
    throw new HttpError(500, "Partial verification failed.");
}

export type PartialExport = {
    rootHex: string;
    candidateHex: string;
    signedCommitBytes: Uint8Array;
    updateBytes: Uint8Array;
    coverage: string;
};

export function editAndExportPartial(
    bundle: Uint8Array,
    expectedBaseHex: string,
    selectedPathsJson: string,
    replacementsJson: string,
    authorKind: string,
    authorBytes: Uint8Array,
    message: Uint8Array,
    timestamp: number,
    seed: Uint8Array,
    limitsJson = consumerLimitsJson(),
): PartialExport {
    if (limitsJson.length > MAX_LIMITS_JSON_BYTES)
        throw new HttpError(400, "Partial limits JSON exceeds 16 KiB.");
    if (replacementsJson.length > MAX_REPLACEMENTS_JSON_BYTES)
        throw new HttpError(413, "Replacement payload exceeds the consumer limit.");
    let result: EditResult | undefined;
    try {
        result = wasm.partial_edit_and_export_with_limits(
            bundle,
            expectedBaseHex,
            selectedPathsJson,
            replacementsJson,
            authorKind,
            authorBytes,
            message,
            BigInt(timestamp),
            seed,
            limitsJson,
        );
        return {
            rootHex: result.root_hex,
            candidateHex: result.candidate_hex,
            signedCommitBytes: Uint8Array.from(result.signed_commit_bytes),
            updateBytes: Uint8Array.from(result.update_bytes),
            coverage: result.coverage,
        };
    } catch (error) {
        throwWasm(error);
    } finally {
        result?.free();
    }
    throw new HttpError(500, "Partial export failed.");
}

export function defaultEditAndExportPartial(
    bundle: Uint8Array,
    expectedBaseHex: string,
    selectedPathsJson: string,
    replacementsJson: string,
    authorKind: string,
    authorBytes: Uint8Array,
    message: Uint8Array,
    timestamp: number,
    seed: Uint8Array,
): PartialExport {
    let result: EditResult | undefined;
    try {
        result = wasm.partial_edit_and_export(
            bundle,
            expectedBaseHex,
            selectedPathsJson,
            replacementsJson,
            authorKind,
            authorBytes,
            message,
            BigInt(timestamp),
            seed,
        );
        return {
            rootHex: result.root_hex,
            candidateHex: result.candidate_hex,
            signedCommitBytes: Uint8Array.from(result.signed_commit_bytes),
            updateBytes: Uint8Array.from(result.update_bytes),
            coverage: result.coverage,
        };
    } catch (error) {
        throwWasm(error);
    } finally {
        result?.free();
    }
    throw new HttpError(500, "Partial export failed.");
}

export function bytesHex(bytes: Uint8Array): string {
    return hex(bytes);
}
