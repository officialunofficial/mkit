import type { WorkspaceSource } from "./contracts";
import { HttpError, readBytes } from "./http";
import { decoder, fromHex, mkit } from "./mkit";
import {
    MAX_FILES,
    putBlob,
    validateManifest,
    validatePath,
    type FileManifest,
    type ObjectStorage,
} from "./objects";
import {
    CONSUMER_BUNDLE_BYTES,
    consumerLimitsJson,
    verifyPartialSnapshot,
} from "./partial-wasm";

export const PUBLIC_PARTIAL_MODE = "public-partial-v1" as const;
const FETCH_TIMEOUT_MS = 15_000;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX_BYTES = /^(?:[0-9a-f]{2})+$/;

export type PartialPrepareRequest = {
    kind: "partial-bundle";
    baseCommit: string;
    selectedPaths: string[][];
    bundleDigest: string;
};

export function publicPartialOrigin(env: {
    PUBLIC_PARTIAL_BUNDLE_ORIGIN?: string;
    PUBLIC_PARTIAL_RESOURCE_OK?: string;
}): string {
    const origin = trustedBundleOrigin(env.PUBLIC_PARTIAL_BUNDLE_ORIGIN);
    if (!origin) throw new HttpError(400, "Public partial bundles are not enabled.");
    if (env.PUBLIC_PARTIAL_RESOURCE_OK !== "1")
        throw new HttpError(
            400,
            "Public partial bundles are not resource-validated on this deployment.",
        );
    return origin;
}

export function trustedBundleOrigin(value: string | undefined): string | undefined {
    if (!value) return undefined;
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        throw new HttpError(400, "Public partial bundle origin is invalid.");
    }
    if (url.protocol !== "https:")
        throw new HttpError(400, "Public partial bundle origin must be HTTPS.");
    if (url.username || url.password)
        throw new HttpError(400, "Public partial bundle origin must not include credentials.");
    if (url.search || url.hash)
        throw new HttpError(400, "Public partial bundle origin must not include a query or fragment.");
    if (url.pathname !== "" && url.pathname !== "/")
        throw new HttpError(400, "Public partial bundle origin must not include a path.");
    return `${url.protocol}//${url.host}`;
}

export function bundleObjectUrl(origin: string, digest: string): string {
    if (!HEX64.test(digest)) throw new HttpError(400, "Invalid bundle digest.");
    return `${origin}/${digest}.mkwb`;
}

export function validatePartialPrepare(body: Record<string, unknown>): PartialPrepareRequest {
    const keys = Object.keys(body);
    if (keys.some((key) => !["kind", "baseCommit", "selectedPaths", "bundleDigest"].includes(key)))
        throw new HttpError(400, "Unknown partial-bundle field.");
    const baseCommit = textHash(body.baseCommit, "base commit");
    const bundleDigest = textHash(body.bundleDigest, "bundle digest");
    const selectedPaths = validateSelectedPaths(body.selectedPaths);
    return { kind: "partial-bundle", baseCommit, selectedPaths, bundleDigest };
}

export function validateSelectedPaths(value: unknown): string[][] {
    if (!Array.isArray(value) || value.length < 1 || value.length > MAX_FILES)
        throw new HttpError(400, "Select between 1 and 256 files.");
    const paths: string[][] = [];
    let prior: Uint8Array | undefined;
    let aggregate = 0;
    for (const [index, entry] of value.entries()) {
        if (!Array.isArray(entry) || entry.length < 1 || entry.length > 32)
            throw new HttpError(400, `selectedPaths[${index}] is not a valid path.`);
        const components: string[] = [];
        const joined: number[] = [];
        for (const [componentIndex, component] of entry.entries()) {
            if (typeof component !== "string" || !HEX_BYTES.test(component))
                throw new HttpError(
                    400,
                    `selectedPaths[${index}][${componentIndex}] is not lowercase hex.`,
                );
            const bytes = fromHex(component);
            if (bytes.length > 255)
                throw new HttpError(400, `selectedPaths[${index}][${componentIndex}] exceeds 255 bytes.`);
            if (componentIndex) joined.push(0x2f);
            joined.push(...bytes);
            components.push(component);
        }
        if (joined.length > 1024) throw new HttpError(400, "A selected path exceeds 1,024 bytes.");
        aggregate += joined.length;
        if (aggregate > 64 * 1024) throw new HttpError(400, "Selected paths exceed 64 KiB.");
        const encoded = new Uint8Array(joined);
        if (prior && compareBytes(prior, encoded) >= 0)
            throw new HttpError(400, "selectedPaths must be strictly ordered and unique.");
        prior = encoded;
        const path = pathFromHex(components);
        validatePath(path);
        paths.push(components);
    }
    return paths;
}

export function pathFromHex(components: string[]): string {
    return components.map((component) => decoder.decode(fromHex(component))).join("/");
}

export async function fetchPublicBundle(
    origin: string,
    digest: string,
    fetcher: typeof fetch = fetch,
): Promise<Uint8Array> {
    const url = bundleObjectUrl(origin, digest);
    let response: Response;
    try {
        response = await fetcher(url, {
            method: "GET",
            redirect: "error",
            signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
            headers: { Accept: "application/octet-stream" },
        });
    } catch (error) {
        if (error instanceof DOMException && error.name === "TimeoutError")
            throw new HttpError(504, "The public bundle request timed out.");
        if (error instanceof TypeError)
            throw new HttpError(400, "Public bundle redirects are not allowed.");
        throw error;
    }
    if (!response.ok) throw new HttpError(502, "The public bundle could not be fetched.");
    let bytes = await readBytes(response, CONSUMER_BUNDLE_BYTES);
    if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
        const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
        bytes = await readBytes(new Response(stream), CONSUMER_BUNDLE_BYTES);
    }
    return bytes;
}

export function bundleStorageKey(workspaceId: string, digest: string): string {
    return `partial/${workspaceId}/bundle/${digest}`;
}

export async function importPartialBundle(
    origin: string | undefined,
    storage: ObjectStorage,
    workspaceId: string,
    request: PartialPrepareRequest,
    fetcher: typeof fetch = fetch,
): Promise<{ source: WorkspaceSource; files: FileManifest; bundleKey: string }> {
    const trusted = trustedBundleOrigin(origin);
    if (!trusted) throw new HttpError(400, "Public partial bundles are not enabled.");
    const bytes = await fetchPublicBundle(trusted, request.bundleDigest, fetcher);
    if (mkit.blake3_hex(bytes) !== request.bundleDigest)
        throw new HttpError(400, "Bundle digest does not match the delivered bytes.");
    const selectedPathsJson = JSON.stringify(request.selectedPaths);
    const snapshot = verifyPartialSnapshot(
        bytes,
        request.baseCommit,
        selectedPathsJson,
        consumerLimitsJson(),
    );
    if (snapshot.coverage !== "selected-only")
        throw new HttpError(400, "Partial snapshot coverage must be selected-only.");
    if (snapshot.files.length !== request.selectedPaths.length)
        throw new HttpError(400, "Verified files do not match the selected paths.");
    const files: FileManifest = Object.create(null);
    for (const [index, selected] of request.selectedPaths.entries()) {
        const file = snapshot.files[index]!;
        if (file.pathJson !== JSON.stringify(selected))
            throw new HttpError(400, "Verified path order does not match the signed selection.");
        const path = pathFromHex(selected);
        files[path] = {
            hash: await putBlob(storage, file.bytes),
            size: file.bytes.length,
            mode: file.mode,
        };
    }
    validateManifest(files);
    const bundleKey = bundleStorageKey(workspaceId, request.bundleDigest);
    await storage.put(bundleKey, bytes);
    const stored = await storage.get(bundleKey);
    if (!stored) throw new HttpError(500, "The public bundle could not be saved.");
    const storedBytes = new Uint8Array(await stored.arrayBuffer());
    if (mkit.blake3_hex(storedBytes) !== request.bundleDigest)
        throw new HttpError(500, "Stored bundle digest mismatch.");
    return {
        source: {
            kind: "partial-bundle",
            repository: request.bundleDigest,
            commitHash: request.baseCommit,
            selectedPaths: request.selectedPaths,
            bundleDigest: request.bundleDigest,
            mode: PUBLIC_PARTIAL_MODE,
        },
        files,
        bundleKey,
    };
}

function textHash(value: unknown, label: string): string {
    if (typeof value !== "string" || !HEX64.test(value))
        throw new HttpError(400, `Invalid ${label}.`);
    return value;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    const length = Math.min(left.length, right.length);
    for (let index = 0; index < length; index++) {
        if (left[index] !== right[index]) return left[index]! - right[index]!;
    }
    return left.length - right.length;
}
