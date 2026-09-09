import { type AgentGrant, grantMessage, type SignedAgentGrant, WORKSPACE_API } from "./contracts";
import { HttpError, readBytes } from "./http";
import { encoder, fromHex, hex, mkit } from "./mkit";

export type AuthenticatedOperation = {
    publicKey: string;
    nonce: string;
    digest: string;
    expiresAt: number;
    body: unknown;
};

/** Exact auth-v2 envelope used by mkit's browser and repository service. */
export async function authenticate(
    request: Request,
    audience: string,
    repository: string,
    now = Date.now(),
    maxBodyBytes = 400000,
): Promise<AuthenticatedOperation> {
    const headers = request.headers;
    const url = new URL(request.url);
    if (url.origin !== audience)
        console.warn(
            JSON.stringify({ event: "signing_origin_mismatch", origin: url.origin, audience }),
        );
    if (url.origin !== audience || url.search || request.method !== "POST")
        throw new HttpError(401, "Invalid signing destination.");
    if (headers.get("origin") && headers.get("origin") !== audience)
        throw new HttpError(403, "Open this workspace on mkit.sh.");
    if (headers.get("content-type")?.split(";")[0] !== "application/json")
        throw new HttpError(415, "Use application/json.");
    const publicKey = headers.get("x-public-key") ?? "";
    const signature = headers.get("x-signature") ?? "";
    const digest = headers.get("x-digest") ?? "";
    const nonce = headers.get("idempotency-key") ?? "";
    const created = headers.get("x-created-at") ?? "";
    const expires = headers.get("x-expires-at") ?? "";
    const createdAt = Number(created),
        expiresAt = Number(expires);
    if (
        headers.get("x-envelope-version") !== "2" ||
        headers.get("x-audience") !== audience ||
        headers.get("x-repository") !== repository ||
        headers.get("x-content-commitment") !== `body:${digest}` ||
        ![publicKey, digest, nonce].every((value) => /^[0-9a-f]{64}$/.test(value)) ||
        !/^[0-9a-f]{128}$/.test(signature) ||
        !Number.isSafeInteger(createdAt) ||
        !Number.isSafeInteger(expiresAt) ||
        created !== String(createdAt) ||
        expires !== String(expiresAt) ||
        createdAt < 0 ||
        createdAt > now + 30000 ||
        expiresAt <= now ||
        expiresAt <= createdAt ||
        expiresAt - createdAt > 300000
    ) {
        throw new HttpError(401, "Unlock your passkey identity and try again.");
    }
    const bytes = await readBytes(request, maxBodyBytes);
    if (mkit.blake3_hex(bytes) !== digest) throw new HttpError(401, "The signed request changed.");
    const canonical = [
        "mkit-write:v2",
        audience,
        repository,
        url.pathname,
        `body:${digest}`,
        created,
        expires,
        nonce,
    ].join("\n");
    const signingDigest = fromHex(mkit.blake3_hex(encoder.encode(canonical)));
    if (!mkit.ed25519_verify(fromHex(signature), signingDigest, fromHex(publicKey)))
        throw new HttpError(401, "Invalid identity signature.");
    let body: unknown;
    try {
        body = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
    } catch {
        throw new HttpError(400, "Invalid JSON request.");
    }
    return {
        publicKey,
        nonce,
        digest: mkit.blake3_hex(encoder.encode(canonical)),
        expiresAt,
        body,
    };
}

export function verifyGrant(
    value: unknown,
    expected: AgentGrant,
    now = Date.now(),
): SignedAgentGrant {
    const candidate = value as Partial<SignedAgentGrant> | null;
    if (
        !candidate ||
        typeof candidate.signature !== "string" ||
        !/^[0-9a-f]{128}$/.test(candidate.signature) ||
        !candidate.grant ||
        JSON.stringify(candidate.grant) !== JSON.stringify(expected) ||
        expected.expiresAt <= now
    ) {
        throw new HttpError(
            403,
            "This agent authorization has expired or changed. Start the remix again.",
        );
    }
    const digest = fromHex(mkit.blake3_hex(encoder.encode(grantMessage(expected))));
    if (
        !mkit.ed25519_verify(fromHex(candidate.signature), digest, fromHex(expected.ownerPublicKey))
    )
        throw new HttpError(403, "Invalid agent authorization.");
    return { grant: expected, signature: candidate.signature };
}

export function randomToken(): string {
    return hex(crypto.getRandomValues(new Uint8Array(32)));
}
export function tokenDigest(token: string): string {
    return mkit.blake3_hex(encoder.encode(token));
}

export function sessionCookie(id: string, token: string, secure = true): string {
    return `mkit_workspace=${token}; Path=${WORKSPACE_API}/${id}; HttpOnly; SameSite=Strict; Max-Age=3600${secure ? "; Secure" : ""}`;
}

export function requestSession(request: Request): string | null {
    const token = request.headers
        .get("Cookie")
        ?.split(";")
        .map((x) => x.trim())
        .find((x) => x.startsWith("mkit_workspace="))
        ?.slice(15);
    return token && /^[0-9a-f]{64}$/.test(token) ? tokenDigest(token) : null;
}
