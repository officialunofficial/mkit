import { describe, expect, it } from "vitest";
import { authenticate, requestSession, sessionCookie, tokenDigest, verifyGrant } from "./auth";
import { type AgentGrant, grantMessage } from "./contracts";
import { encoder, fromHex, hex, mkit } from "./mkit";

const NOW = 1_800_000_000_000;
const AUDIENCE = "https://mkit.sh";
const ID = "ab".repeat(16);
const REPOSITORY = `workspace:${ID}`;
const PATH = `/api/workspaces/${ID}/tasks`;
const OWNER_SEED = "01".repeat(32);
const OWNER_PUBLIC = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const BODY = '{"prompt":"Create café ☕","file":"src/main.ts"}';

// Produced by the actual apps/web/src/lib/repo/envelope.ts
// buildSignedEnvelope + envelopeHeaders with seed 01*32, the body above,
// createdAt=NOW, expiresAt=NOW+300000, and idempotencyKey=02*32. Keep this
// independent of authenticate so byte-layout changes cannot self-validate.
const BROWSER_HEADERS = {
    "Content-Type": "application/json",
    "X-Envelope-Version": "2",
    "X-Audience": AUDIENCE,
    "X-Repository": REPOSITORY,
    "X-Content-Commitment": "body:82e6b8796fdd2b2b3282f4169661a0eb7e06978e119ea6fd67f06436e5ddaba3",
    "X-Expires-At": "1800000300000",
    "X-Public-Key": OWNER_PUBLIC,
    "X-Signature":
        "294d28de822a48860164cf5518d5970581cdb70487a1764bf37ddd1022a1a67ca41e80c32fec4bf40d24b6fac5891d14c3a98fb909ef6102479530a5daf09c03",
    "X-Digest": "82e6b8796fdd2b2b3282f4169661a0eb7e06978e119ea6fd67f06436e5ddaba3",
    "X-Created-At": "1800000000000",
    "Idempotency-Key": "02".repeat(32),
};

function request(
    options: {
        body?: string;
        path?: string;
        origin?: string;
        headers?: Record<string, string>;
    } = {},
) {
    return new Request(`${options.origin ?? AUDIENCE}${options.path ?? PATH}`, {
        method: "POST",
        body: options.body ?? BODY,
        headers: { ...BROWSER_HEADERS, ...options.headers },
    });
}

/** Sign an intentionally invalid time window to distinguish policy rejection
 * from merely rejecting a changed header with a stale signature. */
function signedTimes(created: string, expires: string): Record<string, string> {
    const canonical = [
        "mkit-write:v2",
        AUDIENCE,
        REPOSITORY,
        PATH,
        BROWSER_HEADERS["X-Content-Commitment"],
        created,
        expires,
        BROWSER_HEADERS["Idempotency-Key"],
    ].join("\n");
    return {
        "X-Created-At": created,
        "X-Expires-At": expires,
        "X-Signature": hex(
            mkit.ed25519_sign(
                fromHex(mkit.blake3_hex(encoder.encode(canonical))),
                fromHex(OWNER_SEED),
            ),
        ),
    };
}

describe("workspace auth v2", () => {
    it("accepts an actual browser envelope and returns the operation commitment", async () => {
        const result = await authenticate(request(), AUDIENCE, REPOSITORY, NOW);
        expect(result).toEqual({
            publicKey: OWNER_PUBLIC,
            nonce: "02".repeat(32),
            digest: "711121e56f370d32ce76d476900b8858a12e39db5f6782739b9e9dae53b02e66",
            expiresAt: NOW + 300_000,
            body: JSON.parse(BODY),
        });
    });

    it.each([
        ["body", { body: BODY + " " }],
        ["path", { path: `/api/workspaces/${ID}/files` }],
        ["repository", { headers: { "X-Repository": "workspace:other" } }],
        ["audience header", { headers: { "X-Audience": "https://other.example" } }],
        ["audience URL", { origin: "https://other.example" }],
        ["query string", { path: PATH + "?extra=true" }],
        ["expiry", { headers: { "X-Expires-At": String(NOW + 100_000) } }],
        ["nonce", { headers: { "Idempotency-Key": "03".repeat(32) } }],
        ["content commitment", { headers: { "X-Content-Commitment": `body:${"00".repeat(32)}` } }],
        ["forged signature", { headers: { "X-Signature": "00".repeat(64) } }],
    ] satisfies [string, Parameters<typeof request>[0]][])(
        "rejects altered %s",
        async (_label, options) => {
            await expect(
                authenticate(request(options), AUDIENCE, REPOSITORY, NOW),
            ).rejects.toMatchObject({ status: 401 });
        },
    );

    it("rejects even the intact envelope when verified for another repository", async () => {
        await expect(
            authenticate(request(), AUDIENCE, "workspace:other", NOW),
        ).rejects.toMatchObject({ status: 401 });
    });

    it("rejects cross-origin browser requests", async () => {
        await expect(
            authenticate(
                request({ headers: { Origin: "https://other.example" } }),
                AUDIENCE,
                REPOSITORY,
                NOW,
            ),
        ).rejects.toMatchObject({ status: 403 });
    });

    it.each([
        ["expired", String(NOW - 1), String(NOW)],
        ["future creation", String(NOW + 30_001), String(NOW + 90_000)],
        ["too long", String(NOW), String(NOW + 300_001)],
        ["empty interval", String(NOW), String(NOW)],
        ["noncanonical number", `0${NOW}`, String(NOW + 100_000)],
        ["negative creation", "-1", "1000"],
    ])("rejects correctly signed %s times", async (_label, created, expires) => {
        await expect(
            authenticate(
                request({ headers: signedTimes(created, expires) }),
                AUDIENCE,
                REPOSITORY,
                NOW,
            ),
        ).rejects.toMatchObject({ status: 401 });
    });
});

function grant(): AgentGrant {
    return {
        version: 1,
        workspaceId: ID,
        ownerPublicKey: OWNER_PUBLIC,
        agentPublicKey: hex(mkit.ed25519_pubkey_from_seed(fromHex("03".repeat(32)))),
        source: { kind: "demo", repository: "lobby-v2", commitHash: "04".repeat(32), ref: "main" },
        permissions: ["files", "commands", "versions"],
        createdAt: NOW,
        expiresAt: NOW + 86_400_000,
    };
}

function signedGrant(value: AgentGrant, seed = OWNER_SEED) {
    const digest = fromHex(mkit.blake3_hex(encoder.encode(grantMessage(value))));
    return { grant: value, signature: hex(mkit.ed25519_sign(digest, fromHex(seed))) };
}

describe("delegated agent authorization", () => {
    it("accepts the exact owner-signed grant after JSON transport", () => {
        const expected = grant();
        const candidate = signedGrant(expected);
        expect(verifyGrant(JSON.parse(JSON.stringify(candidate)), expected, NOW)).toEqual(
            candidate,
        );
    });

    it("rejects a grant signed by another key", () => {
        const expected = grant();
        expect(() => verifyGrant(signedGrant(expected, "05".repeat(32)), expected, NOW)).toThrow(
            "Invalid agent authorization",
        );
    });

    it.each(["workspace", "agent", "source", "permissions", "expiry"])(
        "rejects changed %s with the original signature",
        (field) => {
            const expected = grant();
            const candidate = signedGrant(expected);
            candidate.grant = structuredClone(expected);
            if (field === "workspace") candidate.grant.workspaceId = "cd".repeat(16);
            if (field === "agent") candidate.grant.agentPublicKey = "06".repeat(32);
            if (field === "source") candidate.grant.source.commitHash = "07".repeat(32);
            if (field === "permissions") candidate.grant.permissions.reverse();
            if (field === "expiry") candidate.grant.expiresAt += 1;
            expect(() => verifyGrant(candidate, expected, NOW)).toThrow("expired or changed");
        },
    );

    it("rejects expired or missing authorizations", () => {
        const expected = grant();
        expect(() => verifyGrant(signedGrant(expected), expected, expected.expiresAt)).toThrow(
            "expired or changed",
        );
        for (const invalid of [
            null,
            {},
            { grant: expected },
            { grant: expected, signature: "bad" },
        ]) {
            expect(() => verifyGrant(invalid, expected, NOW)).toThrow("expired or changed");
        }
    });
});

describe("workspace session cookies", () => {
    const token = "06".repeat(32);
    it("scopes the secure HttpOnly cookie to one workspace", () => {
        expect(sessionCookie(ID, token)).toBe(
            `mkit_workspace=${token}; Path=/api/workspaces/${ID}; HttpOnly; SameSite=Strict; Max-Age=3600; Secure`,
        );
        expect(sessionCookie(ID, token, false)).not.toContain("; Secure");
    });
    it("finds the exact cookie among unrelated cookies and returns only its digest", () => {
        const req = new Request(AUDIENCE + PATH, {
            headers: { Cookie: `other=a; mkit_workspace=${token}; next=b` },
        });
        expect(requestSession(req)).toBe(tokenDigest(token));
        expect(requestSession(req)).not.toBe(token);
    });
    it.each([
        "",
        "mkit_workspace=",
        "mkit_workspace=short",
        `other_mkit_workspace=${token}`,
        `mkit_workspace=${"AA".repeat(32)}`,
        `mkit_workspace=${token}%00`,
    ])("rejects malformed or absent cookie %j", (cookie) => {
        expect(
            requestSession(new Request(AUDIENCE + PATH, { headers: { Cookie: cookie } })),
        ).toBeNull();
    });
});
