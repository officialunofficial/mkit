import { randomToken, tokenDigest, type AuthenticatedOperation } from "./auth";
import { HttpError } from "./http";

export const BROWSER_SESSION_TTL = 7 * 24 * 60 * 60 * 1000;
const CLEANUP_BATCH = 32;
const EXPIRY_PREFIX = "browser-expiry:";
const validDigest = (value: string) => /^[0-9a-f]{64}$/.test(value);

export type BrowserSession = { id: string; publicKey: string; expiresAt: number };
type SessionRecord = BrowserSession & { receiptKey: string };
type LoginReceipt = {
    digest: string;
    sessionId: string;
    expiresAt: number;
    /** Only retained for the signed login's short retry window. */
    token?: string;
};

function sessionKey(id: string): string {
    return `browser-session:${id}`;
}

function expiryKey(expiresAt: number, key: string): string {
    return `${EXPIRY_PREFIX}${String(expiresAt).padStart(16, "0")}:${key}`;
}

function publicSession(record: SessionRecord): BrowserSession {
    return { id: record.id, publicKey: record.publicKey, expiresAt: record.expiresAt };
}

/** Runs inside the caller's transaction; work is bounded regardless of backlog. */
async function pruneExpired(storage: DurableObjectTransaction, now: number): Promise<void> {
    const expired = await storage.list<string>({
        prefix: EXPIRY_PREFIX,
        end: `${EXPIRY_PREFIX}${String(now).padStart(16, "0")}:~`,
        limit: CLEANUP_BATCH,
    });
    if (expired.size) await storage.delete([...expired.keys(), ...expired.values()]);
}

/** Global browser login metadata in the directory's existing SQLite storage.
 * No signing seed is accepted or persisted. Expiry cleanup is opportunistic;
 * expired sessions and receipts are rejected even before their rows are pruned.
 */
export class BrowserSessions {
    constructor(
        private readonly storage: DurableObjectStorage,
        private readonly clock: () => number = Date.now,
    ) {}

    async create(auth: AuthenticatedOperation): Promise<{ session: BrowserSession; token: string }> {
        return this.storage.transaction(async (storage) => {
            const now = this.clock();
            // authenticate() owns signature verification. Recheck its validity
            // window at the transaction boundary, including on storage retries.
            if (
                ![auth.publicKey, auth.nonce, auth.digest].every(validDigest) ||
                !Number.isSafeInteger(auth.expiresAt) ||
                auth.expiresAt <= now ||
                auth.expiresAt > now + 330_000
            ) throw new HttpError(401, "This login request has expired. Unlock your identity again.");
            await pruneExpired(storage, now);
            const receiptKey = `browser-login:${auth.publicKey}:${auth.nonce}`;
            const prior = await storage.get<LoginReceipt>(receiptKey);
            if (prior && prior.expiresAt > now) {
                if (prior.digest !== auth.digest)
                    throw new HttpError(409, "This login operation was already used for another request.");
                const record = await storage.get<SessionRecord>(sessionKey(prior.sessionId));
                if (!prior.token || !record || record.expiresAt <= now)
                    throw new HttpError(401, "This session was signed out. Unlock your identity again.");
                return { session: publicSession(record), token: prior.token };
            }
            if (prior) await storage.delete([receiptKey, expiryKey(prior.expiresAt, receiptKey)]);
            const token = randomToken();
            const id = tokenDigest(token);
            const record: SessionRecord = {
                id, publicKey: auth.publicKey, expiresAt: now + BROWSER_SESSION_TTL, receiptKey,
            };
            const receipt: LoginReceipt = {
                digest: auth.digest, sessionId: id, expiresAt: auth.expiresAt, token,
            };
            await storage.put({
                [sessionKey(id)]: record,
                [receiptKey]: receipt,
                [expiryKey(record.expiresAt, sessionKey(id))]: sessionKey(id),
                [expiryKey(receipt.expiresAt, receiptKey)]: receiptKey,
            });
            return { session: publicSession(record), token };
        });
    }

    async read(id: string): Promise<BrowserSession | null> {
        if (!validDigest(id)) return null;
        return this.storage.transaction(async (storage) => {
            const now = this.clock();
            await pruneExpired(storage, now);
            const record = await storage.get<SessionRecord>(sessionKey(id));
            if (!record) return null;
            if (record.expiresAt <= now) {
                await storage.delete([sessionKey(id), expiryKey(record.expiresAt, sessionKey(id))]);
                return null;
            }
            return publicSession(record);
        });
    }

    async remove(id: string): Promise<void> {
        if (!validDigest(id)) return;
        await this.storage.transaction(async (storage) => {
            await pruneExpired(storage, this.clock());
            const record = await storage.get<SessionRecord>(sessionKey(id));
            if (!record) return;
            await storage.delete([sessionKey(id), expiryKey(record.expiresAt, sessionKey(id))]);
            const receipt = await storage.get<LoginReceipt>(record.receiptKey);
            if (receipt?.sessionId === id && receipt.token) {
                // Retain the nonce/digest tombstone but erase the bearer token.
                const { token: _token, ...tombstone } = receipt;
                await storage.put(record.receiptKey, tombstone);
            }
        });
    }
}

/** Empty token clears the same host-only cookie on logout. */
export function browserSessionCookie(token: string, secure = true): string {
    if (token && !validDigest(token)) throw new Error("Invalid browser session token");
    const name = secure ? "__Host-mkit_session" : "mkit_session_local";
    const maxAge = token ? BROWSER_SESSION_TTL / 1000 : 0;
    return `${name}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
}

export function requestBrowserSession(request: Request): string | null {
    const protocol = new URL(request.url).protocol;
    const name = protocol === "https:" ? "__Host-mkit_session" : protocol === "http:" ? "mkit_session_local" : null;
    const header = request.headers.get("Cookie");
    if (!name || !header || header.length > 8192) return null;
    const prefix = `${name}=`;
    const matches = header.split(";").map(part => part.trim()).filter(part => part.startsWith(prefix));
    // Duplicate cookies are ambiguous, so do not choose a bearer by position.
    if (matches.length !== 1) return null;
    const token = matches[0].slice(prefix.length);
    return validDigest(token) ? tokenDigest(token) : null;
}
