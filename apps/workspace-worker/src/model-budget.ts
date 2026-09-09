export type ModelBucket = { at: number; requests: number; tokens: number };
export const MINUTE_TOKENS = 7500;
export const INPUT_TOKEN_RESERVE = 512;
export const MINUTE_REQUESTS = 25;

/** Continuous refill prevents a double burst across a wall-clock minute boundary. */
export function refill(bucket: ModelBucket | undefined, now: number): ModelBucket {
    const elapsed = Math.max(0, now - (bucket?.at ?? now)) / 60000;
    return {
        at: now,
        requests: Math.max(0, (bucket?.requests ?? 0) - elapsed * MINUTE_REQUESTS),
        tokens: Math.max(0, (bucket?.tokens ?? 0) - elapsed * MINUTE_TOKENS),
    };
}
export function waitForCapacity(bucket: ModelBucket, reserved: number): number {
    return Math.max(
        0,
        Math.ceil(
            Math.max(
                (bucket.requests + 1 - MINUTE_REQUESTS) / MINUTE_REQUESTS,
                (bucket.tokens + reserved - MINUTE_TOKENS) / MINUTE_TOKENS,
            ) * 60,
        ),
    );
}
