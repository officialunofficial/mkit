export class HttpError extends Error {
    constructor(
        public status: number,
        message: string,
        public retryAfter?: number,
    ) {
        super(message);
    }
}

export async function readBytes(
    request: Request | Response,
    maxBytes: number,
): Promise<Uint8Array> {
    const reader = request.body?.getReader();
    if (!reader) return new Uint8Array();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
        for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            size += value.byteLength;
            if (size > maxBytes) {
                await reader.cancel();
                throw new HttpError(413, "The request is too large.");
            }
            chunks.push(value);
        }
    } finally {
        reader.releaseLock();
    }
    const result = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return result;
}

export function json(value: unknown, status = 200, headers: HeadersInit = {}): Response {
    return Response.json(value, {
        status,
        headers: {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            ...headers,
        },
    });
}

export function errorResponse(error: unknown): Response {
    if (error instanceof HttpError)
        return json(
            { error: error.message },
            error.status,
            error.retryAfter ? { "Retry-After": String(error.retryAfter) } : {},
        );
    console.error(
        JSON.stringify({
            event: "workspace_error",
            type: error instanceof Error ? error.name : "unknown",
        }),
    );
    return json({ error: "The workspace could not complete that action. Try again." }, 500);
}

export function record(value: unknown): Record<string, unknown> {
    if (!value || typeof value !== "object" || Array.isArray(value))
        throw new HttpError(400, "Expected an object.");
    return value as Record<string, unknown>;
}

export function text(value: unknown, maxLength: number, label: string): string {
    if (
        typeof value !== "string" ||
        !value.trim() ||
        value.length > maxLength ||
        value.includes("\0")
    )
        throw new HttpError(400, `Invalid ${label}.`);
    return value;
}
