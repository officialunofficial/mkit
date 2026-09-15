import { authenticate } from "./auth";
import { browserSessionCookie, requestBrowserSession } from "./browser-session";
import type { RemixRequest } from "./contracts";
import { errorResponse, HttpError, json, record, text } from "./http";
import { assertHash } from "./objects";
export { Workspace } from "./workspace";
export { WorkspaceDirectory } from "./directory";
export { Sandbox } from "@cloudflare/sandbox";

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        try {
            const url = new URL(request.url),
                path = url.pathname.replace(/\/$/, "");
            if (path === "/api/workspaces/session") {
                if (url.origin !== env.AUTH_AUDIENCE || url.search)
                    throw new HttpError(401, "Invalid session destination.");
                const directory = env.DIRECTORY.getByName("global");
                const digest = requestBrowserSession(request);
                if (request.method === "GET")
                    return json(digest ? await directory.readBrowserSession(digest) : null);
                if (request.method === "DELETE") {
                    if (request.headers.get("Origin") !== env.AUTH_AUDIENCE)
                        throw new HttpError(403, "Invalid origin.");
                    if (digest) await directory.removeBrowserSession(digest);
                    return json(null, 200, { "Set-Cookie": browserSessionCookie("", url.protocol === "https:") });
                }
                if (request.method === "POST") {
                    const auth = await authenticate(request, env.AUTH_AUDIENCE, "identity");
                    if (Object.keys(record(auth.body)).length)
                        throw new HttpError(400, "Login requires an empty request body.");
                    const login = await directory.createBrowserSession(auth);
                    if ("error" in login) throw new HttpError(login.error.status, login.error.message);
                    return json(login.session, 200, { "Set-Cookie": browserSessionCookie(login.token, url.protocol === "https:") });
                }
                throw new HttpError(405, "Unsupported session method.");
            }
            if (path === "/api/workspaces" && request.method === "GET")
                return json({ workspaces: await env.DIRECTORY.getByName("global").list() });
            if (path === "/api/workspaces/prepare" && request.method === "POST") {
                const auth = await authenticate(request, env.AUTH_AUDIENCE, "workspaces"),
                    body = record(auth.body);
                if (body.kind !== "demo" && body.kind !== "workspace")
                    throw new HttpError(400, "Choose a project to remix.");
                if (body.commitHash !== undefined) assertHash(text(body.commitHash, 64, "commit"));
                if (body.kind === "workspace" && !/^[0-9a-f]{32}$/.test(String(body.workspaceId)))
                    throw new HttpError(400, "Invalid workspace.");
                if (body.ref !== undefined) text(body.ref, 128, "ref");
                return await env.DIRECTORY.getByName("global").fetch(
                    new Request("https://directory/prepare", {
                        method: "POST",
                        body: JSON.stringify({ auth, source: body as RemixRequest }),
                    }),
                );
            }
            const match =
                /^\/api\/workspaces\/([0-9a-f]{32})(?:\/(file|session|activate|tasks|cancel|revoke|restore|versions|terminal|conversation))?$/.exec(
                    path,
                );
            if (!match) throw new HttpError(404, "Workspace route not found.");
            return await env.WORKSPACES.getByName(match[1]!).fetch(request);
        } catch (error) {
            return errorResponse(error);
        }
    },
} satisfies ExportedHandler<Env>;
