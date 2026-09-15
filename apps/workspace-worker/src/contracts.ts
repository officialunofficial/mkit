/** Public HTTP contract shared by the workspace service and mkit.sh. */
export const WORKSPACE_API = "/api/workspaces";

export type WorkspaceSource = {
    kind: "demo" | "workspace";
    repository: string;
    commitHash: string;
    ref?: string;
    workspaceId?: string;
};

export type RemixRequest =
    | { kind: "demo"; ref?: string; commitHash?: string }
    | { kind: "workspace"; workspaceId: string; commitHash?: string };

export type AgentGrant = {
    version: 1;
    workspaceId: string;
    ownerPublicKey: string;
    agentPublicKey: string;
    source: WorkspaceSource;
    permissions: ["files", "commands", "versions"];
    createdAt: number;
    expiresAt: number;
};

export type SignedAgentGrant = { grant: AgentGrant; signature: string };

export type PreparedWorkspace = {
    id: string;
    grant: AgentGrant;
};

export type WorkspaceSummary = {
    id: string;
    title: string;
    ownerPublicKey: string;
    agentPublicKey: string;
    source: WorkspaceSource;
    head: string | null;
    createdAt: number;
    updatedAt: number;
    public: true;
};

export type WorkspaceFile = { path: string; hash: string; size: number; mode: "blob" | "exec" };

export type WorkspaceChange = {
    path: string;
    status: "added" | "modified" | "deleted";
    beforeHash: string | null;
    afterHash: string | null;
};

export type WorkspaceVersion = {
    hash: string;
    treeHash: string;
    parent: string | null;
    message: string;
    signer: string;
    createdAt: number;
};

export type WorkspaceMessage = {
    id: string;
    role: "user" | "assistant" | "system";
    text: string;
    createdAt: number;
};

export type WorkspaceTask = {
    id: string;
    prompt: string;
    status: "queued" | "running" | "completed" | "cancelled" | "failed";
    createdAt: number;
    finishedAt?: number;
    error?: string;
    versionHash?: string;
};

export type WorkspaceView = {
    workspace: WorkspaceSummary;
    files: WorkspaceFile[];
    /** Current working files versus saved HEAD, including when viewing an older version. */
    changes: WorkspaceChange[];
    versions: WorkspaceVersion[];
    /** Conversation and task details are returned only to the authenticated owner. */
    messages: WorkspaceMessage[];
    task: WorkspaceTask | null;
    isOwner: boolean;
    grant: SignedAgentGrant | null;
    agentEnabled: boolean;
};

export type WorkspaceFileContent = {
    path: string;
    content: string;
    /** Optimistic edit precondition; returned for draft and version file reads. */
    hash: string;
    editable: boolean;
};

/** Domain-separated, deterministic delegation bytes signed by the browser owner. */
export function grantMessage(grant: AgentGrant): string {
    return [
        "mkit-workspace-grant:v1",
        grant.workspaceId,
        grant.ownerPublicKey,
        grant.agentPublicKey,
        grant.source.kind,
        grant.source.repository,
        grant.source.commitHash,
        grant.source.ref ?? "",
        grant.source.workspaceId ?? "",
        grant.permissions.join(","),
        String(grant.createdAt),
        String(grant.expiresAt),
    ].join("\n");
}
