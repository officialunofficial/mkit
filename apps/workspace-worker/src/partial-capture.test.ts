import { describe, expect, it, vi } from "vitest";
import { captureSelected } from "./partial-capture";
import type { FileManifest } from "./objects";
import type { SandboxWorkspace } from "./sandbox-files";

const selected: FileManifest = {
    "shallow.txt": { hash: "aa".repeat(32), size: 4, mode: "blob" },
};

describe("partial capture", () => {
    it("accepts the exact selected path and mode set", async () => {
        const sandbox = {
            captureExact: vi.fn(async () => ({ ...selected })),
        } as unknown as SandboxWorkspace;
        await expect(captureSelected(sandbox, "gen", selected)).resolves.toEqual(selected);
    });

    it("rejects new, missing, and mode-changed paths atomically", async () => {
        const sandbox = {
            captureExact: vi.fn(async () => ({
                "shallow.txt": selected["shallow.txt"],
                "extra.txt": { hash: "bb".repeat(32), size: 1, mode: "blob" as const },
            })),
        } as unknown as SandboxWorkspace;
        await expect(captureSelected(sandbox, "gen", selected)).rejects.toThrow(/exactly the selected/);
        sandbox.captureExact = vi.fn(async () => ({}));
        await expect(captureSelected(sandbox, "gen", selected)).rejects.toThrow(/exactly the selected/);
        sandbox.captureExact = vi.fn(async () => ({
            "shallow.txt": { ...selected["shallow.txt"]!, mode: "exec" as const },
        }));
        await expect(captureSelected(sandbox, "gen", selected)).rejects.toThrow(/modes/);
    });
});
