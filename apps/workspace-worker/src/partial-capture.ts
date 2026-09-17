import { HttpError } from "./http";
import { type FileManifest } from "./objects";
import type { SandboxWorkspace } from "./sandbox-files";

/** Capture selected files only. Extra, missing, renamed, or mode-changed paths fail closed. */
export async function captureSelected(
    sandbox: SandboxWorkspace,
    generation: string,
    selected: FileManifest,
): Promise<FileManifest> {
    const captured = await sandbox.capture(generation);
    const selectedPaths = Object.keys(selected).sort();
    const capturedPaths = Object.keys(captured).sort();
    if (selectedPaths.length !== capturedPaths.length)
        throw new HttpError(400, "Capture must include exactly the selected files.");
    const files: FileManifest = Object.create(null);
    for (const path of selectedPaths) {
        const expected = selected[path];
        const actual = captured[path];
        if (!expected || !actual)
            throw new HttpError(400, "Capture changed a selected path.");
        if (actual.mode !== expected.mode)
            throw new HttpError(400, "Capture cannot change file modes.");
        files[path] = actual;
    }
    return files;
}
