import {
    getSandbox,
    parseSSEStream,
    type ExecEvent,
    type Sandbox,
    type ExecutionSession,
} from "@cloudflare/sandbox";
import {
    getBlob,
    putBlob,
    validateManifest,
    validatePath,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    type FileManifest,
    type ObjectStorage,
} from "./objects";

const PROJECT = "/workspace/project";
const MARKER = "/tmp/mkit-generation";
const OUTPUT_LIMIT = 64 * 1024;
const CAPTURE_LIMIT = 8 * 1024 * 1024;
const CHUNK_BYTES = 24 * 1024;

/** Every dynamic argument is one literal POSIX-shell word. */
export function shellQuote(value: string): string {
    return `'${value.replaceAll("'", "'\\''")}'`;
}

/** The helper never follows a symlink, even if a command swaps a path while it runs.
 * Directory descriptors anchor every operation. Before/after metadata checks reject
 * concurrent edits rather than publishing an inconsistent snapshot. */
export const SANDBOX_FILES_PROGRAM = String.raw`
import os, sys, json, stat, base64
P=json.loads(sys.argv[1])
ROOT=P.get('root','/workspace/project')
MARKER=P.get('marker','/tmp/mkit-generation')
NOFOLLOW=os.O_NOFOLLOW
DIRECTORY=os.O_DIRECTORY
IGNORE={'node_modules','.git','.mkit','.venv','__pycache__','target','.DS_Store'}
MAX_FILE=262144
MAX_TOTAL=4194304
MAX_FILES=256

def identity(s): return (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def components(path):
    parts=path.split('/')
    if not path or len(path.encode('utf-8'))>1024 or len(parts)>32 or any(not x or x in ('.','..') or x.lower() in ('.git','.mkit') for x in parts) or any(ord(c)<32 or 127<=ord(c)<=159 or c=='\\' for c in path):
        raise ValueError('Invalid workspace path')
    return parts

def open_absolute(path,create=False):
    if not path.startswith('/'): raise ValueError('Absolute directory required')
    fd=os.open('/',os.O_RDONLY|DIRECTORY|NOFOLLOW)
    try:
        for part in path.split('/')[1:]:
            if not part or part in ('.','..'): raise ValueError('Invalid directory')
            if create:
                try: os.mkdir(part,0o755,dir_fd=fd)
                except FileExistsError: pass
            child=os.open(part,os.O_RDONLY|DIRECTORY|NOFOLLOW,dir_fd=fd)
            os.close(fd); fd=child
        return fd
    except:
        os.close(fd); raise

def parent(root,path,create=False):
    parts=components(path); fd=os.dup(root)
    try:
        for part in parts[:-1]:
            if create:
                try: os.mkdir(part,0o755,dir_fd=fd)
                except FileExistsError: pass
            child=os.open(part,os.O_RDONLY|DIRECTORY|NOFOLLOW,dir_fd=fd)
            os.close(fd); fd=child
        return fd,parts[-1]
    except:
        os.close(fd); raise

def marker_read():
    directory,name=MARKER.rsplit('/',1); parentfd=open_absolute(directory)
    try:
        try: fd=os.open(name,os.O_RDONLY|NOFOLLOW|os.O_NONBLOCK,dir_fd=parentfd)
        except FileNotFoundError: return None
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>1024: raise ValueError('Invalid generation marker')
            data=os.read(fd,1025)
            if identity(before)!=identity(os.fstat(fd)): raise ValueError('Generation changed')
            return data.decode('utf-8')
        finally: os.close(fd)
    finally: os.close(parentfd)

def marker_write(value):
    directory,name=MARKER.rsplit('/',1); parentfd=open_absolute(directory)
    try:
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=parentfd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_nlink!=1: raise ValueError('Invalid generation marker')
            os.ftruncate(fd,0)
            os.write(fd,value.encode('utf-8')); os.fsync(fd)
        finally: os.close(fd)
    finally: os.close(parentfd)

def regular_read(parentfd,name):
    before=os.stat(name,dir_fd=parentfd,follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1: raise ValueError('Only regular, unlinked files are supported: '+name)
    if before.st_size>MAX_FILE: raise ValueError('File exceeds 256 KiB: '+name)
    fd=os.open(name,os.O_RDONLY|NOFOLLOW|os.O_NONBLOCK,dir_fd=parentfd)
    try:
        if identity(before)!=identity(os.fstat(fd)): raise ValueError('File changed while reading: '+name)
        chunks=[]; size=0
        while True:
            chunk=os.read(fd,min(65536,MAX_FILE+1-size))
            if not chunk: break
            chunks.append(chunk); size+=len(chunk)
            if size>MAX_FILE: raise ValueError('File exceeds 256 KiB: '+name)
        if identity(before)!=identity(os.fstat(fd)) or identity(before)!=identity(os.stat(name,dir_fd=parentfd,follow_symlinks=False)):
            raise ValueError('File changed while reading: '+name)
        return b''.join(chunks),before
    finally: os.close(fd)

def clear(fd):
    for name in os.listdir(fd):
        info=os.stat(name,dir_fd=fd,follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child=os.open(name,os.O_RDONLY|DIRECTORY|NOFOLLOW,dir_fd=fd)
            try: clear(child)
            finally: os.close(child)
            os.rmdir(name,dir_fd=fd)
        else: os.unlink(name,dir_fd=fd)

action=P['action']
if action=='generation':
    print(json.dumps(marker_read()))
elif action=='reset':
    marker_write('')
    fd=open_absolute(ROOT,True)
    try: clear(fd)
    finally: os.close(fd)
    print('{}')
elif action=='mark':
    marker_write(P['generation']); print('{}')
else:
    root=open_absolute(ROOT)
    root_identity=identity(os.fstat(root))
    try:
        if action=='read':
            fd,name=parent(root,P['path'])
            try: data,info=regular_read(fd,name)
            finally: os.close(fd)
            print(json.dumps({'content':base64.b64encode(data).decode('ascii'),'mode':'exec' if info.st_mode&0o111 else 'blob'}))
        elif action=='write':
            data=base64.b64decode(P['content'],validate=True); offset=P.get('offset',0)
            if offset<0 or offset+len(data)>MAX_FILE: raise ValueError('File exceeds 256 KiB')
            directory,name=parent(root,P['path'],True)
            try:
                flags=os.O_WRONLY|os.O_CREAT|NOFOLLOW|os.O_NONBLOCK
                fd=os.open(name,flags,0o644,dir_fd=directory)
                try:
                    before=os.fstat(fd)
                    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1: raise ValueError('Only regular, unlinked files are supported')
                    if offset==0: os.ftruncate(fd,0)
                    elif before.st_size!=offset: raise ValueError('File changed while writing')
                    os.lseek(fd,offset,os.SEEK_SET)
                    position=0
                    while position<len(data): position+=os.write(fd,data[position:])
                    if P.get('mode') is not None: os.fchmod(fd,0o755 if P['mode']=='exec' else 0o644)
                    after=os.fstat(fd)
                    if after.st_size!=offset+len(data) or identity(after)!=identity(os.stat(name,dir_fd=directory,follow_symlinks=False)): raise ValueError('File changed while writing')
                finally: os.close(fd)
            finally: os.close(directory)
            print('{}')
        elif action=='capture':
            if marker_read()!=P['generation']: raise ValueError('Workspace generation changed; refusing stale capture')
            output={}; fingerprints={}; total=0; visited=0
            def walk(fd,prefix='',depth=0):
                global total,visited
                if depth>32: raise ValueError('Workspace path exceeds depth limit')
                before=os.fstat(fd)
                for name in sorted(os.listdir(fd)):
                    visited+=1
                    if visited>8192: raise ValueError('Workspace exceeds directory entry limit')
                    if name in IGNORE: continue
                    path=prefix+name; components(path)
                    info=os.stat(name,dir_fd=fd,follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child=os.open(name,os.O_RDONLY|DIRECTORY|NOFOLLOW,dir_fd=fd)
                        try:
                            if identity(info)!=identity(os.fstat(child)): raise ValueError('Directory changed while reading')
                            walk(child,path+'/',depth+1)
                            if identity(info)!=identity(os.stat(name,dir_fd=fd,follow_symlinks=False)): raise ValueError('Directory changed while reading')
                        finally: os.close(child)
                    else:
                        data,info=regular_read(fd,name); total+=len(data)
                        if total>MAX_TOTAL: raise ValueError('Workspace exceeds 4 MiB')
                        if len(output)>=MAX_FILES: raise ValueError('Workspace exceeds 256 files')
                        fingerprints[path]=identity(info)
                        output[path]={'content':base64.b64encode(data).decode('ascii'),'mode':'exec' if info.st_mode&0o111 else 'blob'}
                if identity(before)!=identity(os.fstat(fd)): raise ValueError('Directory changed while reading')
            walk(root)
            for path,before in fingerprints.items():
                directory,name=parent(root,path)
                try:
                    if identity(os.stat(name,dir_fd=directory,follow_symlinks=False))!=before: raise ValueError('File changed during capture')
                finally: os.close(directory)
            if marker_read()!=P['generation']: raise ValueError('Workspace generation changed; refusing stale capture')
            current=open_absolute(ROOT)
            try:
                if identity(os.fstat(current))!=root_identity: raise ValueError('Workspace root changed while reading')
            finally: os.close(current)
            print(json.dumps(output,separators=(',',':')))
        else: raise ValueError('Unknown file operation')
    finally: os.close(root)
`;

type CapturedFile = { content: string; mode: "blob" | "exec" };
export class SandboxWorkspace {
    constructor(
        private readonly namespace: DurableObjectNamespace<Sandbox>,
        readonly id: string,
        private readonly objects: ObjectStorage,
    ) {}

    // A Durable Object RPC stub can remain broken after its instance retires.
    // Keep the stable namespace/id, and obtain a fresh connection for each call.
    // Never retry an uncertain user command as part of connection recovery.
    private get sandbox(): Sandbox {
        return getSandbox(this.namespace, `workspace-${this.id}`, { sleepAfter: "2m" });
    }

    private async helper<T>(payload: Record<string, unknown>): Promise<T> {
        const result = await this.sandbox.exec(
            `/usr/bin/python3 -I -c ${shellQuote(SANDBOX_FILES_PROGRAM)} ${shellQuote(JSON.stringify(payload))}`,
            { cwd: "/", timeout: 60_000, origin: "internal" },
        );
        if (result.exitCode !== 0)
            throw new Error(`Workspace file operation failed: ${result.stderr.slice(-2048)}`);
        if (new TextEncoder().encode(result.stdout).length > CAPTURE_LIMIT)
            throw new Error("Workspace capture exceeds output limit");
        return JSON.parse(result.stdout);
    }

    async ensure(files: FileManifest, generation: string): Promise<void> {
        validateManifest(files);
        if (!generation || generation.length > 1024)
            throw new Error("Invalid workspace generation");
        if ((await this.helper<string | null>({ action: "generation" })) === generation) return;
        // Load and verify every object before touching the working directory.
        const contents: [string, Uint8Array, "blob" | "exec"][] = [];
        for (const [path, file] of Object.entries(files)) {
            const data = await getBlob(this.objects, file.hash);
            if (data.length !== file.size) throw new Error("File size mismatch");
            contents.push([path, data, file.mode]);
        }
        await this.helper({ action: "reset" });
        for (const [path, data, mode] of contents) await this.writeBytes(path, data, mode);
        await this.helper({ action: "mark", generation });
    }

    async capture(generation: string): Promise<FileManifest> {
        const captured = await this.helper<Record<string, CapturedFile>>({
            action: "capture",
            generation,
        });
        if (!captured || typeof captured !== "object" || Array.isArray(captured))
            throw new Error("Invalid workspace capture");
        const entries = Object.entries(captured);
        if (entries.length > MAX_FILES) throw new Error("Workspace exceeds 256 files");
        const manifest: FileManifest = Object.create(null);
        let total = 0;
        for (const [path, file] of entries) {
            validatePath(path);
            if (
                !file ||
                typeof file.content !== "string" ||
                file.content.length > Math.ceil(MAX_FILE_BYTES / 3) * 4 ||
                !["blob", "exec"].includes(file.mode)
            )
                throw new Error("Invalid captured file");
            const bytes = decodeBase64(file.content);
            if (bytes.length > MAX_FILE_BYTES) throw new Error("File exceeds 256 KiB");
            total += bytes.length;
            if (total > MAX_TOTAL_BYTES) throw new Error("Workspace exceeds 4 MiB");
            manifest[path] = {
                hash: await putBlob(this.objects, bytes),
                size: bytes.length,
                mode: file.mode,
            };
        }
        validateManifest(manifest);
        if ((await this.helper<string | null>({ action: "generation" })) !== generation)
            throw new Error("Workspace generation changed; refusing stale capture");
        return manifest;
    }

    async read(path: string): Promise<string> {
        validatePath(path);
        const file = await this.helper<CapturedFile>({ action: "read", path });
        return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
            decodeBase64(file.content),
        );
    }

    private async writeBytes(
        path: string,
        bytes: Uint8Array,
        mode?: "blob" | "exec",
    ): Promise<void> {
        validatePath(path);
        if (bytes.length > MAX_FILE_BYTES) throw new Error("File exceeds 256 KiB");
        for (let offset = 0; offset < bytes.length || offset === 0; offset += CHUNK_BYTES) {
            await this.helper({
                action: "write",
                path,
                offset,
                content: encodeBase64(bytes.subarray(offset, offset + CHUNK_BYTES)),
                ...(mode ? { mode } : {}),
            });
        }
    }
    async write(path: string, content: string): Promise<void> {
        await this.writeBytes(path, new TextEncoder().encode(content));
    }

    async exec(
        command: string,
        signal?: AbortSignal,
    ): Promise<{ stdout: string; stderr: string; exitCode: number }> {
        signal?.throwIfAborted();
        const session = await this.sandbox.createSession({
            id: `command-${crypto.randomUUID()}`,
            cwd: PROJECT,
            commandTimeoutMs: 60_000,
        });
        const controller = new AbortController();
        let deletion: Promise<unknown> | undefined;
        const stop = () => (deletion ??= this.sandbox.deleteSession(session.id));
        const stopOnAbort = () => {
            void stop().catch(() => {});
        };
        controller.signal.addEventListener("abort", stopOnAbort, { once: true });
        const abort = () => controller.abort(signal?.reason ?? new Error("Command cancelled"));
        signal?.addEventListener("abort", abort, { once: true });
        if (signal?.aborted) abort();
        const timer = setTimeout(
            () => controller.abort(new Error("Command exceeded 60 seconds")),
            60_000,
        );
        let stdout = "",
            stderr = "",
            count = 0,
            limited = false;
        try {
            controller.signal.throwIfAborted();
            const aborted = new Promise<never>((_, reject) =>
                controller.signal.addEventListener(
                    "abort",
                    () => reject(controller.signal.reason),
                    { once: true },
                ),
            );
            // Only plain data crosses Durable Object RPC. Signals and callbacks are
            // caller-local: passing them to session.exec() fails serialization before
            // the container ever receives the command.
            const pendingStream = session.execStream(command, { cwd: PROJECT, timeout: 60_000 });
            void pendingStream
                .then((stream) => {
                    if (controller.signal.aborted && !stream.locked)
                        return stream.cancel(controller.signal.reason);
                })
                .catch(() => {});
            const stream = await Promise.race([aborted, pendingStream]);
            const consume = async (): Promise<number> => {
                for await (const event of parseSSEStream<ExecEvent>(stream, controller.signal)) {
                    controller.signal.throwIfAborted();
                    if (event.type === "stdout" || event.type === "stderr") {
                        const bytes = new TextEncoder().encode(event.data ?? "");
                        const text = new TextDecoder().decode(
                            bytes.subarray(0, Math.max(0, OUTPUT_LIMIT - 128 - count)),
                        );
                        if (event.type === "stdout") stdout += text;
                        else stderr += text;
                        count += bytes.length;
                        if (count > OUTPUT_LIMIT - 128) {
                            limited = true;
                            controller.abort(new Error("Command output exceeded 64 KiB"));
                            controller.signal.throwIfAborted();
                        }
                    } else if (event.type === "complete") {
                        return event.exitCode ?? event.result?.exitCode ?? 0;
                    } else if (event.type === "error") {
                        throw new Error(event.error ?? event.data ?? "Command execution failed");
                    }
                }
                throw new Error("Command stream ended without a completion event");
            };
            const exitCode = await Promise.race([aborted, consume()]);
            return { stdout, stderr, exitCode };
        } catch (error) {
            if (limited)
                return {
                    stdout,
                    stderr: `${stderr}\nCommand stopped: output exceeded 64 KiB.`,
                    exitCode: 137,
                };
            throw error;
        } finally {
            clearTimeout(timer);
            signal?.removeEventListener("abort", abort);
            // SDK cancellation/timeout does not terminate the underlying process.
            controller.signal.removeEventListener("abort", stopOnAbort);
            await stop();
        }
    }

    private async terminalSession(): Promise<ExecutionSession> {
        try {
            return await this.sandbox.createSession({
                id: "project",
                cwd: PROJECT,
                commandTimeoutMs: 60_000,
            });
        } catch (error) {
            if (error instanceof Error && error.name === "SessionAlreadyExistsError")
                return this.sandbox.getSession("project");
            throw error;
        }
    }
    async terminal(request: Request): Promise<Response> {
        return (await this.terminalSession()).terminal(request);
    }
    async stopTerminal(): Promise<void> {
        try {
            await this.sandbox.deleteSession("project");
        } catch (error) {
            // 0.12.9 reports a missing session as generic SandboxError/HTTP 500.
            // RPC may erase the class name; match only this exact session's message.
            const missing =
                typeof error === "object" &&
                error !== null &&
                "message" in error &&
                error.message === "Session 'project' not found";
            if (!missing && (!(error instanceof Error) || error.name !== "SessionNotFoundError"))
                throw error;
        }
    }
    async destroy(): Promise<void> {
        await this.sandbox.destroy();
    }
}

function encodeBase64(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
}
function decodeBase64(value: string): Uint8Array {
    return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}
