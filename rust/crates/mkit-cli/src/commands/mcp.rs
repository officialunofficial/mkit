//! `mkit mcp` — a local Model Context Protocol server over stdio.
//!
//! Exposes a conservative subset of mkit as MCP tools so LLM agents can
//! read, search, and manipulate local mkit repositories — the mkit
//! analog of the reference `mcp-server-git`. Design choices follow that
//! template where it is right and diverge where mkit is stronger:
//!
//! * **Local + stdio.** Newline-delimited JSON-RPC 2.0 on stdin/stdout,
//!   processed sequentially. No async runtime: the loop is plain
//!   blocking I/O, keeping the default build tokio-free.
//! * **Subprocess execution.** Each tool call re-invokes this same
//!   binary (`std::env::current_exe()`) with a structured argv — never
//!   a shell — capturing stdout/stderr and the sysexits code. The MCP
//!   loop owns this process's stdout for the protocol, so tools must
//!   not print here; subprocess isolation guarantees that, and the
//!   server version always equals the CLI version.
//! * **Conservative surface.** Like the git template: no network ops
//!   (push/pull/fetch/clone), no history surgery (merge/rebase/
//!   cherry-pick/revert), no worktree destruction (reset --hard /
//!   clean / rm). The server never passes `-f`/`--force`, so mkit's
//!   own data-loss guards remain the backstop. Unlike the template:
//!   first-class signing + attestation tools — the reason mkit exists.
//! * **Scoping.** `--repository <path>` confines every `repo_path`
//!   argument (symlink-resolved) to that root. Without the flag any
//!   path the process can reach is allowed (client-trust mode), same
//!   as the git template.
//! * **Injection defense.** Path/ref-like arguments are rejected if
//!   they begin with `-` so a value can never be parsed as a flag by
//!   the child CLI (which has no `--` separator on `add`).

#[cfg(not(feature = "mcp-v2"))]
use std::io::BufRead;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use serde_json::{Value, json};

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
struct McpOpts {
    /// Confine all tool calls to this repository path (and its
    /// subdirectories). Strongly recommended for agent use.
    #[arg(long, short = 'r', value_name = "PATH")]
    repository: Option<PathBuf>,
    /// Serve over streamable HTTP at this address (e.g. 127.0.0.1:8899)
    /// instead of stdio. Requires `--features mcp-v2`: rmcp's stdio
    /// transport is what the default build speaks, and HTTP needs a real
    /// listener besides. Binds to localhost-family addresses only by
    /// default (rmcp's own DNS-rebinding guard — see `mcp_v2.rs`).
    #[cfg(feature = "mcp-v2")]
    #[arg(long, value_name = "ADDR")]
    http: Option<String>,
}

/// Entry point for `mkit mcp`.
#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<McpOpts>("mkit mcp", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let allowed = match &opts.repository {
        Some(p) => match p.canonicalize() {
            Ok(c) => Some(c),
            Err(e) => {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "error: --repository {}: {e}", p.display());
                return exit::NOINPUT;
            }
        },
        None => None,
    };
    dispatch(allowed, &opts)
}

/// `mcp-v2` swaps the whole `mkit mcp` implementation over to the rmcp-based
/// server (MCP 2026-07-28) at compile time — the same "feature changes the
/// command's behavior, off by default" shape `enc-transport`/`http-transport`
/// use elsewhere in this crate — rather than adding a runtime flag, so there
/// is exactly one code path per build to test and reason about. Either way
/// `dispatch` is the only thing that differs: the tool catalog, argv-building,
/// path confinement, and injection defenses below are shared unconditionally.
#[cfg(feature = "mcp-v2")]
fn dispatch(allowed: Option<PathBuf>, opts: &McpOpts) -> u8 {
    super::mcp_v2::serve(allowed.as_deref(), opts.http.as_deref())
}

#[cfg(not(feature = "mcp-v2"))]
fn dispatch(allowed: Option<PathBuf>, _opts: &McpOpts) -> u8 {
    serve(allowed.as_deref())
}

/// Blocking JSON-RPC loop: one message per line, responses flushed
/// immediately. Returns when stdin reaches EOF (client disconnect).
#[cfg(not(feature = "mcp-v2"))]
fn serve(allowed: Option<&Path>) -> u8 {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    // MCP lifecycle: `initialize` must precede any tool traffic.
    let mut initialized = false;

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Result<Value, _> = serde_json::from_str(&line);
        let (messages, is_batch): (Vec<Value>, bool) = match parsed {
            // A few legacy clients batch; MCP 2025+ forbids it, but
            // handling an array costs nothing. Per JSON-RPC 2.0, a batch
            // request gets ONE batch (array) response — and a batch of
            // only notifications gets no response at all.
            Ok(Value::Array(batch)) => (batch, true),
            Ok(v) => (vec![v], false),
            Err(_) => {
                write_msg(
                    &mut stdout,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": { "code": -32700, "message": "parse error" }
                    }),
                );
                continue;
            }
        };
        let responses: Vec<Value> = messages
            .iter()
            .filter_map(|msg| handle_message(msg, allowed, &mut initialized))
            .collect();
        if is_batch {
            if !responses.is_empty() {
                write_msg(&mut stdout, &Value::Array(responses));
            }
        } else if let Some(response) = responses.into_iter().next() {
            write_msg(&mut stdout, &response);
        }
    }
    exit::OK
}

/// Protocol revisions this server interoperates with. The wire framing
/// and tools surface are common across these; `initialize` negotiates
/// the requested one when supported, else falls back to the latest.
#[cfg(not(feature = "mcp-v2"))]
const SUPPORTED_PROTOCOLS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
#[cfg(not(feature = "mcp-v2"))]
const LATEST_PROTOCOL: &str = "2025-06-18";

#[cfg(not(feature = "mcp-v2"))]
fn write_msg(stdout: &mut impl Write, msg: &Value) {
    // serde_json compact form contains no raw newlines, so one
    // message per line is structurally guaranteed.
    if let Ok(s) = serde_json::to_string(msg) {
        let _ = writeln!(stdout, "{s}");
        let _ = stdout.flush();
    }
}

/// Dispatch one JSON-RPC message. Returns `None` for notifications
/// (nothing is written back). `initialized` tracks the MCP lifecycle:
/// set on `initialize`, required before any tool traffic.
#[cfg(not(feature = "mcp-v2"))]
fn handle_message(msg: &Value, allowed: Option<&Path>, initialized: &mut bool) -> Option<Value> {
    let method = msg.get("method").and_then(Value::as_str)?;
    let id = msg.get("id");
    match (method, id) {
        // ---- notifications (no response) --------------------------
        (_, None | Some(Value::Null)) => None,
        // ---- requests ----------------------------------------------
        ("initialize", Some(id)) => {
            *initialized = true;
            // Negotiate the protocol: honor the client's requested
            // revision when we support it, else return our latest so
            // the client can decide — never claim an arbitrary version.
            let requested = msg
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str);
            let version = match requested {
                Some(v) if SUPPORTED_PROTOCOLS.contains(&v) => v,
                _ => LATEST_PROTOCOL,
            };
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": version,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "mkit-repo", "version": crate::cli::CLI_VERSION },
                    "instructions": INSTRUCTIONS,
                }
            }))
        }
        ("ping", Some(id)) => Some(json!({ "jsonrpc": "2.0", "id": id, "result": {} })),
        // Tool traffic is rejected until the client has initialized.
        ("tools/list" | "tools/call", Some(id)) if !*initialized => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32002, "message": "server not initialized: send `initialize` first" }
        })),
        ("tools/list", Some(id)) => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "tools": tool_descriptors() }
        })),
        ("tools/call", Some(id)) => {
            let name = msg
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let empty = json!({});
            let args = msg.pointer("/params/arguments").unwrap_or(&empty);
            match call_tool(name, args, allowed) {
                Ok(CallOutcome { text, is_error }) => Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [ { "type": "text", "text": text } ],
                        "isError": is_error,
                    }
                })),
                Err(protocol_err) => Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32602, "message": protocol_err }
                })),
            }
        }
        (_, Some(id)) => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("method not found: {method}") }
        })),
    }
}

pub(crate) const INSTRUCTIONS: &str = "Operate local mkit repositories (content-addressed VCS with \
Ed25519-signed commits and in-toto/DSSE attestation). Every tool takes a repo_path. \
Typical flow: mkit_init -> mkit_keygen (REQUIRED before the first commit) -> mkit_add -> \
mkit_commit -> mkit_log/mkit_show. Differentiators: mkit_verify (check a commit/tag \
signature), mkit_attest (attach a signed DSSE attestation), mkit_verify_attest (verify \
attestations against trust roots), mkit_cat_object (inspect content-addressed objects). \
This server runs no network operations (push/pull/fetch/clone), no history surgery \
(merge/rebase/cherry-pick), and never overrides mkit's data-loss guards; a 'refuses \
without -f' error means run that operation outside the MCP, deliberately. Path rules: an \
attest predicate_file must resolve INSIDE the repo; a verify_attest trust_roots path must \
resolve OUTSIDE it. For docs/specs/source of mkit itself, use the separate mkit docs MCP \
(mcp.mkit.sh).";

// ---------------------------------------------------------------------------
// Tool table
// ---------------------------------------------------------------------------

// `pub(crate)` on this table and on `call_tool`/`CallOutcome` below: shared
// with `mcp_v2.rs` (the `--features mcp-v2` rmcp-based server) so the tool
// catalog, argv-building, path confinement, and injection defenses live in
// exactly one place regardless of which protocol layer is compiled in.
pub(crate) struct ToolSpec {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    /// (`read_only`, `destructive`, `idempotent`)
    pub(crate) hints: (bool, bool, bool),
    pub(crate) schema: fn() -> Value,
}

fn prop(desc: &str) -> Value {
    json!({ "type": "string", "description": desc })
}

fn schema(props: Vec<(&str, Value)>, required: &[&str]) -> Value {
    let mut map = serde_json::Map::new();
    for (k, v) in props {
        map.insert(k.to_string(), v);
    }
    json!({ "type": "object", "properties": Value::Object(map), "required": required })
}

fn repo_prop() -> (&'static str, Value) {
    (
        "repo_path",
        prop("Path to the mkit repository (the directory containing .mkit/)"),
    )
}

pub(crate) const TOOLS: &[ToolSpec] = &[
    ToolSpec {
        name: "mkit_status",
        description: "Show staged and working-tree changes (porcelain v2; empty means clean).",
        hints: (true, false, true),
        schema: || schema(vec![repo_prop()], &["repo_path"]),
    },
    ToolSpec {
        name: "mkit_diff_unstaged",
        description: "Show changes in the working directory that are not yet staged.",
        hints: (true, false, true),
        schema: || schema(vec![repo_prop()], &["repo_path"]),
    },
    ToolSpec {
        name: "mkit_diff_staged",
        description: "Show changes staged for the next commit.",
        hints: (true, false, true),
        schema: || schema(vec![repo_prop()], &["repo_path"]),
    },
    ToolSpec {
        name: "mkit_diff",
        description: "Show the diff against a target revision (branch, tag, or 64-hex BLAKE3 id).",
        hints: (true, false, true),
        schema: || {
            schema(
                vec![repo_prop(), ("target", prop("Revision to diff against"))],
                &["repo_path", "target"],
            )
        },
    },
    ToolSpec {
        name: "mkit_log",
        description: "Show commit history as JSONL (hash, author identity, timestamp, message).",
        hints: (true, false, true),
        schema: || {
            schema(
                vec![
                    repo_prop(),
                    (
                        "max_count",
                        json!({ "type": "integer", "description": "Maximum commits to show (default 10)" }),
                    ),
                    (
                        "rev",
                        prop("Optional revision (or A..B range) to start the walk from"),
                    ),
                ],
                &["repo_path"],
            )
        },
    },
    ToolSpec {
        name: "mkit_show",
        description: "Show an object: a commit with its diff, a tag, a tree listing, or blob contents.",
        hints: (true, false, true),
        schema: || {
            schema(
                vec![
                    repo_prop(),
                    ("revision", prop("Revision or object id to show")),
                ],
                &["repo_path", "revision"],
            )
        },
    },
    ToolSpec {
        name: "mkit_branch",
        description: "List branches as JSONL (current branch marked).",
        hints: (true, false, true),
        schema: || schema(vec![repo_prop()], &["repo_path"]),
    },
    ToolSpec {
        name: "mkit_cat_object",
        description: "Inspect a content-addressed object: its type, size, or pretty-printed content.",
        hints: (true, false, true),
        schema: || {
            schema(
                vec![
                    repo_prop(),
                    (
                        "object",
                        prop("Object id (64-hex BLAKE3, prefix accepted) or revision"),
                    ),
                    (
                        "mode",
                        json!({ "type": "string", "enum": ["type", "size", "pretty"], "description": "What to show (default: pretty)" }),
                    ),
                ],
                &["repo_path", "object"],
            )
        },
    },
    ToolSpec {
        name: "mkit_verify",
        description: "Verify the Ed25519 signature on a commit, remix, or signed tag. Pass \
                      `trusted` (or `trust_roots`) to also cross-check the signer against the \
                      trust-roots registry `mkit_trust_add`/`mkit trust list` manage, failing \
                      even on a cryptographically valid signature from an unlisted key.",
        hints: (true, false, true),
        schema: || {
            schema(
                vec![
                    repo_prop(),
                    ("revision", prop("Revision to verify (e.g. HEAD)")),
                    (
                        "trusted",
                        json!({ "type": "boolean", "description": "Cross-check the signer against the default trust-roots registry" }),
                    ),
                    (
                        "trust_roots",
                        prop(
                            "Path to a trust-roots TOML file OUTSIDE the repo (default: \
                             $XDG_CONFIG_HOME/mkit/trust-roots.toml). Implies trusted=true. An \
                             in-repo path is rejected.",
                        ),
                    ),
                ],
                &["repo_path", "revision"],
            )
        },
    },
    ToolSpec {
        name: "mkit_verify_attest",
        description: "Verify every DSSE attestation attached to a commit against a trust-roots \
                      registry. Defaults to the user-scoped trust-roots file; a trust_roots path \
                      inside the repository is always rejected here (hostile-clone defense — \
                      planted in-repo roots can never be selected through the MCP).",
        hints: (true, false, true),
        schema: || {
            schema(
                vec![
                    repo_prop(),
                    (
                        "commit",
                        prop("Commit hash to verify, or \"HEAD\" / omit for the current commit"),
                    ),
                    (
                        "trust_roots",
                        prop(
                            "Path to a trust-roots TOML file OUTSIDE the repo (default: \
                             $XDG_CONFIG_HOME/mkit/trust-roots.toml). An in-repo path is rejected.",
                        ),
                    ),
                    (
                        "algorithm",
                        json!({ "type": "string", "enum": ["ed25519", "secp256k1", "p256"], "description": "Only report signatures of this algorithm" }),
                    ),
                ],
                &["repo_path"],
            )
        },
    },
    ToolSpec {
        name: "mkit_add",
        description: "Stage files for the next commit. Pass explicit paths (\".\" stages everything \
                      non-ignored under the repo root).",
        hints: (false, false, true),
        schema: || {
            schema(
                vec![
                    repo_prop(),
                    (
                        "files",
                        json!({ "type": "array", "items": { "type": "string" }, "description": "Paths to stage" }),
                    ),
                ],
                &["repo_path", "files"],
            )
        },
    },
    ToolSpec {
        name: "mkit_unstage",
        description: "Unstage changes: with files, restores those index entries from HEAD; without, \
                      unstages everything (mixed reset). Never touches the working tree.",
        hints: (false, true, true),
        schema: || {
            schema(
                vec![
                    repo_prop(),
                    (
                        "files",
                        json!({ "type": "array", "items": { "type": "string" }, "description": "Paths to unstage (omit to unstage all)" }),
                    ),
                ],
                &["repo_path"],
            )
        },
    },
    ToolSpec {
        name: "mkit_commit",
        description: "Create an Ed25519-signed commit from the staging index. Requires a signing \
                      key (mkit_keygen) — commits are always signed.",
        hints: (false, false, false),
        schema: || {
            schema(
                vec![repo_prop(), ("message", prop("Commit message"))],
                &["repo_path", "message"],
            )
        },
    },
    ToolSpec {
        name: "mkit_create_branch",
        description: "Create a new branch at HEAD.",
        hints: (false, false, false),
        schema: || {
            schema(
                vec![repo_prop(), ("branch_name", prop("Name of the new branch"))],
                &["repo_path", "branch_name"],
            )
        },
    },
    ToolSpec {
        name: "mkit_checkout",
        description: "Switch HEAD to a branch and restore files. Overwrites clean tracked files \
                      and removes tracked paths absent from the target branch (dirty-worktree \
                      changes are guarded and refuse instead).",
        hints: (false, true, false),
        schema: || {
            schema(
                vec![repo_prop(), ("branch_name", prop("Branch to switch to"))],
                &["repo_path", "branch_name"],
            )
        },
    },
    ToolSpec {
        name: "mkit_init",
        description: "Create a new mkit repository (.mkit/) in repo_path. Run mkit_keygen next — \
                      commits require a signing key.",
        hints: (false, false, false),
        schema: || schema(vec![repo_prop()], &["repo_path"]),
    },
    ToolSpec {
        name: "mkit_keygen",
        description: "Generate a signing key. Default (ed25519) writes the commit-signing key at \
                      .mkit/keys/default.key; secp256k1/p256 write separate ATTESTATION signer keys \
                      (.mkit/keys/<alg>.key) for use with mkit_attest. Refuses to overwrite.",
        hints: (false, false, false),
        schema: || {
            schema(
                vec![
                    repo_prop(),
                    (
                        "algorithm",
                        json!({ "type": "string", "enum": ["ed25519", "secp256k1", "p256"], "description": "Key algorithm (default: ed25519 = the commit key)" }),
                    ),
                    (
                        "print_pubkey",
                        json!({ "type": "boolean", "description": "Also print the public key" }),
                    ),
                ],
                &["repo_path"],
            )
        },
    },
    ToolSpec {
        name: "mkit_attest",
        description: "Produce a signed DSSE attestation (in-toto v1 Statement) for a commit. \
                      Prints the att-id and stores the envelope under .mkit/attestations/. \
                      (Multi-signer envelopes and external-signer argv are intentionally NOT \
                      exposed here — they can direct subprocess execution; use the `mkit attest` \
                      CLI for that advanced flow.)",
        hints: (false, false, false),
        schema: || {
            schema(
                vec![
                    repo_prop(),
                    (
                        "commit",
                        prop("Commit hash to attest, or \"HEAD\" / omit for the current commit"),
                    ),
                    (
                        "algorithm",
                        json!({ "type": "string", "enum": ["ed25519", "secp256k1", "p256"], "description": "Signing algorithm (default: ed25519, always passed explicitly — user config cannot reroute the algorithm through the MCP). Non-ed25519 needs the matching mkit_keygen key." }),
                    ),
                    (
                        "signer",
                        json!({ "type": "string", "enum": ["repo-key", "keystore"], "description": "Primary signer (default: repo-key, always passed explicitly — user config cannot reroute to an external signer through the MCP)." }),
                    ),
                    (
                        "predicate_type",
                        prop("Predicate-type URI written into the Statement"),
                    ),
                    (
                        "predicate_file",
                        prop(
                            "Path to a JSON predicate file INSIDE the repo (an outside path is rejected)",
                        ),
                    ),
                ],
                &["repo_path"],
            )
        },
    },
];

#[cfg(not(feature = "mcp-v2"))]
fn tool_descriptors() -> Value {
    Value::Array(
        TOOLS
            .iter()
            .map(|t| {
                let (read_only, destructive, idempotent) = t.hints;
                json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": (t.schema)(),
                    "annotations": {
                        "readOnlyHint": read_only,
                        "destructiveHint": destructive,
                        "idempotentHint": idempotent,
                        "openWorldHint": false,
                    },
                })
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Tool execution
// ---------------------------------------------------------------------------

pub(crate) struct CallOutcome {
    pub(crate) text: String,
    pub(crate) is_error: bool,
}

impl CallOutcome {
    fn err(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
        }
    }
}

/// `Err(_)` is a protocol-level error (unknown tool); per-call
/// validation and execution failures come back as `Ok` with
/// `is_error: true` so the agent sees an explanatory message.
pub(crate) fn call_tool(name: &str, args: &Value, allowed: Option<&Path>) -> Result<CallOutcome, String> {
    if !TOOLS.iter().any(|t| t.name == name) {
        return Err(format!("unknown tool: {name}"));
    }

    let Some(repo_raw) = args.get("repo_path").and_then(Value::as_str) else {
        return Ok(CallOutcome::err("missing required argument: repo_path"));
    };
    let repo = match validate_repo_path(repo_raw, allowed) {
        Ok(p) => p,
        Err(e) => return Ok(CallOutcome::err(e)),
    };

    // Confine path-typed arguments relative to the repo. `--repository`
    // only constrains repo_path; predicate/trust-roots paths reach the
    // child CLI directly, so the MCP must hold the boundary itself.
    if let Err(e) = confine_path_args(name, args, &repo) {
        return Ok(CallOutcome::err(e));
    }

    let command = match build_argv(name, args) {
        Ok(a) => a,
        Err(e) => return Ok(CallOutcome::err(e)),
    };

    Ok(run_subprocess(&repo, &command))
}

/// Enforce containment of the file-path arguments the child CLI opens
/// itself (so `--repository` scoping can't be bypassed through them):
///
/// * `predicate_file` (attest) is *repo data* — it must resolve INSIDE
///   the repo, so a prompt-injected agent can't slurp an outside file
///   into a signed attestation.
/// * `trust_roots` (verify-attest, verify) is *external authority* — it
///   must resolve OUTSIDE the repo, so a hostile clone's planted
///   `.mkit/trust-roots.toml` can never be selected via the MCP
///   (the CLI's "explicit --trust-roots = user intent" gate assumes a
///   user, but here the value can come from repo-controlled prompt text;
///   see docs/THREAT-MODEL.md §"Trust-roots scope").
fn confine_path_args(name: &str, args: &Value, repo: &Path) -> Result<(), String> {
    match name {
        "mkit_attest" => {
            if let Some(f) = opt_str(args, "predicate_file") {
                confine_path(repo, &f, Containment::Inside, "predicate_file")?;
            }
        }
        "mkit_verify_attest" | "mkit_verify" => {
            if let Some(f) = opt_str(args, "trust_roots") {
                confine_path(repo, &f, Containment::Outside, "trust_roots")?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Containment {
    Inside,
    Outside,
}

/// Resolve `raw` the way the child CLI will (relative to the repo cwd,
/// or as an absolute path) and require it to be inside / outside the
/// repo. The target must exist (the CLI reads it), so canonicalize is
/// the source of truth for both existence and symlink resolution.
fn confine_path(repo: &Path, raw: &str, want: Containment, what: &str) -> Result<(), String> {
    let candidate = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        repo.join(raw)
    };
    let resolved = candidate
        .canonicalize()
        .map_err(|e| format!("invalid {what} '{raw}': {e}"))?;
    let within = resolved.starts_with(repo);
    match want {
        Containment::Inside if !within => Err(format!(
            "{what} '{raw}' is outside the repository; predicate files must live in the repo"
        )),
        Containment::Outside if within => Err(format!(
            "{what} '{raw}' is inside the repository; trust-roots must be a user-controlled file \
             outside the repo (hostile-clone defense — see docs/THREAT-MODEL.md)"
        )),
        _ => Ok(()),
    }
}

/// Resolve and (when scoped) confine `repo_path`.
fn validate_repo_path(raw: &str, allowed: Option<&Path>) -> Result<PathBuf, String> {
    let resolved = PathBuf::from(raw)
        .canonicalize()
        .map_err(|e| format!("invalid repo_path '{raw}': {e}"))?;
    if let Some(root) = allowed
        && !resolved.starts_with(root)
    {
        return Err(format!(
            "repo_path '{raw}' is outside the allowed repository '{}'",
            root.display()
        ));
    }
    if !resolved.is_dir() {
        return Err(format!("repo_path '{raw}' is not a directory"));
    }
    Ok(resolved)
}

/// Reject values that the child CLI could parse as a flag. mkit's
/// `add` has no `--` separator, so this is the containment line.
fn no_dash(value: &str, what: &str) -> Result<(), String> {
    if value.starts_with('-') {
        return Err(format!("invalid {what} '{value}': must not start with '-'"));
    }
    if value.is_empty() {
        return Err(format!("invalid {what}: must not be empty"));
    }
    Ok(())
}

fn req_str(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing required argument: {key}"))
}

fn opt_str(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Push `--commit <hash>` unless the value is "HEAD" (any case) or
/// absent — the CLI's `--commit` parses a hex hash and rejects "HEAD",
/// but defaults to HEAD when the flag is omitted, so map the common
/// agent shorthand onto that default.
fn push_commit(out: &mut Vec<String>, args: &Value) -> Result<(), String> {
    if let Some(commit) = opt_str(args, "commit")
        && !commit.eq_ignore_ascii_case("HEAD")
    {
        no_dash(&commit, "commit")?;
        out.extend(["--commit".into(), commit]);
    }
    Ok(())
}

/// Validate and push `--algorithm <alg>` when present.
fn push_algorithm(out: &mut Vec<String>, args: &Value) -> Result<(), String> {
    if let Some(alg) = opt_str(args, "algorithm") {
        if !matches!(alg.as_str(), "ed25519" | "secp256k1" | "p256") {
            return Err(format!(
                "invalid algorithm '{alg}': expected ed25519, secp256k1, or p256"
            ));
        }
        out.extend(["--algorithm".into(), alg]);
    }
    Ok(())
}

/// Map a tool invocation to a child argv. Every push of a
/// user-controlled value is preceded by a `no_dash` check unless the
/// value follows a long flag that takes it as an unambiguous operand.
/// One arm per tool — long but flat, like the dispatcher in `lib.rs`
/// (same precedent as `serve.rs` for the line-count allowance).
#[allow(clippy::too_many_lines)]
fn build_argv(name: &str, args: &Value) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    match name {
        "mkit_status" => out.extend(["status".into(), "--porcelain=v2".into()]),
        "mkit_diff_unstaged" => out.push("diff".into()),
        "mkit_diff_staged" => out.extend(["diff".into(), "--staged".into()]),
        "mkit_diff" => {
            let target = req_str(args, "target")?;
            no_dash(&target, "target")?;
            out.extend(["diff".into(), target]);
        }
        "mkit_log" => {
            out.extend(["log".into(), "--format=json".into(), "-n".into()]);
            let n = args.get("max_count").and_then(Value::as_u64).unwrap_or(10);
            out.push(n.to_string());
            if let Some(rev) = opt_str(args, "rev") {
                no_dash(&rev, "rev")?;
                out.push(rev);
            }
        }
        "mkit_show" => {
            let rev = req_str(args, "revision")?;
            no_dash(&rev, "revision")?;
            out.extend(["show".into(), rev]);
        }
        "mkit_branch" => out.extend(["branch".into(), "--format=json".into()]),
        "mkit_cat_object" => {
            let object = req_str(args, "object")?;
            no_dash(&object, "object")?;
            let flag = match opt_str(args, "mode").as_deref() {
                None | Some("pretty") => "-p",
                Some("type") => "-t",
                Some("size") => "-s",
                Some(other) => {
                    return Err(format!(
                        "invalid mode '{other}': expected type, size, or pretty"
                    ));
                }
            };
            out.extend(["cat-file".into(), flag.into(), object]);
        }
        "mkit_verify" => {
            let rev = req_str(args, "revision")?;
            no_dash(&rev, "revision")?;
            out.extend(["verify".into(), rev]);
            if args.get("trusted").and_then(Value::as_bool) == Some(true) {
                out.push("--trusted".into());
            }
            if let Some(roots) = opt_str(args, "trust_roots") {
                no_dash(&roots, "trust_roots")?;
                out.extend(["--trust-roots".into(), roots]);
            }
        }
        "mkit_verify_attest" => {
            out.push("verify-attest".into());
            push_commit(&mut out, args)?;
            if let Some(roots) = opt_str(args, "trust_roots") {
                no_dash(&roots, "trust_roots")?;
                out.extend(["--trust-roots".into(), roots]);
            }
            push_algorithm(&mut out, args)?;
        }
        "mkit_add" => {
            out.push("add".into());
            let files = args
                .get("files")
                .and_then(Value::as_array)
                .ok_or("missing required argument: files")?;
            if files.is_empty() {
                return Err("files must not be empty".into());
            }
            for f in files {
                let f = f.as_str().ok_or("files entries must be strings")?;
                no_dash(f, "file path")?;
                out.push(f.into());
            }
        }
        "mkit_unstage" => {
            match args.get("files") {
                // Key absent = the documented "unstage everything" form:
                // bare `reset` (mixed) — the working tree is never touched.
                None => out.push("reset".into()),
                // Key present: it must be a non-empty array of strings. A
                // malformed value (string, empty array, …) must NOT silently
                // widen a targeted unstage into a whole-index mutation.
                Some(Value::Array(list)) if !list.is_empty() => {
                    out.extend(["restore".into(), "--staged".into()]);
                    for f in list {
                        let f = f.as_str().ok_or("files entries must be strings")?;
                        no_dash(f, "file path")?;
                        out.push(f.into());
                    }
                }
                Some(_) => {
                    return Err(
                        "files must be a non-empty array of paths; omit it entirely to \
                         unstage everything"
                            .into(),
                    );
                }
            }
        }
        "mkit_commit" => {
            let message = req_str(args, "message")?;
            if message.trim().is_empty() {
                return Err("message must not be empty".into());
            }
            out.extend(["commit".into(), "-m".into(), message]);
        }
        "mkit_create_branch" => {
            let branch = req_str(args, "branch_name")?;
            no_dash(&branch, "branch_name")?;
            out.extend(["branch".into(), branch]);
        }
        "mkit_checkout" => {
            let branch = req_str(args, "branch_name")?;
            no_dash(&branch, "branch_name")?;
            out.extend(["checkout".into(), branch]);
        }
        "mkit_init" => out.push("init".into()),
        "mkit_keygen" => {
            out.push("keygen".into());
            push_algorithm(&mut out, args)?;
            if args.get("print_pubkey").and_then(Value::as_bool) == Some(true) {
                out.push("--print-pubkey".into());
            }
        }
        "mkit_attest" => {
            out.push("attest".into());
            push_commit(&mut out, args)?;
            // ALWAYS pass --algorithm explicitly: when absent the child CLI
            // falls back to user-scoped `attest.default_algorithm`, which
            // config.rs documents as a security-sensitive selector — ambient
            // config must not steer an agent-triggered signing operation.
            let alg = opt_str(args, "algorithm").unwrap_or_else(|| "ed25519".into());
            if !matches!(alg.as_str(), "ed25519" | "secp256k1" | "p256") {
                return Err(format!(
                    "invalid algorithm '{alg}': expected ed25519, secp256k1, or p256"
                ));
            }
            out.extend(["--algorithm".into(), alg]);
            // ALWAYS pass --signer explicitly: when the flag is absent the
            // child CLI falls back to user-scoped `attest.signer` config,
            // which may name `external` — and the external-signer path is
            // excluded from the MCP (it executes a configured subprocess).
            let signer = opt_str(args, "signer").unwrap_or_else(|| "repo-key".into());
            if !matches!(signer.as_str(), "repo-key" | "keystore") {
                return Err(format!(
                    "invalid signer '{signer}': expected repo-key or keystore \
                     (external is excluded from the MCP)"
                ));
            }
            out.extend(["--signer".into(), signer]);
            if let Some(uri) = opt_str(args, "predicate_type") {
                no_dash(&uri, "predicate_type")?;
                out.extend(["--predicate-type".into(), uri]);
            }
            if let Some(file) = opt_str(args, "predicate_file") {
                no_dash(&file, "predicate_file")?;
                out.extend(["--predicate-file".into(), file]);
            }
        }
        other => return Err(format!("unknown tool: {other}")),
    }
    Ok(out)
}

/// Run `mkit <argv>` in `repo`, capturing everything. The child is
/// always this same binary, so server and CLI can never skew.
fn run_subprocess(repo: &Path, argv: &[String]) -> CallOutcome {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return CallOutcome::err(format!("cannot locate mkit binary: {e}")),
    };
    let output = std::process::Command::new(exe)
        .args(argv)
        .current_dir(repo)
        // Deterministic, capture-friendly child environment: no ANSI,
        // and no editor fallback (commit always receives -m here, but
        // belt-and-braces against any future interactive path).
        .env("NO_COLOR", "1")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("EDITOR")
        .env_remove("VISUAL")
        .output();
    let output = match output {
        Ok(o) => o,
        Err(e) => return CallOutcome::err(format!("failed to run mkit {}: {e}", argv.join(" "))),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let code = output.status.code().unwrap_or(-1);

    if output.status.success() {
        let mut text = stdout.trim_end().to_string();
        if text.is_empty() {
            // Several mkit commands put confirmation prose on stderr
            // and reserve stdout for machine output; surface it.
            text = stderr.trim_end().to_string();
        }
        if text.is_empty() {
            text = "(ok — no output)".into();
        }
        CallOutcome {
            text,
            is_error: false,
        }
    } else {
        let mut text = format!("error: mkit exited {code} ({})", sysexits_name(code));
        if !stderr.trim().is_empty() {
            text.push('\n');
            text.push_str(stderr.trim_end());
        }
        if !stdout.trim().is_empty() {
            text.push('\n');
            text.push_str(stdout.trim_end());
        }
        CallOutcome {
            text,
            is_error: true,
        }
    }
}

/// Human label for the BSD sysexits codes documented in docs/CLI.md.
fn sysexits_name(code: i32) -> &'static str {
    match code {
        0 => "ok",
        1 => "general error",
        64 => "usage: wrong args or unknown subcommand",
        65 => "dataerr: malformed input",
        66 => "noinput: missing or unreadable input",
        69 => "unavailable: transport could not connect",
        73 => "cantcreat: cannot create output",
        75 => "tempfail: transient failure, retry is safe",
        76 => "protocol error",
        77 => "noperm: permission denied",
        78 => "config error",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(feature = "mcp-v2"))]
    fn tool_table_is_complete_and_annotated() {
        let tools = tool_descriptors();
        let arr = tools.as_array().unwrap();
        assert_eq!(arr.len(), 18, "tool count is part of the public surface");
        for t in arr {
            assert!(t.get("name").is_some());
            assert!(t.get("description").is_some());
            assert_eq!(t.pointer("/inputSchema/type").unwrap(), "object");
            // Every tool is local-only.
            assert_eq!(t.pointer("/annotations/openWorldHint").unwrap(), false);
            // repo_path is universal.
            assert!(t.pointer("/inputSchema/properties/repo_path").is_some());
        }
    }

    #[test]
    #[cfg(not(feature = "mcp-v2"))]
    fn read_only_tools_are_marked() {
        let tools = tool_descriptors();
        for t in tools.as_array().unwrap() {
            let name = t.get("name").unwrap().as_str().unwrap();
            let ro = t
                .pointer("/annotations/readOnlyHint")
                .unwrap()
                .as_bool()
                .unwrap();
            let expect_ro = matches!(
                name,
                "mkit_status"
                    | "mkit_diff_unstaged"
                    | "mkit_diff_staged"
                    | "mkit_diff"
                    | "mkit_log"
                    | "mkit_show"
                    | "mkit_branch"
                    | "mkit_cat_object"
                    | "mkit_verify"
                    | "mkit_verify_attest"
            );
            assert_eq!(ro, expect_ro, "readOnlyHint wrong for {name}");
        }
    }

    #[test]
    fn argv_construction_basics() {
        let argv = build_argv("mkit_status", &json!({})).unwrap();
        assert_eq!(argv, ["status", "--porcelain=v2"]);

        let argv = build_argv("mkit_commit", &json!({ "message": "hello world" })).unwrap();
        assert_eq!(argv, ["commit", "-m", "hello world"]);

        let argv = build_argv("mkit_add", &json!({ "files": ["a.txt", "src/b.rs"] })).unwrap();
        assert_eq!(argv, ["add", "a.txt", "src/b.rs"]);
    }

    #[test]
    fn flag_injection_is_rejected() {
        for (tool, args) in [
            ("mkit_diff", json!({ "target": "-R" })),
            ("mkit_show", json!({ "revision": "--help" })),
            ("mkit_add", json!({ "files": ["-A"] })),
            ("mkit_checkout", json!({ "branch_name": "-b" })),
            ("mkit_create_branch", json!({ "branch_name": "-D" })),
            ("mkit_cat_object", json!({ "object": "--batch" })),
            ("mkit_log", json!({ "rev": "--graph" })),
            ("mkit_attest", json!({ "predicate_file": "--force" })),
        ] {
            let err = build_argv(tool, &args).unwrap_err();
            assert!(err.contains("must not start with '-'"), "{tool}: {err}");
        }
    }

    #[test]
    fn unstage_maps_to_restore_or_reset() {
        let argv = build_argv("mkit_unstage", &json!({})).unwrap();
        assert_eq!(argv, ["reset"]);
        let argv = build_argv("mkit_unstage", &json!({ "files": ["a.txt"] })).unwrap();
        assert_eq!(argv, ["restore", "--staged", "a.txt"]);
    }

    #[test]
    fn unstage_rejects_malformed_files_instead_of_widening() {
        // A present-but-malformed `files` must error, never silently
        // broaden a targeted unstage into a whole-index reset.
        for bad in [
            json!({ "files": "a.txt" }),
            json!({ "files": [] }),
            json!({ "files": 3 }),
        ] {
            let err = build_argv("mkit_unstage", &bad).unwrap_err();
            assert!(err.contains("non-empty array"), "{bad}: {err}");
        }
    }

    #[test]
    fn attest_always_pins_the_signer() {
        // Omitted signer must still emit --signer repo-key so user config
        // (`attest.signer = external`) can never reroute an MCP-triggered
        // attestation into an external-signer subprocess.
        let argv = build_argv("mkit_attest", &json!({})).unwrap();
        assert_eq!(
            argv,
            ["attest", "--algorithm", "ed25519", "--signer", "repo-key"]
        );
        let argv = build_argv("mkit_attest", &json!({ "signer": "keystore" })).unwrap();
        assert_eq!(
            argv,
            ["attest", "--algorithm", "ed25519", "--signer", "keystore"]
        );
        let argv = build_argv("mkit_attest", &json!({ "algorithm": "p256" })).unwrap();
        assert_eq!(
            argv,
            ["attest", "--algorithm", "p256", "--signer", "repo-key"]
        );
        let err = build_argv("mkit_attest", &json!({ "signer": "external" })).unwrap_err();
        assert!(err.contains("excluded"), "{err}");
    }

    #[test]
    #[cfg(not(feature = "mcp-v2"))]
    fn checkout_is_marked_destructive() {
        // Checkout rewrites tracked worktree files; clients use
        // destructiveHint to decide whether to confirm.
        let tools = tool_descriptors();
        let checkout = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t.get("name").unwrap() == "mkit_checkout")
            .unwrap();
        assert_eq!(
            checkout.pointer("/annotations/destructiveHint").unwrap(),
            true
        );
    }

    #[test]
    fn no_force_flag_ever_emitted() {
        // The server must never override mkit's data-loss guards.
        for spec in TOOLS {
            let args = json!({
                "repo_path": "/tmp", "target": "x", "revision": "x", "object": "x",
                "message": "m", "branch_name": "b", "files": ["f"],
                "commit": "c", "predicate_type": "t", "predicate_file": "p",
            });
            if let Ok(argv) = build_argv(spec.name, &args) {
                assert!(
                    !argv.iter().any(|a| a == "-f" || a == "--force"),
                    "{} emits a force flag",
                    spec.name
                );
            }
        }
    }

    #[test]
    fn scope_validation_rejects_outside_paths() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let allowed = root.path().canonicalize().unwrap();

        assert!(validate_repo_path(root.path().to_str().unwrap(), Some(&allowed)).is_ok());
        let err = validate_repo_path(outside.path().to_str().unwrap(), Some(&allowed)).unwrap_err();
        assert!(err.contains("outside the allowed repository"));
        // Unscoped mode allows anything that exists.
        assert!(validate_repo_path(outside.path().to_str().unwrap(), None).is_ok());
    }

    #[test]
    #[cfg(not(feature = "mcp-v2"))]
    fn initialize_negotiates_protocol_and_lists_tools() {
        let mut init_state = false;

        // Tool traffic before initialize is rejected (-32002).
        let early = json!({ "jsonrpc": "2.0", "id": 0, "method": "tools/list" });
        let resp = handle_message(&early, None, &mut init_state).unwrap();
        assert_eq!(resp.pointer("/error/code").unwrap(), -32002);
        assert!(!init_state);

        // A supported protocol is echoed back.
        let init = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": "2024-11-05", "capabilities": {} }
        });
        let resp = handle_message(&init, None, &mut init_state).unwrap();
        assert_eq!(
            resp.pointer("/result/protocolVersion").unwrap(),
            "2024-11-05"
        );
        assert_eq!(
            resp.pointer("/result/serverInfo/name").unwrap(),
            "mkit-repo"
        );
        assert!(resp.pointer("/result/instructions").is_some());
        assert!(init_state);

        // An UNsupported protocol falls back to our latest, never echoed.
        let mut s2 = false;
        let bad = json!({
            "jsonrpc": "2.0", "id": 9, "method": "initialize",
            "params": { "protocolVersion": "1900-01-01" }
        });
        let resp = handle_message(&bad, None, &mut s2).unwrap();
        assert_eq!(
            resp.pointer("/result/protocolVersion").unwrap(),
            LATEST_PROTOCOL
        );

        // After initialize, tools/list works.
        let list = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
        let resp = handle_message(&list, None, &mut init_state).unwrap();
        assert_eq!(
            resp.pointer("/result/tools")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            18
        );

        // Notifications produce no response.
        let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(handle_message(&note, None, &mut init_state).is_none());

        // Unknown methods error.
        let bogus = json!({ "jsonrpc": "2.0", "id": 3, "method": "resources/list" });
        let resp = handle_message(&bogus, None, &mut init_state).unwrap();
        assert_eq!(resp.pointer("/error/code").unwrap(), -32601);
    }
}
