//! `mkit blame [-w] [-M] [-C] [--ignore-rev <rev>] [--ignore-revs-file <file>]
//! [--ignore-rev-precise] [--first-parent] [--reverse] [<rev>] [-L <range>]
//! <file>` — line-level attribution.
//!
//! Blames `<file>` as of `<rev>` (default `HEAD`), optionally restricted
//! to a line range with `-L`. `-w` ignores whitespace when matching
//! lines across revisions (git `-w`); `-M`/`-C` detect lines moved within
//! the file / copied from other files (git `-M`/`-C`); `--ignore-rev` /
//! `--ignore-revs-file` skip "noise" commits during attribution (git
//! `--ignore-rev`), falling through to the commit that previously changed
//! each line. `--ignore-rev-precise` (mkit-only; requires `--ignore-rev`/
//! `--ignore-revs-file`) refines that fall-through with content matching
//! instead of git's positional per-hunk guess — a documented divergence,
//! opt-in only. Blame is merge-aware by default (a line merged from a side
//! branch is credited to the commit that wrote it); `--first-parent`
//! restricts the walk to first parents (git `--first-parent`).
//! `--reverse <start>..<end>` instead walks history forward, attributing
//! each line of the `<start>` version to the last commit in the range in
//! which it still existed (git `--reverse`).
//!
//! Output modes:
//!
//! - default — `<short12>\t<line_num>\t<text>\n` per line, pinned by
//!   the integration test in `tests/cli_wire.rs:233-243`.
//! - `--format=json` — JSONL, one self-contained record per line with
//!   keys `hash`, `line_num`, `author`, `timestamp`, `text`. Schema
//!   diverges from the tab format because mkit's author is an
//!   Identity, not a `Name <email>` string — see commands/log.rs for
//!   the same divergence.
//!
//! Line numbers in the output are always the file's own 1-based numbers,
//! so a `-L 40,60` slice still prints `40..=60`, matching `git blame -L`.
//!
//! `--prove [-o <path>]` (SPEC-BLAME-PROOF.md, D7; issue #495 PR C) builds a
//! tamper-evident blame-proof predicate for the whole file (via
//! `mkit_core::ops::blame::proof::build_blame_proof`), wraps it in a signed
//! DSSE envelope, and writes it to `<file>.blame-proof.json` (or `-o`).
//! Signing reuses `mkit attest`'s signer-selection flags
//! (`--algorithm`/`--signer`/`--external-signer-arg`/`--additional-signer`).
//! Incompatible with `--reverse` and `-L` (the proof always covers every
//! line of the file at the resolved commit — see the spec's D3). Verify with
//! `mkit verify-attest --envelope-file <path> --subject-file <file>`.

use std::collections::HashSet;
use std::io::Write;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use mkit_attest::{Envelope, PAYLOAD_TYPE_IN_TOTO, Sig, statement};
use mkit_core::hash::{self, Hash};
use mkit_core::ops::blame::proof::build_blame_proof;
use mkit_core::ops::blame::{
    BlameOptions, BlameResult, CopyDetection, MoveDetection, blame_file_reverse, blame_file_with,
    format_blame_text,
};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use super::attest;
use super::attest_factory;
use super::blame_proof;
use super::revspec;
use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BlameFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit blame",
    about = "Show line-level commit attribution.",
    override_usage = "mkit blame [OPTIONS] [<rev>] [--] <file>"
)]
// A CLI flag struct: each bool is an independent `git blame` toggle, so the
// "too many bools" heuristic (which targets state that should be an enum)
// does not apply.
#[allow(clippy::struct_excessive_bools)]
struct BlameOpts {
    /// Output format. Default emits `<short12>\t<line_num>\t<text>`
    /// per line; `json` emits JSONL with `hash`, `line_num`,
    /// `author`, `timestamp`, `text` keys.
    #[arg(long, value_enum, default_value = "default")]
    format: BlameFormat,
    /// Ignore whitespace when matching lines across revisions, like
    /// `git blame -w`, so a whitespace-only edit (reindent, tab↔space,
    /// spacing tweak) doesn't reattribute the line. Output still shows
    /// the file's current bytes.
    #[arg(short = 'w', long = "ignore-whitespace")]
    ignore_whitespace: bool,
    /// Restrict output to a line range, like `git blame -L`. Accepts
    /// `<start>,<end>`, `<start>,+<n>` (n lines forward), `<start>,-<n>`
    /// (n lines back, ending at start), `<start>,` (start to EOF),
    /// `,<end>` (start of file to end), or a bare `<start>` (start to
    /// EOF). Lines are 1-based and inclusive; an inverted range is
    /// swapped and an over-long end is clamped to EOF, matching git.
    // `allow_hyphen_values` so a pathological negative start (`-3,5`)
    // reaches the parser for a git-faithful diagnostic instead of clap
    // mistaking `-3` for a flag. Valid values never start with `-` (the
    // `-<n>` offset is always the second field).
    #[arg(
        short = 'L',
        long = "lines",
        value_name = "START,END",
        allow_hyphen_values = true
    )]
    lines: Option<String>,
    /// Detect lines moved *within* the file, like `git blame -M`: a moved
    /// block of at least 20 alphanumeric characters is credited to its
    /// origin commit rather than the editing one. (git's inline `-M<num>`
    /// threshold override is not exposed; the core API accepts a custom
    /// threshold.)
    #[arg(short = 'M', long = "find-moves")]
    find_moves: bool,
    /// Detect lines copied *from other files*, like `git blame -C`
    /// (implies `-M`). Repeat to widen the search: `-C` covers files
    /// changed in the same commit, `-C -C` every file in the parent
    /// commit. A copied block needs at least 40 alphanumeric characters.
    /// (git's inline `-C<num>` threshold override is not exposed.)
    #[arg(short = 'C', long = "find-copies", action = clap::ArgAction::Count)]
    find_copies: u8,
    /// Ignore a "noise" commit (mass reformat, license header, rename)
    /// when attributing lines, like `git blame --ignore-rev`. A line that
    /// would be credited to an ignored commit falls through to the commit
    /// that previously changed it; a genuine insertion stays put. Accepts
    /// any revision (short hash, ref, `HEAD~2`) and may be repeated.
    #[arg(long = "ignore-rev", value_name = "REV")]
    ignore_rev: Vec<String>,
    /// Ignore every commit listed in `<file>`, like
    /// `git blame --ignore-revs-file`. One full hex object name per line;
    /// blank lines and `#` comments (including inline) are skipped. May be
    /// repeated.
    #[arg(long = "ignore-revs-file", value_name = "FILE")]
    ignore_revs_file: Vec<String>,
    /// Refine `--ignore-rev`/`--ignore-revs-file` fall-through with content
    /// matching instead of git's positional per-hunk guess (mkit-only
    /// divergence; the default fall-through stays git-identical). git pairs
    /// a fallen-through line with whatever line sits at the same offset in
    /// the hunk; mkit hashes content, so it can often identify the line's
    /// true surviving origin even when a reformat/reorder moved it to a
    /// different offset. Requires `--ignore-rev` or `--ignore-revs-file`.
    #[arg(long = "ignore-rev-precise")]
    ignore_rev_precise: bool,
    /// Walk history *forward* instead of backward, like
    /// `git blame --reverse`. Blames the `<start>` version of the file and
    /// attributes each line to the last commit in the range in which it
    /// still existed. Requires the `<rev>` argument to be a
    /// `<start>..<end>` range (`<start>..` defaults `<end>` to HEAD); a
    /// bare revision or a missing `<start>` is rejected. Cannot be combined
    /// with `-M`/`-C` or `--ignore-rev`/`--ignore-revs-file`.
    #[arg(long = "reverse")]
    reverse: bool,
    /// Follow only each commit's first parent, like `git blame
    /// --first-parent`. By default blame is merge-aware: a line merged in
    /// from a side branch is credited to the commit that wrote it. With
    /// `--first-parent` such a line is credited to the merge commit instead.
    /// Composes with `-w`/`-M`/`-C`/`--ignore-rev`; redundant with
    /// `--reverse` (reverse blame is already first-parent only).
    #[arg(long = "first-parent")]
    first_parent: bool,
    /// Emit a signed, tamper-evident blame-proof DSSE envelope for the
    /// whole file instead of printing blame text (SPEC-BLAME-PROOF.md D7).
    /// Incompatible with `--reverse` and `-L` (the proof always covers
    /// every line of the file). Verify with `mkit verify-attest
    /// --envelope-file <path> --subject-file <file>`.
    #[arg(long = "prove")]
    prove: bool,
    /// Output path for `--prove`. Defaults to `<file>.blame-proof.json`.
    #[arg(short = 'o', long = "output", value_name = "PATH")]
    output: Option<String>,
    /// `--prove` signing algorithm: `ed25519`, `secp256k1`, or `p256`.
    /// Same flag as `mkit attest --algorithm`.
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
    /// `--prove` primary signer kind: `repo-key` (default), `keystore`, or
    /// `external`. Same flag as `mkit attest --signer`.
    #[arg(long, value_name = "KIND")]
    signer: Option<String>,
    /// `--prove`: repeatable, adds a co-signature to the envelope. Same
    /// grammar as `mkit attest --additional-signer`.
    #[arg(long = "additional-signer", value_name = "SPEC")]
    additional_signers: Vec<String>,
    /// `--prove`: repeatable argv token passed to an external signer
    /// subprocess. Same flag as `mkit attest --external-signer-arg`.
    #[arg(
        long = "external-signer-arg",
        value_name = "ARG",
        allow_hyphen_values = true
    )]
    external_signer_args_vec: Vec<String>,
    /// `[<rev>] <file>`: the file to blame, optionally preceded by the
    /// revision to blame it at (a ref, hash, or `HEAD~2`-style spec).
    /// Without a revision the file is blamed against HEAD. A `--`
    /// separator before the file is accepted and ignored.
    #[arg(value_name = "REV/FILE", num_args = 1..=2, required = true)]
    rev_and_file: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<BlameOpts>("mkit blame", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(opts.format, BlameFormat::Json);

    // `rev_and_file` is clamped to 1..=2 by clap: one value is the file
    // (blame against HEAD); two values are `<rev> <file>`.
    let (rev_spec, file) = match opts.rev_and_file.as_slice() {
        [file] => (None, file),
        [rev, file] => (Some(rev), file),
        // Unreachable: clap enforces num_args = 1..=2.
        _ => return emit_err("expected [<rev>] <file>", exit::USAGE),
    };

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    if let Err((msg, code)) = check_flag_conflicts(&opts) {
        return emit_err(&msg, code);
    }

    // `-M` enables move detection at git's default threshold; `-C` (a
    // repeat count) sets the copy search level. `-C` implies `-M` in the
    // core, so a bare `-C` still credits within-file moves too.
    let moves = if opts.find_moves {
        MoveDetection::GIT_DEFAULT
    } else {
        MoveDetection::Off
    };
    let copies = if opts.find_copies > 0 {
        CopyDetection::git_default(opts.find_copies)
    } else {
        CopyDetection::Off
    };
    // Build the `--ignore-rev` / `--ignore-revs-file` skip set. Each
    // failure is already git-faithful text paired with an exit code.
    let ignore_revs = match collect_ignore_revs(&store, &mkit_dir, &opts) {
        Ok(set) => Arc::new(set),
        Err((msg, code)) => return emit_err(&msg, code),
    };

    let blame_opts = BlameOptions {
        ignore_whitespace: opts.ignore_whitespace,
        moves,
        copies,
        ignore_revs,
        ignore_rev_precise: opts.ignore_rev_precise,
        first_parent: opts.first_parent,
    };

    if opts.prove {
        let commit = match resolve_blame_commit(&store, &mkit_dir, rev_spec) {
            Ok(h) => h,
            Err((msg, code)) => return emit_err(&msg, code),
        };
        return run_prove(&opts, &cwd, &store, commit, file, &blame_opts);
    }

    // `--reverse` walks forward over a `<start>..<end>` range; plain blame
    // walks backward from a single `<rev>` (or HEAD).
    let result = if opts.reverse {
        let (start, end) = match resolve_reverse_range(&store, &mkit_dir, rev_spec, file) {
            Ok(pair) => pair,
            Err((msg, code)) => return emit_err(&msg, code),
        };
        match blame_file_reverse(&store, start, end, file, &blame_opts) {
            Ok(r) => r,
            Err(e) => return emit_err(&format!("blame: {e}"), exit::NOINPUT),
        }
    } else {
        // Resolve the commit to blame against: an explicit <rev> via the
        // shared revspec grammar, otherwise HEAD.
        let head = match resolve_blame_commit(&store, &mkit_dir, rev_spec) {
            Ok(h) => h,
            Err((msg, code)) => return emit_err(&msg, code),
        };
        match blame_file_with(&store, head, file, &blame_opts) {
            Ok(r) => r,
            Err(e) => return emit_err(&format!("blame: {e}"), exit::NOINPUT),
        }
    };

    // `-L` slices the per-line attributions to the requested range,
    // preserving the file's own 1-based line numbers in the output.
    let result = match &opts.lines {
        Some(spec) => match parse_line_range(spec, result.lines.len(), file) {
            Ok((start, end)) => BlameResult {
                lines: result.lines[start - 1..end].to_vec(),
            },
            // The message is already git-faithful and self-contained
            // (it carries `file` where git does), so it prints verbatim.
            Err(msg) => return emit_err(&msg, exit::USAGE),
        },
        None => result,
    };

    if json {
        render_json(&result)
    } else {
        let text = format_blame_text(&result);
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(text.as_bytes());
        exit::OK
    }
}

/// Reject flag combinations `run` cannot satisfy, before any store/revision
/// resolution work. On error returns `(message, exit_code)`.
fn check_flag_conflicts(opts: &BlameOpts) -> Result<(), (String, u8)> {
    // `--reverse` is a distinct walk that resolves line survival via the
    // LCS matcher only — it runs neither move/copy nor ignore-rev
    // detection, so reject the combination rather than silently ignoring
    // those flags.
    if opts.reverse
        && (opts.find_moves
            || opts.find_copies > 0
            || !opts.ignore_rev.is_empty()
            || !opts.ignore_revs_file.is_empty())
    {
        return Err((
            "--reverse cannot be combined with -M/-C or --ignore-rev/--ignore-revs-file"
                .to_string(),
            exit::USAGE,
        ));
    }
    // `--ignore-rev-precise` only refines an active ignore-rev set; without
    // one it has nothing to refine, so reject it outright rather than
    // silently no-op'ing.
    if opts.ignore_rev_precise && opts.ignore_rev.is_empty() && opts.ignore_revs_file.is_empty() {
        return Err((
            "--ignore-rev-precise requires --ignore-rev or --ignore-revs-file".to_string(),
            exit::USAGE,
        ));
    }
    // `--prove` always builds a proof over the whole file (SPEC-BLAME-PROOF
    // §4/D3 — dense attributions covering every line) at a single resolved
    // commit, so it cannot compose with `--reverse` (a distinct range walk)
    // or `-L` (a line subset).
    if opts.prove && opts.reverse {
        return Err((
            "--prove cannot be combined with --reverse".to_string(),
            exit::USAGE,
        ));
    }
    if opts.prove && opts.lines.is_some() {
        return Err((
            "--prove cannot be combined with -L".to_string(),
            exit::USAGE,
        ));
    }
    Ok(())
}

/// Resolve the commit to blame against: an explicit `<rev>` via the shared
/// revspec grammar, otherwise HEAD. Shared by plain (non-`--reverse`) blame
/// and `--prove` (D7 always blames a single resolved commit).
fn resolve_blame_commit(
    store: &ObjectStore,
    mkit_dir: &std::path::Path,
    rev_spec: Option<&String>,
) -> Result<Hash, (String, u8)> {
    if let Some(spec) = rev_spec {
        return revspec::resolve_revision(store, mkit_dir, spec)
            .map_err(|e| (format!("{e}"), exit::NOINPUT));
    }
    match refs::resolve_head(mkit_dir) {
        Ok(Some(h)) => Ok(h),
        Ok(None) => Err(("no commits yet".to_string(), exit::GENERAL_ERROR)),
        Err(e) => Err((format!("resolve HEAD: {e}"), exit::GENERAL_ERROR)),
    }
}

/// `mkit blame --prove`: build the SPEC-BLAME-PROOF v1 predicate (D4), wrap
/// it in a signed DSSE envelope whose subject is the blamed file's blob
/// digest (D2), and write it to `<file>.blame-proof.json` or `-o <path>`.
#[allow(clippy::too_many_lines)]
fn run_prove(
    opts: &BlameOpts,
    cwd: &std::path::Path,
    store: &ObjectStore,
    commit: Hash,
    file: &str,
    blame_opts: &BlameOptions,
) -> u8 {
    let predicate = match build_blame_proof(store, blame_opts, commit, file) {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("blame proof: {e}"), exit::NOINPUT),
    };
    let predicate_json = match blame_proof::encode_predicate(&predicate) {
        Ok(s) => s,
        Err(e) => {
            return emit_err(
                &format!("encode blame-proof predicate: {e}"),
                exit::GENERAL_ERROR,
            );
        }
    };

    let stmt = statement::Statement {
        subjects: vec![statement::Subject {
            name: Some(file.to_owned()),
            digest_blake3_hex: hash::to_hex(&predicate.blob),
        }],
        predicate_type: blame_proof::BLAME_PROOF_PREDICATE_TYPE.to_owned(),
        predicate_jcs: predicate_json.as_bytes(),
    };
    let stmt_bytes = match statement::encode(&stmt) {
        Ok(s) => s.into_bytes(),
        Err(e) => return emit_err(&format!("statement: {e}"), exit::DATAERR),
    };

    // --- Signer selection: same flags/semantics as `mkit attest`. --------
    let mut cfg = match crate::config::read_or_default(cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let alg_str = opts
        .algorithm
        .clone()
        .unwrap_or_else(|| cfg.attest.default_algorithm_or_fallback().to_owned());
    let Ok(algorithm) = attest_factory::parse_algorithm(&alg_str) else {
        return emit_err(
            &format!("unknown algorithm '{alg_str}' — expected one of: ed25519, secp256k1, p256"),
            exit::USAGE,
        );
    };
    let signer_kind = opts
        .signer
        .clone()
        .unwrap_or_else(|| cfg.attest.signer_or_fallback().to_owned());
    // `--external-signer-arg` REPLACES `attest.external_signer_args` when
    // present, exactly like `mkit attest`.
    if let Some(argv) = attest::external_signer_args_from_vec(&opts.external_signer_args_vec) {
        cfg.attest.external_signer_args = argv;
    }
    let mut signers = match attest::build_signer_list(
        cwd,
        &cfg,
        algorithm,
        &signer_kind,
        &opts.additional_signers,
    ) {
        Ok(s) => s,
        Err((msg, code)) => return emit_err(&msg, code),
    };

    let pae = mkit_attest::pae_of(PAYLOAD_TYPE_IN_TOTO, &stmt_bytes);
    let mut signatures: Vec<Sig> = Vec::with_capacity(signers.len());
    for (idx, signer) in signers.iter_mut().enumerate() {
        let sig_bytes = match signer.sign(&pae) {
            Ok(b) => b,
            Err(e) => {
                return emit_err(
                    &format!("sign (signer #{}): {e}", idx + 1),
                    exit::GENERAL_ERROR,
                );
            }
        };
        let keyid = match signer.keyid() {
            Ok(k) => k,
            Err(e) => {
                return emit_err(
                    &format!("keyid (signer #{}): {e}", idx + 1),
                    exit::GENERAL_ERROR,
                );
            }
        };
        signatures.push(Sig {
            keyid,
            sig: sig_bytes,
        });
    }

    let envelope = Envelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_owned(),
        payload: stmt_bytes,
        signatures,
    };
    let encoded = match envelope.encode() {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("encode envelope: {e}"), exit::DATAERR),
    };

    let out_path = opts
        .output
        .clone()
        .unwrap_or_else(|| format!("{file}.blame-proof.json"));
    if let Err(e) = std::fs::write(&out_path, encoded.as_bytes()) {
        return emit_err(&format!("write '{out_path}': {e}"), exit::CANTCREAT);
    }

    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "blame-proof for {file}@{} → {out_path} ({} signature(s))",
        hash::to_hex(&commit),
        envelope.signatures.len()
    );
    exit::OK
}

/// Resolve `--ignore-rev` / `--ignore-revs-file` into the set of commits
/// to skip during attribution.
///
/// `--ignore-rev` takes any revision (short hash, ref, `HEAD~2`) via the
/// shared revspec grammar — git resolves these the same way — so an
/// unknown one errors `cannot find revision <rev> to ignore`.
/// `--ignore-revs-file` entries must be **full** hex object names (git
/// rejects short hashes in the file): each line is truncated at the first
/// `#` (inline comments), trimmed, and skipped if empty; a malformed
/// entry errors `invalid object name: <token>`, and an unreadable file
/// `could not open object name list: <path>`. All three messages and the
/// full-hash-only rule were verified against real git.
///
/// On error returns `(message, exit_code)`; mkit uses its sysexits-style
/// codes rather than git's blanket `128`.
fn collect_ignore_revs(
    store: &ObjectStore,
    mkit_dir: &std::path::Path,
    opts: &BlameOpts,
) -> Result<HashSet<Hash>, (String, u8)> {
    let mut set = HashSet::new();

    for spec in &opts.ignore_rev {
        match revspec::resolve_revision(store, mkit_dir, spec) {
            Ok(h) => {
                set.insert(h);
            }
            Err(_) => {
                return Err((
                    format!("cannot find revision {spec} to ignore"),
                    exit::DATAERR,
                ));
            }
        }
    }

    for path in &opts.ignore_revs_file {
        let contents = std::fs::read_to_string(path).map_err(|_| {
            (
                format!("could not open object name list: {path}"),
                exit::NOINPUT,
            )
        })?;
        for raw in contents.lines() {
            // Strip an inline `#` comment, then surrounding whitespace
            // (covers trailing `\r` on CRLF files), matching git.
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let h = hash::from_hex(line)
                .map_err(|_| (format!("invalid object name: {line}"), exit::DATAERR))?;
            set.insert(h);
        }
    }

    Ok(set)
}

/// Resolve the `--reverse` `<start>..<end>` range argument into a pair of
/// commit hashes. `<start>..` defaults `<end>` to HEAD. A missing range, a
/// bare revision (no `..`), an empty `<start>`, a triple-dot/extra-dot
/// range, or an empty range (`start == end`) is a usage error.
///
/// `file` is only used to sharpen the no-range diagnostic: if the single
/// positional looks like the range itself (`a..b`), the file was likely
/// forgotten.
///
/// git's diagnostics here (`No commit to dig up from?`, `More than one
/// commit to dig up from, X and Y?`) are cryptic; mkit names the concrete
/// problem instead — a documented bucket-1 divergence, like the clearer
/// `-L` messages. On error returns `(message, exit_code)`.
fn resolve_reverse_range(
    store: &ObjectStore,
    mkit_dir: &std::path::Path,
    rev_spec: Option<&String>,
    file: &str,
) -> Result<(Hash, Hash), (String, u8)> {
    let Some(spec) = rev_spec else {
        // A lone `a..b` positional is parsed as the *file*; the user most
        // likely supplied the range but omitted the filename.
        if file.contains("..") {
            return Err((
                format!(
                    "--reverse: missing <file> (got only '{file}', which looks like the range)"
                ),
                exit::USAGE,
            ));
        }
        return Err((
            "--reverse requires a <start>..<end> revision range".to_string(),
            exit::USAGE,
        ));
    };
    let Some((start_str, end_str)) = spec.split_once("..") else {
        return Err((
            format!("--reverse requires a <start>..<end> range, got '{spec}'"),
            exit::USAGE,
        ));
    };
    // Reject git's triple-dot symmetric range and any extra `..`: blame
    // takes a single two-dot range. (`a...b` splits to end `.b`; `a..b..c`
    // to end `b..c`.)
    if end_str.starts_with('.') || end_str.contains("..") {
        return Err((
            format!("--reverse requires a single <start>..<end> range, got '{spec}'"),
            exit::USAGE,
        ));
    }
    if start_str.is_empty() {
        return Err((
            "--reverse requires an explicit <start> revision".to_string(),
            exit::USAGE,
        ));
    }
    let start = revspec::resolve_revision(store, mkit_dir, start_str)
        .map_err(|e| (format!("{e}"), exit::NOINPUT))?;
    // `<start>..` (empty end) defaults to HEAD, matching git.
    let end = if end_str.is_empty() {
        match refs::resolve_head(mkit_dir) {
            Ok(Some(h)) => h,
            Ok(None) => return Err(("no commits yet".to_string(), exit::GENERAL_ERROR)),
            Err(e) => return Err((format!("resolve HEAD: {e}"), exit::GENERAL_ERROR)),
        }
    } else {
        revspec::resolve_revision(store, mkit_dir, end_str)
            .map_err(|e| (format!("{e}"), exit::NOINPUT))?
    };
    // An empty range (`start == end`) has nothing to walk; git rejects it.
    if start == end {
        return Err((
            format!("--reverse: empty revision range '{spec}'"),
            exit::USAGE,
        ));
    }
    Ok((start, end))
}

/// Parse a `git blame -L` style range spec into an inclusive, 1-based
/// `(start, end)` pair validated against `total` (the file's line count).
/// `file` only feeds git-faithful "has only N lines" diagnostics.
///
/// Accepted forms — `<start>,<end>`, `<start>,+<n>` (n lines forward),
/// `<start>,-<n>` (n lines back, ending at `<start>`), `<start>,`,
/// `,<end>`, and a bare `<start>` (treated as `<start>,` → to EOF).
/// An omitted start defaults to line 1; an omitted end to `total`.
/// To match git: an inverted absolute range (`5,2`) is swapped, a low
/// bound past EOF errors `file <f> has only N lines`, and an over-long
/// high bound is clamped to `total`. A zero/negative line number errors
/// `-L invalid line number: <tok>` and a zero offset `-L invalid empty
/// range`.
///
/// Returns `Err(message)` with a git-faithful diagnostic on bad input.
fn parse_line_range(spec: &str, total: usize, file: &str) -> Result<(usize, usize), String> {
    let (start_tok, end_tok) = match spec.split_once(',') {
        Some((s, e)) => (s.trim(), Some(e.trim())),
        None => (spec.trim(), None),
    };

    // Start anchor: defaults to 1 when omitted (the `,<end>` form).
    let start = if start_tok.is_empty() {
        1
    } else {
        parse_one_based(start_tok)?
    };

    // Resolve the inclusive `(lo, hi)` bounds from the end token. git's
    // end forms:
    //   omitted / empty  → to EOF
    //   absolute `<m>`   → swap with start if inverted (`5,2` → 2..5)
    //   `+<n>`           → n lines forward from start (`5,+2` → 5..6)
    //   `-<n>`           → n lines back, *ending* at start (`5,-2` → 4..5),
    //                      the low bound clamped up to line 1
    // A `+0` / `-0` offset is an empty range.
    let (lo, hi) = match end_tok {
        None | Some("") => (start, total),
        Some(tok) if tok.starts_with('+') => (start, start.saturating_add(parse_offset(tok)? - 1)),
        Some(tok) if tok.starts_with('-') => {
            let n = parse_offset(tok)?;
            (start.saturating_sub(n - 1).max(1), start)
        }
        Some(tok) => {
            let m = parse_one_based(tok)?;
            if start > m { (m, start) } else { (start, m) }
        }
    };

    // Empty file: no blamable lines. Checked *after* token validation so
    // an explicit zero / empty-range token reports its own error first,
    // matching git for every form.
    if total == 0 {
        return Err(format!("file {file} has only 0 lines"));
    }

    // git validates the low bound (the actual range start) against EOF for
    // every form — including `-<n>`, whose anchor may itself sit past EOF —
    // and clamps an over-long high bound down to the last line. `lo >= 1`
    // here by construction, so the `lines[lo - 1..hi]` slice is safe.
    if lo > total {
        return Err(format!("file {file} has only {total} lines"));
    }
    Ok((lo, hi.min(total)))
}

/// Parse a single decimal line-number token. Junk (non-integer) gets a
/// clear mkit diagnostic; git instead dumps usage here.
fn parse_line_num(tok: &str) -> Result<usize, String> {
    tok.parse::<usize>()
        .map_err(|_| format!("invalid line number '{tok}' in -L range"))
}

/// Parse a 1-based absolute line number, rejecting `0` and negatives the
/// way git does: a parseable-but-invalid integer (e.g. `0`, `-3`) yields
/// `-L invalid line number: <tok>`, while non-integer junk keeps the
/// clearer [`parse_line_num`] message.
fn parse_one_based(tok: &str) -> Result<usize, String> {
    match tok.parse::<usize>() {
        Ok(n) if n >= 1 => Ok(n),
        // `0`, or (via the usize parse failing) a negative integer.
        _ if tok.parse::<i64>().is_ok() => Err(format!("-L invalid line number: {tok}")),
        _ => Err(format!("invalid line number '{tok}' in -L range")),
    }
}

/// Parse the `<n>` in a `+<n>` / `-<n>` end offset (the leading sign is
/// included in `tok`). A zero offset is git's `-L invalid empty range`.
fn parse_offset(tok: &str) -> Result<usize, String> {
    let n = parse_line_num(&tok[1..])?;
    if n == 0 {
        return Err("-L invalid empty range".to_string());
    }
    Ok(n)
}

/// JSONL output for `--format=json`. One record per source line:
///
/// ```json
/// {"hash":"<64-hex>","line_num":<int>,"author":"<identity>","timestamp":<int>,"text":"<line>"}
/// ```
fn render_json(result: &BlameResult) -> u8 {
    let mut stdout = std::io::stdout().lock();
    for line in &result.lines {
        let _ = stdout.write_all(b"{");
        let _ = write!(
            stdout,
            "\"hash\":\"{}\"",
            format::hex_hash(&line.commit_hash)
        );
        let _ = write!(stdout, ",\"line_num\":{}", line.line_num);
        let _ = write!(
            stdout,
            ",\"author\":\"{}\"",
            format::json_escape(&format::full_identity(&line.author))
        );
        let _ = write!(stdout, ",\"timestamp\":{}", line.timestamp);
        // Line text may contain arbitrary bytes from the source file.
        // Render via lossy UTF-8 — the original bytes are recoverable
        // via the default tab format for callers that care.
        let text = String::from_utf8_lossy(&line.text);
        let _ = write!(stdout, ",\"text\":\"{}\"", format::json_escape(&text));
        let _ = stdout.write_all(b"}\n");
    }
    exit::OK
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    // Semantics here are pinned against real `git blame -L` behavior
    // (verified empirically): inclusive bounds, `+n` = n lines, bare
    // start runs to EOF, inverted ranges swap, over-long ends clamp.

    /// Thin wrapper supplying a fixed filename so the range cases read
    /// cleanly; the filename only colors the "has only N lines" message.
    fn range(spec: &str, total: usize) -> Result<(usize, usize), String> {
        super::parse_line_range(spec, total, "f.txt")
    }

    #[test]
    fn explicit_range_is_inclusive() {
        assert_eq!(range("3,5", 8), Ok((3, 5)));
    }

    #[test]
    fn plus_n_is_n_lines_from_start() {
        // `git blame -L 3,+2` → lines 3,4.
        assert_eq!(range("3,+2", 8), Ok((3, 4)));
        assert_eq!(range("1,+1", 8), Ok((1, 1)));
    }

    #[test]
    fn minus_n_is_n_lines_ending_at_start() {
        // `git blame -L <start>,-<n>` → n lines ending at start, low bound
        // clamped up to line 1. Verified against real git.
        assert_eq!(range("5,-2", 8), Ok((4, 5)));
        assert_eq!(range("8,-3", 8), Ok((6, 8)));
        assert_eq!(range("3,-1", 8), Ok((3, 3)));
        assert_eq!(range("2,-5", 8), Ok((1, 2))); // clamps to line 1
    }

    #[test]
    fn minus_n_anchor_past_eof_still_validates_low_bound() {
        // `12,-3` on an 8-line file → [10,12] → low bound 10 > 8: error,
        // matching git (it validates the range start, not the anchor).
        assert!(range("12,-3", 8).unwrap_err().contains("only 8 lines"));
        // `8,-3` → [6,8] → fine; high bound already within EOF.
        assert_eq!(range("8,-3", 8), Ok((6, 8)));
    }

    #[test]
    fn open_ended_start_runs_to_eof() {
        assert_eq!(range("4,", 8), Ok((4, 8)));
    }

    #[test]
    fn bare_start_runs_to_eof() {
        // `git blame -L 3` → 3..EOF.
        assert_eq!(range("3", 8), Ok((3, 8)));
    }

    #[test]
    fn open_ended_end_starts_at_one() {
        assert_eq!(range(",3", 8), Ok((1, 3)));
    }

    #[test]
    fn inverted_range_is_swapped() {
        // `git blame -L 5,2` → 2..5.
        assert_eq!(range("5,2", 8), Ok((2, 5)));
    }

    #[test]
    fn end_past_eof_is_clamped() {
        assert_eq!(range("3,99", 8), Ok((3, 8)));
    }

    #[test]
    fn start_past_eof_errors() {
        let err = range("99,100", 8).unwrap_err();
        assert!(err.contains("only 8 lines"), "got {err:?}");
    }

    #[test]
    fn empty_file_message_is_git_faithful_for_every_form() {
        // git validates explicit line-number tokens *before* the
        // line-count check, so on an empty file the "has only 0 lines"
        // message applies only to forms without an explicit zero; an
        // explicit `0` (`,0` / `3,0`) still reports the invalid-zero error
        // first. Both halves are pinned against real git.
        for spec in ["1,", "3", "1,3", "2,5"] {
            let err = super::parse_line_range(spec, 0, "empty.txt").unwrap_err();
            assert_eq!(err, "file empty.txt has only 0 lines", "spec {spec:?}");
        }
        for spec in [",0", "3,0"] {
            let err = super::parse_line_range(spec, 0, "empty.txt").unwrap_err();
            assert_eq!(err, "-L invalid line number: 0", "spec {spec:?}");
        }
    }

    #[test]
    fn zero_start_errors() {
        assert_eq!(range("0,5", 8).unwrap_err(), "-L invalid line number: 0");
    }

    #[test]
    fn zero_line_number_uses_git_message() {
        // Regression: `,0` defaults start to 1, parses end 0, then the old
        // inverted-range swap yielded start == 0 and panicked. git reports
        // `-L invalid line number: 0` (exact word order) for every form
        // carrying an explicit zero.
        for spec in [",0", "3,0", "0,0", "0", "0,"] {
            assert_eq!(
                range(spec, 8).unwrap_err(),
                "-L invalid line number: 0",
                "spec {spec:?}"
            );
        }
    }

    #[test]
    fn negative_line_number_uses_git_message() {
        // A parseable-but-invalid integer reports its token, like git's
        // `-L invalid line number: -3` (negatives only valid as `-<n>`
        // *offsets*, handled separately).
        assert_eq!(range("-3,5", 8).unwrap_err(), "-L invalid line number: -3");
    }

    #[test]
    fn zero_offset_is_invalid_empty_range() {
        // git: `+0` / `-0` → `-L invalid empty range`.
        assert_eq!(range("3,+0", 8).unwrap_err(), "-L invalid empty range");
        assert_eq!(range("3,-0", 8).unwrap_err(), "-L invalid empty range");
    }

    #[test]
    fn non_numeric_errors() {
        // True junk keeps mkit's clearer message (git dumps usage here).
        assert!(range("a,b", 8).is_err());
        assert!(range("3,+x", 8).is_err());
    }
}
