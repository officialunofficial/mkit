//! `mkit git verify` / `status` / `format-patch` (feature
//! `git-bridge`): bridge-state inspection and audit.
//!
//! `verify` re-checks a state dir's staging mirror against the local
//! store: bridge-translated objects shallow-verify (SPEC-GIT-BRIDGE
//! §10) and must reconstruct to their mapped mkit twin; imported
//! objects must have retained raw bytes hashing to their sha1 and a
//! twin signed by the pinned importer key (SPEC-GIT-IMPORT §4).
//! `--fork-audit` adds §14.3 step 3: every tree/blob referenced by a
//! bridge commit re-derives from its mkit twin and must reproduce the
//! exact sha1.
//!
//! `format-patch` renders native commits as `git am`-able mbox
//! patches, so contributions can flow to a git upstream even without
//! a writable fork (the no-export collaboration path).

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use mkit_core::Hash;
use mkit_core::object::{Commit, Object};
use mkit_core::store::ObjectStore;
use mkit_git_bridge::gitobj::{GitObject, GitType, Sha1Id, sha1_hex};
use mkit_git_bridge::gitsrc::{CatFileBatch, GitObjKind};
use mkit_git_bridge::verify::ShallowVerdict;
use mkit_git_bridge::{author, gitparse, map, reconstruct, translate, verify};

use super::revspec;
use crate::exit;

type CmdResult<T> = Result<T, (String, u8)>;

const ATTESTATIONS_REF: &str = "refs/mkit/attestations";

#[derive(Debug, Parser)]
pub(super) struct VerifyArgs {
    /// Bridge state name under `.mkit/git/`. Optional when exactly
    /// one state dir exists.
    #[arg(long = "remote-name", value_name = "NAME")]
    pub remote_name: Option<String>,
    /// Full fork audit (SPEC-GIT-BRIDGE §14.3): additionally
    /// re-derive every tree/blob referenced by bridge commits from
    /// its mkit twin and require the exact sha1.
    #[arg(long = "fork-audit")]
    pub fork_audit: bool,
    /// Verify only these refs (full names). Default: every ref
    /// recorded in the state dir.
    #[arg(long = "ref", value_name = "REF")]
    pub refs: Vec<String>,
}

#[derive(Debug, Parser)]
pub(super) struct StatusArgs {}

#[derive(Debug, Parser)]
pub(super) struct FormatPatchArgs {
    /// Commit range `A..B` (or a single rev, meaning `<rev>..HEAD`).
    pub range: String,
    /// Write patch files into this directory (default: current dir).
    #[arg(short = 'o', long = "output-directory", value_name = "DIR")]
    pub output: Option<PathBuf>,
    /// Print all patches to stdout instead of writing files.
    #[arg(long)]
    pub stdout: bool,
}

// ─── shared state-dir resolution ────────────────────────────────────

fn state_names(mkit_dir: &Path) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(rd) = std::fs::read_dir(mkit_dir.join("git")) {
        for e in rd.flatten() {
            if e.path().is_dir()
                && let Some(name) = e.file_name().to_str()
            {
                names.push(name.to_owned());
            }
        }
    }
    names.sort();
    names
}

fn resolve_state(mkit_dir: &Path, remote_name: Option<&str>) -> CmdResult<(String, PathBuf)> {
    if let Some(name) = remote_name {
        let state = map::state_dir(mkit_dir, name).map_err(|e| (e.to_string(), exit::USAGE))?;
        if !state.is_dir() {
            return Err((format!("no bridge state for '{name}'"), exit::NOINPUT));
        }
        return Ok((name.to_owned(), state));
    }
    let names = state_names(mkit_dir);
    match names.as_slice() {
        [] => Err((
            "no git bridge state (run `mkit git import` or `mkit git export` first)".into(),
            exit::NOINPUT,
        )),
        [one] => Ok((one.clone(), mkit_dir.join("git").join(one))),
        many => Err((
            format!(
                "multiple bridge states ({}); pick one with --remote-name",
                many.join(", ")
            ),
            exit::USAGE,
        )),
    }
}

fn open_repo(cwd: &Path) -> CmdResult<(PathBuf, ObjectStore)> {
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    if !mkit_dir.is_dir() {
        return Err(("not a mkit repository".into(), exit::USAGE));
    }
    let store = ObjectStore::open(cwd).map_err(|e| (format!("open store: {e}"), exit::NOINPUT))?;
    Ok((mkit_dir, store))
}

// ─── mkit git verify ────────────────────────────────────────────────

#[derive(Default)]
struct Counts {
    bridge: usize,
    unsigned: usize,
    imported: usize,
    derived: usize,
}

struct Audit<'a> {
    raw_dir: PathBuf,
    batch: CatFileBatch,
    store: &'a ObjectStore,
    /// sha1 → mkit twin (both directions of the unified map).
    inv: HashMap<Sha1Id, Hash>,
    /// mkit → sha1, for tree re-derivation child resolution.
    fwd: HashMap<Hash, Sha1Id>,
    pinned: Option<[u8; 32]>,
    deep: bool,
    failures: Vec<String>,
    counts: Counts,
    seen: HashSet<Sha1Id>,
}

impl Audit<'_> {
    fn fail(&mut self, id: &Sha1Id, why: &str) {
        self.failures.push(format!("{} {why}", sha1_hex(id)));
    }

    fn twin(&mut self, id: &Sha1Id) -> Option<Hash> {
        let t = self.inv.get(id).copied();
        if t.is_none() {
            self.fail(id, "no mkit twin recorded in the map");
        }
        t
    }

    fn raw_path(&self, id: &Sha1Id) -> PathBuf {
        let hex = sha1_hex(id);
        self.raw_dir.join(&hex[..2]).join(&hex[2..])
    }

    /// Walk all commits reachable from `tip` in the staging repo,
    /// checking each (and, with `--fork-audit`, the content closure
    /// of every bridge commit).
    fn walk(&mut self, tip: &Sha1Id) {
        let mut stack = vec![*tip];
        while let Some(id) = stack.pop() {
            if !self.seen.insert(id) {
                continue;
            }
            let (kind, body) = match self.batch.read(&id) {
                Ok(v) => v,
                Err(e) => {
                    self.fail(&id, &format!("unreadable in staging: {e}"));
                    continue;
                }
            };
            match kind {
                GitObjKind::Commit => {
                    let parsed = match gitparse::parse_commit(&body) {
                        Ok(p) => p,
                        Err(e) => {
                            self.fail(&id, &format!("unparsable commit: {e}"));
                            continue;
                        }
                    };
                    if self.raw_path(&id).exists() {
                        self.check_imported(&id, false);
                    } else {
                        self.check_bridge_commit(&id, &body);
                        if self.deep {
                            self.audit_object(&parsed.tree);
                        }
                    }
                    for p in &parsed.parents {
                        stack.push(*p);
                    }
                }
                GitObjKind::Tag => {
                    if self.raw_path(&id).exists() {
                        self.check_imported(&id, true);
                    } else {
                        self.check_bridge_tag(&id, &body);
                    }
                    if let Ok(t) = gitparse::parse_tag(&body) {
                        stack.push(t.object);
                    }
                }
                GitObjKind::Blob | GitObjKind::Tree => {
                    // Refs at blobs/trees are not bridge state; the
                    // content closure is covered by --fork-audit.
                }
            }
        }
    }

    /// SPEC-GIT-IMPORT §4 / SPEC-GIT-BRIDGE §14.3 step 2: retained
    /// raw bytes must hash to the sha1, and the mkit twin must be
    /// signed by the pinned importer key.
    fn check_imported(&mut self, id: &Sha1Id, is_tag: bool) {
        match std::fs::read(self.raw_path(id)) {
            Ok(raw) => match GitObject::parse_raw(&raw) {
                Some(obj) if obj.id() == *id => {}
                Some(_) => self.fail(id, "retained raw bytes hash to a DIFFERENT sha1"),
                None => self.fail(id, "retained raw bytes are not framed git bytes"),
            },
            Err(e) => self.fail(id, &format!("retained raw bytes unreadable: {e}")),
        }
        let Some(twin) = self.twin(id) else { return };
        match self.store.read_object(&twin) {
            Ok(Object::Commit(c)) if !is_tag => self
                .check_importer_sig(id, &c.signer, || mkit_core::sign::verify_commit(&c).is_ok()),
            Ok(Object::Tag(t)) if is_tag => {
                let signer = t.signer;
                self.check_importer_sig(id, &signer, || mkit_core::sign::verify_tag(&t).is_ok());
            }
            Ok(_) => self.fail(id, "mkit twin has a different object kind"),
            Err(e) => self.fail(id, &format!("mkit twin missing from store: {e}")),
        }
        self.counts.imported += 1;
    }

    fn check_importer_sig(&mut self, id: &Sha1Id, signer: &[u8; 32], ok: impl FnOnce() -> bool) {
        match self.pinned {
            Some(pin) if pin != *signer => {
                self.fail(id, "twin signer is NOT the pinned importer key");
            }
            None => self.fail(id, "imported object but no importer key pinned"),
            Some(_) => {
                if !ok() {
                    self.fail(id, "importer signature does not verify");
                }
            }
        }
    }

    /// §10 shallow verification + the twin/map correspondence.
    fn check_bridge_commit(&mut self, id: &Sha1Id, body: &[u8]) {
        let obj = GitObject {
            gtype: GitType::Commit,
            body: body.to_vec(),
        };
        self.check_bridge_obj(id, &obj, reconstruct::reconstruct_commit);
    }

    fn check_bridge_tag(&mut self, id: &Sha1Id, body: &[u8]) {
        let obj = GitObject {
            gtype: GitType::Tag,
            body: body.to_vec(),
        };
        self.check_bridge_obj(id, &obj, reconstruct::reconstruct_tag);
    }

    fn check_bridge_obj(
        &mut self,
        id: &Sha1Id,
        obj: &GitObject,
        rec: impl Fn(&[u8]) -> Result<reconstruct::Reconstructed, mkit_git_bridge::BridgeError>,
    ) {
        match verify::shallow_verify(obj) {
            Ok(ShallowVerdict::Verified) => {}
            Ok(ShallowVerdict::Unsigned) => self.counts.unsigned += 1,
            Ok(ShallowVerdict::Failed) => self.fail(id, "embedded signature does NOT verify"),
            Err(e) => {
                self.fail(id, &format!("not bridge-shaped: {e}"));
                return;
            }
        }
        match rec(&obj.body) {
            Ok(r) => {
                if let Some(twin) = self.twin(id)
                    && r.hash != twin
                {
                    self.fail(id, "reconstructs to a hash OTHER than its mapped twin");
                }
                if let Err(e) = self.store.read_object(&r.hash) {
                    self.fail(id, &format!("reconstructed twin missing from store: {e}"));
                }
            }
            Err(e) => self.fail(id, &format!("reconstruction failed: {e}")),
        }
        self.counts.bridge += 1;
    }

    /// §14.3 step 3: re-derive the git bytes for `id` from its mkit
    /// twin and require the exact sha1; recurse through trees.
    fn audit_object(&mut self, id: &Sha1Id) {
        if !self.seen.insert(*id) {
            return;
        }
        let Some(twin) = self.twin(id) else { return };
        let obj = match self.store.read_object(&twin) {
            Ok(o) => o,
            Err(e) => {
                self.fail(id, &format!("mkit twin missing from store: {e}"));
                return;
            }
        };
        let derived = match &obj {
            Object::Blob(b) => Ok(translate::translate_blob(&b.data)),
            Object::ChunkedBlob(m) => translate::translate_chunked(&twin, m, self.store),
            Object::Tree(t) => {
                let fwd = &self.fwd;
                translate::translate_tree(t, &|h| fwd.get(h).copied())
            }
            _ => {
                self.fail(id, "content position holds a non-content mkit twin");
                return;
            }
        };
        match derived {
            Ok(g) if g.id() == *id => self.counts.derived += 1,
            Ok(_) => self.fail(id, "re-derivation produced a DIFFERENT sha1"),
            Err(e) => {
                self.fail(id, &format!("re-derivation failed: {e}"));
                return;
            }
        }
        if let Object::Tree(t) = &obj {
            for e in &t.entries {
                if let Some(child) = self.fwd.get(&e.object_hash).copied() {
                    self.audit_object(&child);
                } else {
                    self.fail(
                        id,
                        &format!(
                            "tree entry {:?} has no recorded sha1",
                            String::from_utf8_lossy(&e.name)
                        ),
                    );
                }
            }
        }
    }
}

pub(super) fn verify(args: &VerifyArgs) -> CmdResult<()> {
    let cwd = std::env::current_dir().map_err(|e| (format!("cwd: {e}"), exit::NOINPUT))?;
    let (mkit_dir, store) = open_repo(&cwd)?;
    let (name, state) = resolve_state(&mkit_dir, args.remote_name.as_deref())?;
    let staging = state.join("repo.git");
    if !staging.join("objects").is_dir() {
        return Err((
            format!("state '{name}' has no staging repo to verify against"),
            exit::NOINPUT,
        ));
    }

    // Refs to audit: explicit, else everything recorded (both
    // directions; in a fork dir the same name may have two tips).
    let mut targets: Vec<(String, Sha1Id, &'static str)> = Vec::new();
    let recorded_export =
        map::load_ref_state(&state).map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?;
    let recorded_import =
        map::load_import_ref_state(&state).map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?;
    for s in &recorded_export {
        if s.ref_name != ATTESTATIONS_REF {
            targets.push((s.ref_name.clone(), s.git_id, "exported"));
        }
    }
    for s in &recorded_import {
        if !targets
            .iter()
            .any(|(n, id, _)| *n == s.ref_name && *id == s.git_id)
        {
            targets.push((s.ref_name.clone(), s.git_id, "imported"));
        }
    }
    if !args.refs.is_empty() {
        targets.retain(|(n, _, _)| args.refs.iter().any(|r| r == n));
        for r in &args.refs {
            if !targets.iter().any(|(n, _, _)| n == r) {
                return Err((format!("{r}: not recorded in state '{name}'"), exit::USAGE));
            }
        }
    }
    if targets.is_empty() {
        return Err((format!("state '{name}' records no refs"), exit::NOINPUT));
    }

    let mut audit = Audit {
        raw_dir: state.join("raw"),
        batch: CatFileBatch::open(&staging).map_err(|e| (e.to_string(), exit::UNAVAILABLE))?,
        store: &store,
        inv: map::load_map_inverse(&state).map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?,
        fwd: map::load_map(&state).map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?,
        pinned: map::read_signer(&state).map_err(|e| (e.to_string(), exit::CONFIG_ERROR))?,
        deep: args.fork_audit,
        failures: Vec::new(),
        counts: Counts::default(),
        seen: HashSet::new(),
    };

    let mut stderr = std::io::stderr().lock();
    for (ref_name, tip, origin) in &targets {
        audit.walk(tip);
        // §14.3 step 2, head scope: an imported tip must carry its
        // git-import/v1 attestation (full signature verification is
        // `mkit verify-attest`'s job; the audit checks the claim
        // EXISTS for the recorded twin).
        if args.fork_audit
            && audit.raw_path(tip).exists()
            && let Some(twin) = audit.inv.get(tip).copied()
        {
            let attested =
                mkit_attest::store::list(&mkit_dir, &twin).is_ok_and(|v| !v.is_empty());
            if !attested {
                audit.failures.push(format!(
                    "{} imported head has no git-import/v1 attestation recorded",
                    sha1_hex(tip)
                ));
            }
        }
        let _ = writeln!(stderr, "verified {ref_name} ({origin}, {})", sha1_hex(tip));
    }
    let c = &audit.counts;
    let mut summary = format!(
        "{} bridge-translated ({} unsigned), {} imported-vouched",
        c.bridge, c.unsigned, c.imported
    );
    if args.fork_audit {
        let _ = write!(summary, ", {} content-derived", c.derived);
    }
    if audit.failures.is_empty() {
        let _ = writeln!(stderr, "ok: {summary}");
        Ok(())
    } else {
        for f in &audit.failures {
            let _ = writeln!(stderr, "FAIL {f}");
        }
        Err((
            format!(
                "{} object(s) failed verification ({summary})",
                audit.failures.len()
            ),
            exit::DATAERR,
        ))
    }
}

// ─── mkit git status ────────────────────────────────────────────────

pub(super) fn status(_args: &StatusArgs) -> CmdResult<()> {
    let cwd = std::env::current_dir().map_err(|e| (format!("cwd: {e}"), exit::NOINPUT))?;
    let (mkit_dir, _store) = open_repo(&cwd)?;
    let names = state_names(&mkit_dir);
    let mut out = std::io::stdout().lock();
    if names.is_empty() {
        let _ = writeln!(
            out,
            "no git bridge state (run `mkit git import` or `mkit git export` first)"
        );
        return Ok(());
    }
    for name in &names {
        let state = mkit_dir.join("git").join(name);
        let direction = map::read_direction(&state)
            .ok()
            .flatten()
            .map_or("unknown", |d| d.as_str());
        let _ = writeln!(out, "{name}  direction={direction}");
        for (file, label) in [("source", "source"), ("dest", "dest")] {
            if let Ok(v) = std::fs::read_to_string(state.join(file)) {
                let _ = writeln!(out, "  {label}: {}", v.trim());
            }
        }
        if let Ok(Some(key)) = map::read_signer(&state) {
            let _ = writeln!(
                out,
                "  importer key: {}… (pinned)",
                &mkit_git_bridge::gitobj::bytes_hex(&key)[..16]
            );
        }
        for s in map::load_import_ref_state(&state).unwrap_or_default() {
            let _ = writeln!(
                out,
                "  tracking {} @ {} (import)",
                s.ref_name,
                &sha1_hex(&s.git_id)[..12]
            );
        }
        for s in map::load_ref_state(&state).unwrap_or_default() {
            if s.ref_name == ATTESTATIONS_REF {
                continue;
            }
            let _ = writeln!(
                out,
                "  exported {} @ {} (lease)",
                s.ref_name,
                &sha1_hex(&s.git_id)[..12]
            );
        }
        let staging = if state.join("repo.git/objects").is_dir() {
            "ok"
        } else {
            "missing"
        };
        let _ = writeln!(out, "  staging: {staging}");
    }
    Ok(())
}

// ─── mkit git format-patch ──────────────────────────────────────────

/// A patch series: oldest-first hashes, the commit set, and the
/// resolved `A`/`B` endpoint spellings (for messages).
type Series = (Vec<Hash>, HashMap<Hash, Commit>, String, String);

/// Resolve `A..B` (or `<rev>` = `<rev>..HEAD`) to the commit set and
/// its oldest-first topological order (parents before children,
/// timestamp as the tiebreak).
fn range_commits(store: &ObjectStore, mkit_dir: &Path, range: &str) -> CmdResult<Series> {
    let (a, b) = match range.split_once("..") {
        Some((a, b)) => (
            a.to_owned(),
            if b.is_empty() {
                "HEAD".to_owned()
            } else {
                b.to_owned()
            },
        ),
        None => (range.to_owned(), "HEAD".to_owned()),
    };
    let resolve = |spec: &str| -> CmdResult<Hash> {
        revspec::resolve_revision(store, mkit_dir, spec)
            .map_err(|e| (format!("{spec}: {e}"), exit::DATAERR))
    };
    let exclude_tip = peel(store, resolve(&a)?);
    let include_tip = peel(store, resolve(&b)?);

    // Ancestors of A drop out of the patch series.
    let mut excluded: HashSet<Hash> = HashSet::new();
    let mut stack = vec![exclude_tip];
    while let Some(h) = stack.pop() {
        if !excluded.insert(h) {
            continue;
        }
        if let Ok(Object::Commit(c)) = store.read_object(&h) {
            stack.extend(c.parents.iter().copied());
        }
    }
    let mut commits: HashMap<Hash, Commit> = HashMap::new();
    let mut stack = vec![include_tip];
    while let Some(h) = stack.pop() {
        if excluded.contains(&h) || commits.contains_key(&h) {
            continue;
        }
        let c = match store.read_object(&h) {
            Ok(Object::Commit(c)) => c,
            Ok(_) => {
                return Err((
                    format!("not a commit: {}", mkit_core::to_hex(&h)),
                    exit::DATAERR,
                ));
            }
            Err(e) => {
                return Err((
                    format!("read {}: {e}", mkit_core::to_hex(&h)),
                    exit::DATAERR,
                ));
            }
        };
        stack.extend(c.parents.iter().copied());
        commits.insert(h, c);
    }

    let mut remaining: Vec<Hash> = commits.keys().copied().collect();
    remaining.sort_by_key(|h| (commits[h].timestamp, *h));
    let mut ordered: Vec<Hash> = Vec::with_capacity(remaining.len());
    let mut placed: HashSet<Hash> = HashSet::new();
    while !remaining.is_empty() {
        let before = ordered.len();
        remaining.retain(|h| {
            let ready = commits[h]
                .parents
                .iter()
                .all(|p| placed.contains(p) || !commits.contains_key(p));
            if ready {
                ordered.push(*h);
                placed.insert(*h);
            }
            !ready
        });
        if ordered.len() == before {
            return Err(("commit graph cycle (corrupt store?)".into(), exit::DATAERR));
        }
    }
    Ok((ordered, commits, a, b))
}

pub(super) fn format_patch(args: &FormatPatchArgs) -> CmdResult<()> {
    let cwd = std::env::current_dir().map_err(|e| (format!("cwd: {e}"), exit::NOINPUT))?;
    let (mkit_dir, store) = open_repo(&cwd)?;
    let (ordered, commits, a, b) = range_commits(&store, &mkit_dir, &args.range)?;

    let mut skipped_merges = 0usize;
    let series: Vec<&Hash> = ordered
        .iter()
        .filter(|h| {
            let m = commits[*h].parents.len() > 1;
            if m {
                skipped_merges += 1;
            }
            !m
        })
        .collect();
    if skipped_merges > 0 {
        eprintln!("warning: {skipped_merges} merge commit(s) skipped (patches are linear)");
    }
    if series.is_empty() {
        eprintln!("no commits in range {a}..{b}");
        return Ok(());
    }

    let total = series.len();
    let outdir = args.output.clone().unwrap_or_else(|| cwd.clone());
    if !args.stdout {
        std::fs::create_dir_all(&outdir)
            .map_err(|e| (format!("create {}: {e}", outdir.display()), exit::CANTCREAT))?;
    }
    let mut stdout = std::io::stdout().lock();
    for (i, h) in series.iter().enumerate() {
        let c = &commits[*h];
        let text = render_patch(&store, h, c, i + 1, total)?;
        if args.stdout {
            stdout
                .write_all(text.as_bytes())
                .map_err(|e| (format!("write: {e}"), exit::GENERAL_ERROR))?;
        } else {
            let name = format!("{:04}-{}.patch", i + 1, slug(&subject_of(c)));
            let path = outdir.join(&name);
            std::fs::write(&path, &text)
                .map_err(|e| (format!("write {}: {e}", path.display()), exit::CANTCREAT))?;
            let _ = writeln!(stdout, "{name}");
        }
    }
    Ok(())
}

fn peel(store: &ObjectStore, mut h: Hash) -> Hash {
    while let Ok(Object::Tag(t)) = store.read_object(&h) {
        h = t.target;
    }
    h
}

fn subject_of(c: &Commit) -> String {
    let msg = String::from_utf8_lossy(&c.message);
    msg.lines().next().unwrap_or("").to_owned()
}

fn slug(subject: &str) -> String {
    let mut out = String::new();
    for ch in subject.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let trimmed = out.trim_end_matches('-');
    let cut = trimmed.chars().take(52).collect::<String>();
    if cut.is_empty() { "patch".into() } else { cut }
}

fn render_patch(
    store: &ObjectStore,
    hash: &Hash,
    c: &Commit,
    n: usize,
    total: usize,
) -> CmdResult<String> {
    let mut out = String::new();
    // mbox separator: git's fixed magic date; the id field is the
    // mkit commit hash (git only needs the "From " prefix).
    let _ = writeln!(
        out,
        "From {} Mon Sep 17 00:00:00 2001",
        mkit_core::to_hex(hash)
    );
    let _ = writeln!(out, "From: {}", from_header(c));
    let _ = writeln!(out, "Date: {}", rfc2822(c.timestamp));
    let msg = String::from_utf8_lossy(&c.message);
    let mut lines = msg.lines();
    let subject = lines.next().unwrap_or("");
    if total > 1 {
        let _ = write!(out, "Subject: [PATCH {n}/{total}] {subject}\n\n");
    } else {
        let _ = write!(out, "Subject: [PATCH] {subject}\n\n");
    }
    let body: Vec<&str> = lines.skip_while(|l| l.is_empty()).collect();
    if !body.is_empty() {
        out.push_str(&body.join("\n"));
        out.push('\n');
    }
    out.push_str("---\n");

    let old_tree = match c.parents.first() {
        Some(p) => match store.read_object(p) {
            Ok(Object::Commit(pc)) => Some(pc.tree_hash),
            _ => None,
        },
        None => None,
    };
    let diff = mkit_core::ops::diff::diff_trees(store, old_tree, Some(c.tree_hash))
        .map_err(|e| (format!("diff: {e}"), exit::GENERAL_ERROR))?;
    let mut buf: Vec<u8> = Vec::new();
    for e in &diff.entries {
        let mut one: Vec<u8> = Vec::new();
        super::diff::emit_entry_patch(&mut one, store, e).map_err(|m| (m, exit::GENERAL_ERROR))?;
        // `git am` cannot apply the textual "Binary files differ"
        // notice (and we don't emit git's base85 binary literals), so
        // a series touching binary content would fail at the
        // MAINTAINER's end — refuse here instead.
        if one
            .split(|&b| b == b'\n')
            .any(|l| l.starts_with(b"Binary files "))
        {
            return Err((
                format!(
                    "{}: binary change in commit {} — format-patch emits text \
                     patches only; use `mkit git export` for binary content",
                    e.path,
                    &mkit_core::to_hex(hash)[..12]
                ),
                exit::DATAERR,
            ));
        }
        buf.extend_from_slice(&one);
    }
    out.push_str(&String::from_utf8_lossy(&buf));
    out.push_str("-- \nmkit git format-patch\n\n");
    Ok(out)
}

/// `From:` header. An opaque identity that already looks like a git
/// person ("Name <email>") passes through; anything else renders the
/// bridge's display name with its sentinel email (matching what
/// `mkit git export` would emit).
fn from_header(c: &Commit) -> String {
    if let Ok(s) = std::str::from_utf8(&c.author.bytes)
        && c.author.kind == mkit_core::object::IdentityKind::Opaque
        && s.contains('<')
        && s.ends_with('>')
        && !s.chars().any(char::is_control)
    {
        return s.to_owned();
    }
    format!(
        "{} <{}>",
        author::display_name(&c.author),
        author::BRIDGE_EMAIL
    )
}

/// RFC 2822 date from a unix timestamp (UTC).
fn rfc2822(ts: u64) -> String {
    const WDAY: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    #[allow(clippy::cast_possible_wrap)] // ts/86400 < i64::MAX
    let days = (ts / 86_400) as i64;
    let secs = ts % 86_400;
    let (y, m, d) = civil_from_days(days);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // rem_euclid(7) ∈ 0..7
    let wd = ((days + 4).rem_euclid(7)) as usize; // 1970-01-01 = Thu
    format!(
        "{}, {} {} {} {:02}:{:02}:{:02} +0000",
        WDAY[wd],
        d,
        MON[(m - 1) as usize],
        y,
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Days-since-epoch → (year, month, day). Howard Hinnant's
/// `civil_from_days`, exact over the proleptic Gregorian calendar.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // d ∈ 1..=31, m ∈ 1..=12
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc2822_known_dates() {
        assert_eq!(rfc2822(0), "Thu, 1 Jan 1970 00:00:00 +0000");
        // date -u -r 1700000000 → Tue Nov 14 22:13:20 UTC 2023
        assert_eq!(rfc2822(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 +0000");
        // Leap-day check: 2024-02-29 12:00:00 UTC = 1709208000
        assert_eq!(rfc2822(1_709_208_000), "Thu, 29 Feb 2024 12:00:00 +0000");
    }

    #[test]
    fn slugs() {
        assert_eq!(slug("Add foo, bar & baz!"), "Add-foo-bar-baz");
        assert_eq!(slug("???"), "patch");
    }
}
