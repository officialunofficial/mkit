//! Correspondence and provenance verification for Git bridge state.

use super::*;
use mkit_git_bridge::verify::ShallowVerdict;
use mkit_git_bridge::{import, reconstruct, verify};

mod provenance;

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
            if self.seen.len() >= mkit_core::ops::graph::MAX_REACHABLE {
                self.fail(&id, "audit closure exceeds the traversal limit");
                return;
            }
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
                        self.check_imported(&id, false, &body);
                        self.audit_object(&parsed.tree);
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
                        self.check_imported(&id, true, &body);
                    } else {
                        self.check_bridge_tag(&id, &body);
                    }
                    if let Ok(t) = gitparse::parse_tag(&body) {
                        stack.push(t.object);
                    }
                }
                GitObjKind::Blob | GitObjKind::Tree => {
                    self.seen.remove(&id);
                    self.audit_object(&id);
                }
            }
        }
    }

    /// Check both the importer signature and the exact translation of the raw
    /// Git object. Cache lookup alone is never a correspondence proof.
    fn check_imported(&mut self, id: &Sha1Id, is_tag: bool, body: &[u8]) {
        let raw = read_retained(&self.raw_path(id));
        match raw {
            Ok(raw) => match GitObject::parse_raw(&raw) {
                Some(obj) if obj.id() == *id && obj.body == body => {}
                Some(_) => {
                    self.fail(
                        id,
                        "retained raw bytes hash to a DIFFERENT sha1 or differ from staging",
                    );
                    return;
                }
                None => {
                    self.fail(id, "retained raw bytes are not framed git bytes");
                    return;
                }
            },
            Err(e) => {
                self.fail(id, &format!("retained raw bytes unreadable: {e}"));
                return;
            }
        }
        let Some(twin) = self.twin(id) else { return };
        let Some(pin) = self.pinned else {
            self.fail(id, "imported object but no importer key pinned");
            return;
        };
        let expected = (|| {
            let resolve = |git_id: &Sha1Id| {
                self.inv.get(git_id).copied().ok_or_else(|| {
                    mkit_git_bridge::BridgeError::Integrity("missing child correspondence".into())
                })
            };
            if is_tag {
                let parsed = gitparse::parse_tag(body)
                    .map_err(|e| mkit_git_bridge::BridgeError::Integrity(e.to_string()))?;
                let target = resolve(&parsed.object)?;
                let kind = self
                    .store
                    .read_object(&target)
                    .map_err(|e| mkit_git_bridge::BridgeError::Integrity(e.to_string()))?
                    .object_type();
                import::unsigned_tag(id, body, pin, target, Some(kind)).map(Object::Tag)
            } else {
                let parsed = gitparse::parse_commit(body)
                    .map_err(|e| mkit_git_bridge::BridgeError::Integrity(e.to_string()))?;
                let tree = resolve(&parsed.tree)?;
                let parents = parsed
                    .parents
                    .iter()
                    .map(resolve)
                    .collect::<Result<Vec<_>, _>>()?;
                import::unsigned_commit(id, body, pin, tree, parents).map(Object::Commit)
            }
        })();
        let mut actual = match self.store.read_object(&twin) {
            Ok(o) => o,
            Err(e) => {
                self.fail(id, &format!("mkit twin missing from store: {e}"));
                return;
            }
        };
        match &mut actual {
            Object::Commit(c) if !is_tag => {
                self.check_importer_sig(id, &c.signer, || {
                    mkit_core::sign::verify_commit(c).is_ok()
                });
                c.signature = [0; 64];
            }
            Object::Tag(t) if is_tag => {
                self.check_importer_sig(id, &t.signer, || mkit_core::sign::verify_tag(t).is_ok());
                t.signature = [0; 64];
            }
            _ => self.fail(id, "mkit twin has a different object kind"),
        }
        match expected {
            Ok(expected) if expected == actual => {}
            Ok(_) => self.fail(
                id,
                "signed twin is NOT the translation of the retained Git bytes",
            ),
            Err(e) => self.fail(id, &format!("cannot derive imported correspondence: {e}")),
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
                let edges_match = match &r.object {
                    Object::Commit(c) => gitparse::parse_commit(&obj.body).is_ok_and(|g| {
                        self.inv.get(&g.tree) == Some(&c.tree_hash)
                            && g.parents.len() == c.parents.len()
                            && g.parents
                                .iter()
                                .zip(&c.parents)
                                .all(|(g, m)| self.inv.get(g) == Some(m))
                    }),
                    Object::Tag(t) => gitparse::parse_tag(&obj.body)
                        .is_ok_and(|g| self.inv.get(&g.object) == Some(&t.target)),
                    _ => false,
                };
                if !edges_match {
                    self.fail(
                        id,
                        "Git tree/parent/target edges differ from the signed mkit edges",
                    );
                }
                if let Err(e) = self.store.read_object(&r.hash) {
                    self.fail(id, &format!("reconstructed twin missing from store: {e}"));
                }
            }
            Err(e) => self.fail(id, &format!("reconstruction failed: {e}")),
        }
        self.counts.bridge += 1;
    }

    /// Validate content correspondences from Git bytes, including historic
    /// normalized modes. Traverse iteratively to bound stack use.
    fn audit_object(&mut self, id: &Sha1Id) {
        let mut pending = vec![(*id, 0usize)];
        while let Some((id, depth)) = pending.pop() {
            if depth > import::MAX_TREE_DEPTH
                || self.seen.len() >= mkit_core::ops::graph::MAX_REACHABLE
            {
                self.fail(&id, "audit content exceeds the traversal limit");
                return;
            }
            if !self.seen.insert(id) {
                continue;
            }
            let Some(twin) = self.twin(&id) else { continue };
            let (kind, body) = match self.batch.read(&id) {
                Ok(v) => v,
                Err(e) => {
                    self.fail(&id, &e.to_string());
                    continue;
                }
            };
            let git = GitObject {
                gtype: kind.into(),
                body,
            };
            if git.id() != id {
                self.fail(&id, "staging content hash mismatch");
                continue;
            }
            let derived = match kind {
                GitObjKind::Blob => mkit_core::worktree::hash_file_object(&git.body)
                    .map_err(|e| mkit_git_bridge::BridgeError::Integrity(e.to_string())),
                GitObjKind::Tree => {
                    let result = import::translate_tree_metadata(&id, &git.body, false, |child| {
                        let h = self.inv.get(child).copied().ok_or_else(|| {
                            mkit_git_bridge::BridgeError::Integrity(
                                "missing tree child mapping".into(),
                            )
                        })?;
                        let kind = self
                            .store
                            .read_object(&h)
                            .map_err(|e| mkit_git_bridge::BridgeError::Integrity(e.to_string()))?
                            .object_type();
                        Ok((h, Some(kind)))
                    });
                    if let Ok(entries) = gitparse::parse_tree(&git.body) {
                        for entry in entries {
                            pending.push((entry.id, depth + 1));
                        }
                    }
                    result.and_then(|(tree, _)| {
                        Object::Tree(tree)
                            .id()
                            .map_err(|e| mkit_git_bridge::BridgeError::Integrity(e.to_string()))
                    })
                }
                _ => Err(mkit_git_bridge::BridgeError::Integrity(
                    "non-content Git object in tree".into(),
                )),
            };
            match derived {
                Ok(h) if h == twin => {
                    // Check the stored closure too: a manifest's identity alone
                    // cannot establish that its chunks are present.
                    if kind == GitObjKind::Blob {
                        match mkit_core::worktree::read_blob(self.store, &twin) {
                            Ok(bytes) if bytes == git.body => {}
                            Ok(_) => self.fail(&id, "stored content differs from Git bytes"),
                            Err(e) => self.fail(&id, &e.to_string()),
                        }
                    } else if let Err(e) = self.store.read_object(&twin) {
                        self.fail(&id, &e.to_string());
                    }
                    self.counts.derived += 1;
                }
                Ok(_) => self.fail(&id, "content twin is NOT the translation of the Git bytes"),
                Err(e) => self.fail(&id, &e.to_string()),
            }
        }
    }
}

pub(super) fn run(args: &VerifyArgs) -> CmdResult<()> {
    let cwd = std::env::current_dir().map_err(|e| (format!("cwd: {e}"), exit::NOINPUT))?;
    let (layout, store) = open_repo(&cwd)?;
    let (name, state) = resolve_state(&layout, args.remote_name.as_deref())?;
    let staging = state.join("repo.git");
    if !staging.join("objects").is_dir() {
        return Err((
            format!("state '{name}' has no staging repo to verify against"),
            exit::NOINPUT,
        ));
    }

    let targets = audit_targets(args, &state, &name)?;

    let mut audit = Audit {
        raw_dir: state.join("raw"),
        batch: CatFileBatch::open(&staging).map_err(|e| (e.to_string(), exit::UNAVAILABLE))?,
        store: &store,
        inv: map::load_map_inverse(&state).map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?,
        pinned: map::read_signer(&state).map_err(|e| (e.to_string(), exit::CONFIG_ERROR))?,
        deep: args.fork_audit,
        failures: Vec::new(),
        counts: Counts::default(),
        seen: HashSet::new(),
    };

    let source = if audit.pinned.is_some() {
        let version = std::fs::read_to_string(state.join("import-spec"))
            .map_err(|e| (format!("read import-spec: {e}"), exit::DATAERR))?;
        if version.trim() != import::IMPORT_SPEC_VERSION.to_string() {
            return Err((
                "unsupported import-spec version for audit".into(),
                exit::DATAERR,
            ));
        }
        std::fs::read_to_string(state.join("source"))
            .map_err(|e| (format!("read import source: {e}"), exit::DATAERR))?
            .trim()
            .to_owned()
    } else {
        String::new()
    };

    let mut stderr = std::io::stderr().lock();
    for (ref_name, tip, origin) in &targets {
        audit.walk(tip);
        // A required claim must establish the exact source/ref/head relation,
        // not just be a file in the head's attestation directory.
        if audit.raw_path(tip).exists()
            && let (Some(twin), Some(pin)) = (audit.inv.get(tip).copied(), audit.pinned)
        {
            let context = provenance::Context {
                layout: &layout,
                store: &store,
                source: &source,
                remote: &name,
                signer: pin,
            };
            if !context.matches(ref_name, tip, &twin) {
                audit.fail(
                    tip,
                    "no verified git-import/v1 attestation matches this head, ref and source",
                );
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
    if audit.failures.is_empty() && c.unsigned > 0 {
        // §10: an all-zero mkit-signature FAILS both verification
        // modes — reported as unsigned (never "tampered"), but never
        // as success either.
        return Err((
            format!("{} unsigned object(s) ({summary})", c.unsigned),
            exit::DATAERR,
        ));
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

fn audit_targets(
    args: &VerifyArgs,
    state: &Path,
    name: &str,
) -> CmdResult<Vec<(String, Sha1Id, &'static str)>> {
    // Refs to audit: explicit, else everything recorded (both
    // directions; in a fork dir the same name may have two tips).
    let mut targets: Vec<(String, Sha1Id, &'static str)> = Vec::new();
    let recorded_export =
        map::load_ref_state(state).map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?;
    let recorded_import =
        map::load_import_ref_state(state).map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?;
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

    Ok(targets)
}

fn read_retained(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let limit = mkit_git_bridge::gitsrc::MAX_OBJECT_BYTES + 64;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other(
            "retained raw bytes exceed the object limit",
        ));
    }
    Ok(bytes)
}
