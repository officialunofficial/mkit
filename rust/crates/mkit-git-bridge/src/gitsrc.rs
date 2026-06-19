//! Reading objects out of a local git repository
//! (SPEC-GIT-IMPORT §2): one long-lived `git cat-file --batch` child
//! for object bytes, plus `rev-list` / `ls-refs` / config plumbing.
//!
//! git owns wire protocol, auth, and pack storage; this module owns
//! only the subprocess conversation. All inputs to the child are
//! 40-hex object ids (never user strings), so the argv/stdin surface
//! is injection-free by construction.

use crate::error::BridgeError;
use crate::gitobj::{GitType, Sha1Id, sha1_from_hex, sha1_hex};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// Refuse single objects above this size up front (the mkit per-file
/// cap; SPEC-GIT-IMPORT §3.1) so a hostile upstream can't make us
/// buffer arbitrarily.
pub const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

/// Base `git` command against `repo` with the bridge's subprocess
/// hygiene applied: `GIT_TERMINAL_PROMPT=0` (a credential prompt must
/// fail cleanly, never hang a CI run) and user hooks neutralized via
/// `core.hooksPath` pointed at the platform null device (a
/// `core.hooksPath` in user config must not run arbitrary hooks
/// against the private staging mirror). User/system gitconfig is
/// otherwise INHERITED on purpose: credential helpers, `core.sshCommand`,
/// and proxy settings live there and remote fetch/push need them —
/// none of it can affect translation output (mkit generates every
/// object byte itself).
#[must_use]
pub fn git_command(repo: &Path) -> Command {
    let mut c = Command::new("git");
    c.arg("-C").arg(repo);
    apply_hygiene(&mut c);
    c
}

/// Apply the subprocess hygiene (see [`git_command`]) to a caller-built
/// `git` command without a `-C <repo>` (e.g. a bare `git --version`
/// probe).
pub fn apply_hygiene(c: &mut Command) {
    c.env("GIT_TERMINAL_PROMPT", "0");
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    c.arg("-c").arg(format!("core.hooksPath={null}"));
}

/// The git object type names `cat-file --batch` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitObjKind {
    Blob,
    Tree,
    Commit,
    Tag,
}

impl GitObjKind {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "blob" => Self::Blob,
            "tree" => Self::Tree,
            "commit" => Self::Commit,
            "tag" => Self::Tag,
            _ => return None,
        })
    }
}

impl From<GitObjKind> for GitType {
    fn from(kind: GitObjKind) -> Self {
        match kind {
            GitObjKind::Blob => Self::Blob,
            GitObjKind::Tree => Self::Tree,
            GitObjKind::Commit => Self::Commit,
            GitObjKind::Tag => Self::Tag,
        }
    }
}

/// A long-lived `git cat-file --batch` child bound to one repository.
///
/// Batch protocol (verified against git ≥ 2.30): write `<oid>\n` to
/// stdin; read `<oid> <type> <size>\n`, exactly `<size>` body bytes,
/// then one trailing `\n`. Unknown ids answer `<oid> missing\n`
/// (no body — the stream stays clean). Any OTHER read error leaves
/// the stream desynchronized: treat it as fatal for this batch.
#[derive(Debug)]
pub struct CatFileBatch {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    repo: PathBuf,
}

impl CatFileBatch {
    /// Spawn the child against `repo` (a `.git`/bare directory).
    pub fn open(repo: &Path) -> Result<Self, BridgeError> {
        let mut child = git_command(repo)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| BridgeError::Source(format!("spawn git cat-file: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| BridgeError::Source("cat-file stdin unavailable".into()))?;
        let stdout = child
            .stdout
            .take()
            .map(BufReader::new)
            .ok_or_else(|| BridgeError::Source("cat-file stdout unavailable".into()))?;
        Ok(Self {
            child,
            stdin,
            stdout,
            repo: repo.to_path_buf(),
        })
    }

    /// Read one object's kind + body bytes.
    pub fn read(&mut self, id: &Sha1Id) -> Result<(GitObjKind, Vec<u8>), BridgeError> {
        let hex = sha1_hex(id);
        self.stdin
            .write_all(format!("{hex}\n").as_bytes())
            .and_then(|()| self.stdin.flush())
            .map_err(|e| BridgeError::Source(format!("cat-file write: {e}")))?;

        let mut header = String::new();
        self.stdout
            .read_line(&mut header)
            .map_err(|e| BridgeError::Source(format!("cat-file read: {e}")))?;
        let header = header.trim_end();
        let mut parts = header.split(' ');
        let (Some(echo), Some(kind_or_missing)) = (parts.next(), parts.next()) else {
            return Err(BridgeError::Source(format!(
                "cat-file: malformed header {header:?} (repo {})",
                self.repo.display()
            )));
        };
        if kind_or_missing == "missing" {
            return Err(BridgeError::Source(format!("object {echo} missing")));
        }
        let kind = GitObjKind::from_name(kind_or_missing)
            .ok_or_else(|| BridgeError::Source(format!("cat-file: unknown type {header:?}")))?;
        let size: u64 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| BridgeError::Source(format!("cat-file: bad size {header:?}")))?;
        if size > MAX_OBJECT_BYTES {
            // Drain body + trailing newline so the batch stream stays
            // synchronized (callers keep using this child), and refuse
            // PER-REF: one oversized object must not abort the whole
            // import (SPEC-GIT-IMPORT §3.1).
            // checked: a u64::MAX size would wrap `size + 1` to 0 in
            // release, skip the drain entirely, and silently desync
            // the batch stream — every later read returns wrong bytes.
            let Some(mut remaining) = size.checked_add(1) else {
                return Err(BridgeError::Source(format!(
                    "object {echo} reports an absurd size ({size}); cat-file \
                     stream untrustworthy"
                )));
            };
            let mut sink_buf = vec![0u8; 64 * 1024];
            while remaining > 0 {
                let take = remaining.min(sink_buf.len() as u64);
                #[allow(clippy::cast_possible_truncation)] // take <= 64 KiB
                let take = take as usize;
                self.stdout
                    .read_exact(&mut sink_buf[..take])
                    .map_err(|e| BridgeError::Source(format!("cat-file drain: {e}")))?;
                remaining -= take as u64;
            }
            let mut obj = crate::gitobj::Sha1Id::default();
            if let Some(parsed) = sha1_from_hex(echo) {
                obj = parsed;
            }
            return Err(crate::error::Refusal::BlobTooLarge {
                object: {
                    let mut h = [0u8; 32];
                    h[..20].copy_from_slice(&obj);
                    h
                },
                size,
            }
            .into());
        }
        #[allow(clippy::cast_possible_truncation)] // size checked against the cap above
        let mut body = vec![0u8; size as usize];
        self.stdout
            .read_exact(&mut body)
            .map_err(|e| BridgeError::Source(format!("cat-file body: {e}")))?;
        let mut nl = [0u8; 1];
        self.stdout
            .read_exact(&mut nl)
            .map_err(|e| BridgeError::Source(format!("cat-file trailer: {e}")))?;
        Ok((kind, body))
    }
}

impl Drop for CatFileBatch {
    fn drop(&mut self) {
        // Kill + reap to avoid a zombie (stdin close alone would
        // also end the batch loop, but kill is prompt and unconditional).
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn git_stdout(repo: &Path, args: &[&str]) -> Result<String, BridgeError> {
    let out = git_command(repo)
        .args(args)
        .output()
        .map_err(|e| BridgeError::Source(format!("spawn git: {e}")))?;
    if !out.status.success() {
        return Err(BridgeError::Source(format!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    String::from_utf8(out.stdout).map_err(|_| BridgeError::Source("git output not UTF-8".into()))
}

/// Commit ids reachable from `tips` minus `exclude`, parents-first
/// (`--reverse --topo-order`), i.e. translation order.
pub fn rev_list(
    repo: &Path,
    tips: &[Sha1Id],
    exclude: &[Sha1Id],
) -> Result<Vec<Sha1Id>, BridgeError> {
    let mut args: Vec<String> = vec!["rev-list".into(), "--reverse".into(), "--topo-order".into()];
    for t in tips {
        args.push(sha1_hex(t));
    }
    for e in exclude {
        args.push(format!("^{}", sha1_hex(e)));
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = git_stdout(repo, &arg_refs)?;
    out.lines()
        .map(|l| {
            sha1_from_hex(l.trim())
                .ok_or_else(|| BridgeError::Source(format!("rev-list: bad id {l:?}")))
        })
        .collect()
}

/// One upstream ref as listed in the staging mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamRef {
    /// Full ref name (`refs/heads/main`, `refs/tags/v1`).
    pub name: String,
    /// The ref's own id (a tag OBJECT id for annotated tags).
    pub id: Sha1Id,
    /// The peeled commit id for annotated tags (`<ref>^{}` rows).
    pub peeled: Option<Sha1Id>,
}

/// List `refs/heads/*` and `refs/tags/*` in the mirror, with peels.
pub fn list_refs(repo: &Path) -> Result<Vec<UpstreamRef>, BridgeError> {
    let out = git_stdout(
        repo,
        &[
            "for-each-ref",
            "--format=%(refname) %(objectname) %(*objectname)",
            "refs/heads",
            "refs/tags",
        ],
    )?;
    let mut refs = Vec::new();
    for line in out.lines() {
        let mut parts = line.split(' ');
        let (Some(name), Some(id_hex)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some(id) = sha1_from_hex(id_hex) else {
            continue;
        };
        let peeled = parts
            .next()
            .filter(|s| !s.is_empty())
            .and_then(sha1_from_hex);
        refs.push(UpstreamRef {
            name: name.to_owned(),
            id,
            peeled,
        });
    }
    Ok(refs)
}

/// The mirror's default-branch ref (`HEAD` symref target), if any.
pub fn default_branch(repo: &Path) -> Result<Option<String>, BridgeError> {
    let out = git_command(repo)
        .args(["symbolic-ref", "--quiet", "HEAD"])
        .output()
        .map_err(|e| BridgeError::Source(format!("spawn git: {e}")))?;
    if !out.status.success() {
        return Ok(None); // detached/unborn HEAD
    }
    Ok(Some(String::from_utf8_lossy(&out.stdout).trim().to_owned()))
}

/// Is `old` an ancestor of `new` in this repo? (`git merge-base
/// --is-ancestor`: exit 0 = yes, 1 = no.)
pub fn is_ancestor(repo: &Path, old: &Sha1Id, new: &Sha1Id) -> Result<bool, BridgeError> {
    let st = git_command(repo)
        .args([
            "merge-base",
            "--is-ancestor",
            &sha1_hex(old),
            &sha1_hex(new),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| BridgeError::Source(format!("spawn git: {e}")))?;
    match st.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(BridgeError::Source(
            "merge-base --is-ancestor failed".into(),
        )),
    }
}

/// Whether the repo still has `id` (`git cat-file -e`). Exit 0 =
/// present; any nonzero = absent (gc'd, never fetched, garbage).
pub fn object_exists(repo: &Path, id: &Sha1Id) -> Result<bool, BridgeError> {
    let st = git_command(repo)
        .args(["cat-file", "-e", &sha1_hex(id)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| BridgeError::Source(format!("spawn git: {e}")))?;
    Ok(st.code() == Some(0))
}

/// SPEC-GIT-IMPORT §2: SHA-256 upstreams refuse whole-import.
pub fn is_sha256_repo(repo: &Path) -> Result<bool, BridgeError> {
    let out = git_command(repo)
        .args(["config", "extensions.objectformat"])
        .output()
        .map_err(|e| BridgeError::Source(format!("spawn git: {e}")))?;
    // Unset config exits non-zero — that's the sha1 default.
    Ok(out.status.success()
        && String::from_utf8_lossy(&out.stdout)
            .trim()
            .eq_ignore_ascii_case("sha256"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Build a tiny real repo: two commits + an annotated tag.
    fn fixture() -> Option<(tempfile::TempDir, Sha1Id)> {
        if !git_available() {
            return None;
        }
        let td = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            let out = Command::new("git")
                .arg("-C")
                .arg(td.path())
                .args(args)
                .env("GIT_AUTHOR_NAME", "A")
                .env("GIT_AUTHOR_EMAIL", "a@x")
                .env("GIT_COMMITTER_NAME", "C")
                .env("GIT_COMMITTER_EMAIL", "c@x")
                .env("GIT_AUTHOR_DATE", "1700000000 +0000")
                .env("GIT_COMMITTER_DATE", "1700000000 +0000")
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?}: {out:?}");
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
        run(&["init", "--quiet", "--initial-branch=main", "."]);
        std::fs::write(td.path().join("a.txt"), "hello\n").unwrap();
        run(&["add", "a.txt"]);
        run(&["commit", "--quiet", "-m", "first"]);
        std::fs::write(td.path().join("b.txt"), "world\n").unwrap();
        run(&["add", "b.txt"]);
        run(&["commit", "--quiet", "-m", "second"]);
        run(&["tag", "-a", "v1", "-m", "tag msg"]);
        let head = sha1_from_hex(&run(&["rev-parse", "HEAD"])).unwrap();
        Some((td, head))
    }

    #[test]
    fn batch_reads_kinds_and_missing() {
        let Some((td, head)) = fixture() else { return };
        let git_dir = td.path().join(".git");
        let mut batch = CatFileBatch::open(&git_dir).unwrap();
        let (kind, body) = batch.read(&head).unwrap();
        assert_eq!(kind, GitObjKind::Commit);
        let c = crate::gitparse::parse_commit(&body).unwrap();
        assert_eq!(c.message, b"second\n");
        assert_eq!(c.committer.timestamp, 1_700_000_000);
        // The tree, then a blob through the tree.
        let (kind, tree_body) = batch.read(&c.tree).unwrap();
        assert_eq!(kind, GitObjKind::Tree);
        let entries = crate::gitparse::parse_tree(&tree_body).unwrap();
        assert_eq!(entries.len(), 2);
        let (kind, blob) = batch.read(&entries[0].id).unwrap();
        assert_eq!(kind, GitObjKind::Blob);
        assert_eq!(blob, b"hello\n");
        // Missing object errors without poisoning the stream.
        assert!(batch.read(&[0xEEu8; 20]).is_err());
        assert!(batch.read(&head).is_ok(), "stream survives a miss");
    }

    #[test]
    fn rev_list_orders_parents_first_and_excludes() {
        let Some((td, head)) = fixture() else { return };
        let git_dir = td.path().join(".git");
        let all = rev_list(&git_dir, &[head], &[]).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(*all.last().unwrap(), head, "tip last (parents first)");
        let inc = rev_list(&git_dir, &[head], &[all[0]]).unwrap();
        assert_eq!(inc, vec![head], "exclusion yields the delta only");
    }

    #[test]
    fn list_refs_peels_tags_and_default_branch() {
        let Some((td, head)) = fixture() else { return };
        let git_dir = td.path().join(".git");
        let refs = list_refs(&git_dir).unwrap();
        let tag = refs.iter().find(|r| r.name == "refs/tags/v1").unwrap();
        assert_ne!(tag.id, head, "annotated tag has its own object id");
        assert_eq!(tag.peeled, Some(head));
        let main = refs.iter().find(|r| r.name == "refs/heads/main").unwrap();
        assert_eq!(main.id, head);
        assert_eq!(main.peeled, None);
        assert_eq!(
            default_branch(&git_dir).unwrap().as_deref(),
            Some("refs/heads/main")
        );
        assert!(!is_sha256_repo(&git_dir).unwrap());
    }

    /// `GitObjKind -> GitType` must agree with the canonical
    /// `GitObject::raw` framing for every kind, so the single shared
    /// header layout stays correct (no per-call-site drift).
    #[test]
    fn objkind_into_gittype_frames_canonically() {
        for (kind, name) in [
            (GitObjKind::Blob, "blob"),
            (GitObjKind::Tree, "tree"),
            (GitObjKind::Commit, "commit"),
            (GitObjKind::Tag, "tag"),
        ] {
            let gtype: GitType = kind.into();
            assert_eq!(gtype.name(), name);
            let body = b"hi".to_vec();
            let raw = crate::gitobj::GitObject {
                gtype,
                body: body.clone(),
            }
            .raw();
            let mut expect = Vec::new();
            expect.extend_from_slice(name.as_bytes());
            expect.push(b' ');
            expect.extend_from_slice(body.len().to_string().as_bytes());
            expect.push(0);
            expect.extend_from_slice(&body);
            assert_eq!(raw, expect, "{name} framing");
        }
    }
}
