//! `mkit commit` — build a signed commit object from the staging
//! index.
//!
//! Scope:
//! 1. Accept `-m <msg>` OR spawn `$EDITOR` on a tempfile pre-filled
//! with [`editor::COMMIT_EDITMSG_TEMPLATE`]. An empty message
//! aborts.
//! 2. Read `.mkit/index` and build a tree via
//! [`worktree::build_tree_from_index`]. An empty / missing index is
//! an error — `mkit add <path>` (or `mkit add .`) must come first.
//! 3. Resolve the author identity in this order:
//! a. `--author <spec>` CLI flag (overrides everything).
//! b. `config.user_identity` in `.mkit/config`.
//! c. Derived from the signing key's public key (default).
//! 4. Sign the commit, write the `Commit` object, advance
//! `refs/heads/<current>` and `HEAD`.
//!
//! Pre-issue-#102 `mkit commit` walked the worktree directly via
//! `worktree::build_tree`, ignoring the index entirely. That made
//! `mkit add` write-only state with no reader and surprised any user
//! reasoning by analogy from git. Post-#102, the staging area is
//! load-bearing: only paths in the index land in the commit's tree.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use mkit_core::index;
use mkit_core::object::{Commit, Identity, IdentityKind, Object};
use mkit_core::refs::{self, Head};
use mkit_core::serialize;
use mkit_core::sign::{self, KeyPair};
use mkit_core::store::ObjectStore;
use mkit_core::worktree;
use mkit_keystore::{KeyRef, KeySelector, open_backend};

use crate::clap_shim;
use crate::config::Config;
use crate::editor::{COMMIT_EDITMSG_TEMPLATE, spawn_editor};
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(
    name = "mkit commit",
    about = "Create a signed commit from the staging index."
)]
struct CommitOptions {
    /// Commit message. If omitted, `$EDITOR` is launched.
    #[arg(short, long)]
    message: Option<String>,
    /// Override the author Identity for this commit.
    #[arg(long = "author", value_name = "SPEC")]
    author_spec: Option<String>,
    /// Stage every tracked-and-modified file before committing
    /// (mirrors `git commit -a`).
    #[arg(short = 'a', long)]
    all: bool,
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(args: &[String]) -> u8 {
    // Split fused `-am<msg>` / `-am <msg>` shortcuts into the
    // equivalent `-a -m <msg>` so clap sees only canonical forms.
    let normalised = expand_dash_am(args);
    let opts = match clap_shim::parse::<CommitOptions>("mkit commit", &normalised) {
        Ok(o) => o,
        Err(code) => return code,
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

    let cfg = match crate::config::read_or_default(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };

    // ---- Resolve / prompt for message. -----------------------------
    let msg = match opts.message {
        Some(m) => m,
        None => match spawn_editor(COMMIT_EDITMSG_TEMPLATE) {
            Ok(m) if !m.is_empty() => m,
            Ok(_) => {
                return emit_err("empty commit message — aborting", exit::USAGE);
            }
            Err(e) => return emit_err(&format!("editor: {e}"), exit::GENERAL_ERROR),
        },
    };

    // ---- Load signer. ----------------------------------------------
    let mut signer = match load_commit_signer(&cwd, &cfg) {
        Ok(signer) => signer,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    let signer_public = match signer.public_key() {
        Ok(public) => public,
        Err((msg, code)) => return emit_err(&msg, code),
    };

    // ---- Resolve author. -------------------------------------------
    // Precedence: --author flag → config.user_identity → pubkey-derived.
    let author = match resolve_author(
        opts.author_spec.as_deref(),
        &cfg.user_identity,
        &signer_public,
    ) {
        Ok(id) => id,
        Err(e) => return emit_err(&format!("author: {e}"), exit::CONFIG_ERROR),
    };

    if opts.all
        && let Err(e) = super::add::stage_tracked_changes(&cwd, &store)
    {
        return emit_err(&format!("stage tracked changes: {e}"), exit::GENERAL_ERROR);
    }

    // Read the staging index. An absent file OR a totally empty
    // entries vector is a hard error — see module docs and issue
    // #102. An all-Removed index, by contrast, is a meaningful
    // changeset (the user is committing deletions) and produces an
    // empty-tree commit, so we DON'T gate on `staged_count()` (which
    // excludes Removed entries by design).
    let Ok(idx) = index::read_index(&cwd) else {
        return emit_err(
            "nothing staged: run `mkit add <path>` (or `mkit add .`) before commit",
            exit::USAGE,
        );
    };
    if idx.entries.is_empty() {
        return emit_err(
            "nothing staged: index is empty; run `mkit add <path>` (or `mkit add .`) before commit",
            exit::USAGE,
        );
    }
    let tree_hash = match worktree::build_tree_from_index(&store, &idx) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("build tree: {e}"), exit::GENERAL_ERROR),
    };
    let parents = match refs::resolve_head(&mkit_dir) {
        Ok(Some(h)) => vec![h],
        _ => vec![],
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut unsigned = Commit::new_unannotated(
        tree_hash,
        parents,
        author,
        signer_public,
        msg.as_bytes().to_vec(),
        timestamp,
        [0u8; 64],
    );
    let sig = match signer.sign_commit(&unsigned) {
        Ok(s) => s,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    unsigned.signature = sig;
    let bytes = match serialize::serialize(&Object::Commit(unsigned)) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("serialize commit: {e}"), exit::DATAERR),
    };
    let commit_hash = match store.write(&bytes) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("store commit: {e}"), exit::CANTCREAT),
    };
    if let Err((m, c)) = advance_head(&mkit_dir, &commit_hash) {
        return emit_err(&m, c);
    }
    if let Err(e) = super::sync_index_to_tree(&cwd, &store, tree_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "committed {} ({})",
        format::short_hash(&commit_hash, 8),
        msg.lines().next().unwrap_or("")
    );
    exit::OK
}

/// Pre-process `args` to canonicalize the legacy `-am<msg>` /
/// `-am <msg>` shortcut into `-a -m <msg>`. Everything else passes
/// through unchanged. Clap then sees only canonical forms.
fn expand_dash_am(args: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(args.len() + 2);
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-am" => {
                out.push("-a".to_owned());
                out.push("-m".to_owned());
                if let Some(next) = iter.next() {
                    out.push(next.clone());
                }
            }
            s if s.starts_with("-am") && s.len() > 3 => {
                out.push("-a".to_owned());
                out.push("-m".to_owned());
                out.push(s[3..].to_owned());
            }
            _ => out.push(a.clone()),
        }
    }
    out
}

#[cfg(test)]
mod expand_dash_am_tests {
    use super::expand_dash_am;

    fn to_strs(args: &[String]) -> Vec<&str> {
        args.iter().map(String::as_str).collect()
    }

    #[test]
    fn fused_dash_am_with_inline_message() {
        let out = expand_dash_am(&["-amhello".to_owned()]);
        assert_eq!(to_strs(&out), &["-a", "-m", "hello"]);
    }

    #[test]
    fn spaced_dash_am_with_following_message() {
        let out = expand_dash_am(&["-am".to_owned(), "hello".to_owned()]);
        assert_eq!(to_strs(&out), &["-a", "-m", "hello"]);
    }

    #[test]
    fn unrelated_args_pass_through() {
        let out = expand_dash_am(&[
            "-m".to_owned(),
            "msg".to_owned(),
            "--author".to_owned(),
            "id".to_owned(),
        ]);
        assert_eq!(to_strs(&out), &["-m", "msg", "--author", "id"]);
    }
}

/// Load the Ed25519 signing key. Returns a mapped (message,
/// exit-code) pair on failure so the caller can route the error
/// through its usual `emit_err` path.
///
/// Auto-generation was removed in combined with a non-atomic
/// `save_key`, an interrupted keygen could silently rotate the user's
/// identity (subsequent commits no longer share a signer with prior
/// ones). The save path is now atomic, but auto-keygen also masks
/// genuine path-misconfigurations and tooling errors. Users run
/// `mkit keygen` once, explicitly, and a missing key on `mkit commit`
/// is now an error.
fn load_signing_key(
    cwd: &std::path::Path,
    rel_signing_key_path: &str,
) -> Result<KeyPair, (String, u8)> {
    let key_path = match crate::config::resolve_key_path(cwd, rel_signing_key_path) {
        Ok(p) => p,
        Err(e) => return Err((format!("{e}"), exit::CONFIG_ERROR)),
    };
    if !key_path.exists() {
        return Err((
            format!(
                "no signing key at {} — run `mkit keygen` to create one",
                key_path.display()
            ),
            exit::NOINPUT,
        ));
    }
    sign::load_key(&key_path).map_err(|e| (format!("load key: {e}"), exit::NOPERM))
}

pub(super) enum CommitSigner {
    Legacy(KeyPair),
    Keystore(Box<dyn mkit_keystore::KeySigner>),
}

impl CommitSigner {
    pub(super) fn public_key(&self) -> Result<[u8; 32], (String, u8)> {
        match self {
            Self::Legacy(kp) => Ok(kp.public.0),
            Self::Keystore(signer) => {
                let public = signer
                    .public_key()
                    .map_err(|error| (format!("keystore public key: {error}"), exit::DATAERR))?;
                public.try_into().map_err(|public: Vec<u8>| {
                    (
                        format!(
                            "keystore Ed25519 public key must be 32 bytes, got {}",
                            public.len()
                        ),
                        exit::DATAERR,
                    )
                })
            }
        }
    }

    pub(super) fn sign_commit(&mut self, commit: &Commit) -> Result<[u8; 64], (String, u8)> {
        match self {
            Self::Legacy(kp) => sign::sign_commit(commit, kp)
                .map(|signature| signature.0)
                .map_err(|error| (format!("sign: {error}"), exit::GENERAL_ERROR)),
            Self::Keystore(signer) => {
                let digest = sign::commit_signing_hash(commit)
                    .map_err(|error| (format!("commit signing hash: {error}"), exit::DATAERR))?;
                let signature = signer
                    .sign(&digest)
                    .map_err(|error| (format!("keystore sign: {error}"), exit::DATAERR))?;
                signature.try_into().map_err(|signature: Vec<u8>| {
                    (
                        format!(
                            "keystore Ed25519 signature must be 64 bytes, got {}",
                            signature.len()
                        ),
                        exit::DATAERR,
                    )
                })
            }
        }
    }
}

pub(super) fn load_commit_signer(
    cwd: &std::path::Path,
    cfg: &Config,
) -> Result<CommitSigner, (String, u8)> {
    match cfg.signer.as_str() {
        "" | "legacy" => load_signing_key(cwd, &cfg.signing_key).map(CommitSigner::Legacy),
        "keystore" => load_keystore_commit_signer(cfg),
        other => Err((
            format!("unknown signer `{other}` — expected `legacy` or `keystore`"),
            exit::CONFIG_ERROR,
        )),
    }
}

fn load_keystore_commit_signer(cfg: &Config) -> Result<CommitSigner, (String, u8)> {
    let key_ref = cfg
        .key
        .ed25519_ref_or_fallback()
        .parse::<KeyRef>()
        .map_err(|error| (format!("key.ed25519_ref: {error}"), exit::CONFIG_ERROR))?;
    let store = open_backend(key_ref.backend())
        .map_err(|error| (format!("keystore backend: {error}"), exit::UNAVAILABLE))?;
    let selector = KeySelector::new(
        key_ref.label().to_owned(),
        Some(mkit_keystore::Algorithm::Ed25519),
    )
    .map_err(|error| (format!("key.ed25519_ref: {error}"), exit::CONFIG_ERROR))?;
    let signer = store.open(&selector).map_err(|error| match error {
        mkit_keystore::Error::KeyNotFound(_) => (
            format!(
                "missing keystore signing key `{}` — run `mkit key generate --backend {} --algorithm ed25519 --label {}` first, or set `signer = legacy` and use `mkit keygen`: {error}",
                cfg.key.ed25519_ref_or_fallback(), key_ref.backend(), key_ref.label()
            ),
            exit::NOINPUT,
        ),
        other => (
            format!("keystore signing key `{}`: {other}", cfg.key.ed25519_ref_or_fallback()),
            exit::DATAERR,
        ),
    })?;
    Ok(CommitSigner::Keystore(signer))
}

/// Advance the branch pointed to by HEAD (or HEAD itself, if detached)
/// to `commit_hash`.
fn advance_head(
    mkit_dir: &std::path::Path,
    commit_hash: &mkit_core::hash::Hash,
) -> Result<(), (String, u8)> {
    let head = refs::read_head(mkit_dir).map_err(|e| (format!("read HEAD: {e}"), exit::DATAERR))?;
    match head {
        Head::Branch(name) => refs::write_ref(mkit_dir, &name, commit_hash)
            .map_err(|e| (format!("write ref: {e}"), exit::CANTCREAT)),
        Head::Detached(_) => refs::write_head_detached(mkit_dir, commit_hash)
            .map_err(|e| (format!("update HEAD: {e}"), exit::CANTCREAT)),
    }
}

/// Resolve the commit author. See [`run`] for precedence order.
///
/// Exposed to sibling commands (`cherry_pick`, `merge`) so they apply
/// the same precedence as `commit`: `--author` flag (if any) → user-
/// scoped `user.identity` config → signer pubkey fallback. They pass
/// `None` for `author_flag` because they don't accept that flag.
pub(super) fn resolve_author(
    author_flag: Option<&str>,
    cfg_user_identity: &str,
    signer_public: &[u8; 32],
) -> Result<Identity, String> {
    if let Some(spec) = author_flag {
        return parse_author_spec(spec);
    }
    if !cfg_user_identity.is_empty() {
        return decode_user_identity_hex(cfg_user_identity);
    }
    Ok(Identity::ed25519(*signer_public))
}

/// Parse a `--author` flag value.
///
/// Accepted forms:
/// * `ed25519:<64-char hex>` — 32-byte Ed25519 public key.
/// * `did:key:<hex>` — opaque DID-key bytes (hex-decoded, any length
/// ≤ `IDENTITY_MAX_LEN`).
/// * `opaque:<bytes>` — raw UTF-8 bytes, stored as-is.
fn parse_author_spec(spec: &str) -> Result<Identity, String> {
    if let Some(hex) = spec.strip_prefix("ed25519:") {
        let bytes = hex_decode(hex).ok_or_else(|| "ed25519:<hex> invalid hex".to_string())?;
        if bytes.len() != 32 {
            return Err("ed25519:<hex> must decode to 32 bytes".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(Identity::ed25519(arr));
    }
    if let Some(hex) = spec.strip_prefix("did:key:") {
        let bytes = hex_decode(hex).ok_or_else(|| "did:key:<hex> invalid hex".to_string())?;
        if bytes.is_empty() {
            return Err("did:key:<hex> must decode to ≥ 1 byte".to_string());
        }
        return Ok(Identity {
            kind: IdentityKind::DidKey,
            bytes,
        });
    }
    if let Some(raw) = spec.strip_prefix("opaque:") {
        if raw.is_empty() {
            return Err("opaque:<bytes> must not be empty".to_string());
        }
        return Ok(Identity::opaque(raw.as_bytes().to_vec()));
    }
    Err(format!(
        "unknown identity spec '{spec}' — expected ed25519:<hex>, did:key:<hex>, or opaque:<bytes>"
    ))
}

/// Decode a `user.identity` config string into an [`Identity`]. The
/// config file stores the canonical `[kind:u8][len:u16 LE][bytes]`
/// form (see `config::expand_user_identity`), so we invert that here.
fn decode_user_identity_hex(hex: &str) -> Result<Identity, String> {
    let bytes =
        hex_decode(hex).ok_or_else(|| "user.identity: not a lowercase hex string".to_string())?;
    if bytes.len() < 3 {
        return Err("user.identity: too short (kind + len prefix missing)".to_string());
    }
    let kind_byte = bytes[0];
    let declared_len = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
    if bytes.len() != usize::from(declared_len) + 3 {
        return Err("user.identity: declared length does not match payload".to_string());
    }
    let payload = bytes[3..].to_vec();
    let kind = match kind_byte {
        0x01 => IdentityKind::Ed25519,
        0x02 => IdentityKind::DidKey,
        // 0x03 (mid) shares the Opaque variant — upstream compat.
        0x03 | 0x04 => IdentityKind::Opaque,
        other => return Err(format!("user.identity: unknown kind byte {other:#04x}")),
    };
    if kind == IdentityKind::Ed25519 && payload.len() != 32 {
        return Err("user.identity: ed25519 payload must be exactly 32 bytes".to_string());
    }
    Ok(Identity {
        kind,
        bytes: payload,
    })
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = nibble(b[i])?;
        let lo = nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    Some(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => 10 + c - b'a',
        b'A'..=b'F' => 10 + c - b'A',
        _ => return None,
    })
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_keystore::Keystore;

    #[test]
    fn parse_author_ed25519_roundtrips() {
        let hex = "11".repeat(32);
        let spec = format!("ed25519:{hex}");
        let id = parse_author_spec(&spec).unwrap();
        assert_eq!(id.kind, IdentityKind::Ed25519);
        assert_eq!(id.bytes.len(), 32);
        assert!(id.bytes.iter().all(|&b| b == 0x11));
    }

    #[test]
    fn parse_author_rejects_bad_ed25519() {
        assert!(parse_author_spec("ed25519:short").is_err());
        assert!(parse_author_spec("ed25519:zzzzz").is_err());
    }

    #[test]
    fn parse_author_did_key_decodes() {
        let id = parse_author_spec("did:key:deadbeef").unwrap();
        assert_eq!(id.kind, IdentityKind::DidKey);
        assert_eq!(id.bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_author_opaque_takes_raw_bytes() {
        let id = parse_author_spec("opaque:hello world").unwrap();
        assert_eq!(id.kind, IdentityKind::Opaque);
        assert_eq!(id.bytes, b"hello world");
    }

    #[test]
    fn parse_author_rejects_unknown_prefix() {
        assert!(parse_author_spec("foo:bar").is_err());
        assert!(parse_author_spec("").is_err());
    }

    #[test]
    fn decode_user_identity_ed25519_roundtrip() {
        // Mirror expand_user_identity("ed25519:<hex>") output.
        // 0x01 + len(32=0x20,0x00) + 32 bytes of 0xAB.
        let mut hex = String::from("012000");
        hex.push_str(&"ab".repeat(32));
        let id = decode_user_identity_hex(&hex).unwrap();
        assert_eq!(id.kind, IdentityKind::Ed25519);
        assert_eq!(id.bytes.len(), 32);
    }

    #[test]
    fn decode_user_identity_rejects_length_mismatch() {
        let hex = "011000aabbcc"; // declares 16 bytes, provides 3
        assert!(decode_user_identity_hex(hex).is_err());
    }

    #[test]
    fn resolve_author_prefers_flag_over_config() {
        let kp = KeyPair::generate().unwrap();
        let hex = "22".repeat(32);
        let spec = format!("ed25519:{hex}");
        // Populate config with a DIFFERENT identity to verify flag wins.
        let cfg_hex = {
            let mut s = String::from("012000");
            s.push_str(&"33".repeat(32));
            s
        };
        let id = resolve_author(Some(&spec), &cfg_hex, &kp.public.0).unwrap();
        assert!(id.bytes.iter().all(|&b| b == 0x22));
    }

    #[test]
    fn resolve_author_uses_config_when_no_flag() {
        let kp = KeyPair::generate().unwrap();
        let mut cfg_hex = String::from("012000");
        cfg_hex.push_str(&"44".repeat(32));
        let id = resolve_author(None, &cfg_hex, &kp.public.0).unwrap();
        assert_eq!(id.kind, IdentityKind::Ed25519);
        assert!(id.bytes.iter().all(|&b| b == 0x44));
    }

    #[test]
    fn resolve_author_falls_back_to_pubkey() {
        let kp = KeyPair::generate().unwrap();
        let id = resolve_author(None, "", &kp.public.0).unwrap();
        assert_eq!(id.kind, IdentityKind::Ed25519);
        assert_eq!(id.bytes, kp.public.0.to_vec());
    }

    #[test]
    fn keystore_commit_signature_matches_legacy_keypair_signature() {
        let seed = [0x5a; 32];
        let kp = KeyPair::from_seed(seed);
        let store_root = tempfile::tempdir().unwrap();
        let store = mkit_keystore::SoftwareRawKeystore::with_root(store_root.path().join("keys"));
        store
            .import(
                "committer",
                mkit_keystore::SecretKey::new(mkit_keystore::Algorithm::Ed25519, seed),
                mkit_keystore::KeyAttrs::default(),
                mkit_keystore::ImportOptions::default(),
            )
            .unwrap();
        let selector =
            mkit_keystore::KeySelector::new("committer", Some(mkit_keystore::Algorithm::Ed25519))
                .unwrap();
        let mut signer = CommitSigner::Keystore(store.open(&selector).unwrap());
        let signer_public = signer.public_key().unwrap();
        let commit = Commit::new_unannotated(
            [1; 32],
            vec![[2; 32]],
            Identity::ed25519(signer_public),
            signer_public,
            b"same commit".to_vec(),
            123,
            [0; 64],
        );

        let keystore_sig = signer.sign_commit(&commit).unwrap();
        let legacy_sig = sign::sign_commit(&commit, &kp).unwrap().0;
        assert_eq!(keystore_sig, legacy_sig);
    }
}
