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

use mkit_core::index;
use mkit_core::object::{Commit, Identity, IdentityKind, Object};
use mkit_core::refs::{self, Head};
use mkit_core::serialize;
use mkit_core::sign::{self, KeyPair};
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use crate::editor::{COMMIT_EDITMSG_TEMPLATE, spawn_editor};
use crate::exit;
use crate::format;

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(args: &[String]) -> u8 {
    let mut message: Option<String> = None;
    let mut author_spec: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-m" if i + 1 < args.len() => {
                message = Some(args[i + 1].clone());
                i += 2;
            }
            "--author" if i + 1 < args.len() => {
                author_spec = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }

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
    let msg = match message {
        Some(m) => m,
        None => match spawn_editor(COMMIT_EDITMSG_TEMPLATE) {
            Ok(m) if !m.is_empty() => m,
            Ok(_) => {
                return emit_err("empty commit message — aborting", exit::USAGE);
            }
            Err(e) => return emit_err(&format!("editor: {e}"), exit::GENERAL_ERROR),
        },
    };

    // ---- Load signing key. -----------------------------------------
    let kp = match load_signing_key(&cwd, &cfg.signing_key) {
        Ok(kp) => kp,
        Err((msg, code)) => return emit_err(&msg, code),
    };

    // ---- Resolve author. -------------------------------------------
    // Precedence: --author flag → config.user_identity → pubkey-derived.
    let author = match resolve_author(author_spec.as_deref(), &cfg.user_identity, &kp) {
        Ok(id) => id,
        Err(e) => return emit_err(&format!("author: {e}"), exit::CONFIG_ERROR),
    };

    // Read the staging index. An absent file or zero non-removed
    // entries is a hard error — see module docs and issue #102.
    let Ok(idx) = index::read_index(&cwd) else {
        return emit_err(
            "nothing staged: run `mkit add <path>` (or `mkit add .`) before commit",
            exit::USAGE,
        );
    };
    if idx.staged_count() == 0 {
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
        kp.public.0,
        msg.as_bytes().to_vec(),
        timestamp,
        [0u8; 64],
    );
    let sig = match sign::sign_commit(&unsigned, &kp) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("sign: {e}"), exit::GENERAL_ERROR),
    };
    unsigned.signature = sig.0;
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
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(
        stdout,
        "committed {} ({})",
        format::short_hash(&commit_hash, 8),
        msg.lines().next().unwrap_or("")
    );
    exit::OK
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

/// Advance the branch pointed to by HEAD (or HEAD itself, if detached)
/// to `commit_hash`.
fn advance_head(
    mkit_dir: &std::path::Path,
    commit_hash: &mkit_core::hash::Hash,
) -> Result<(), (String, u8)> {
    let head = refs::read_head(mkit_dir).unwrap_or(Head::Branch("main".to_string()));
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
    kp: &KeyPair,
) -> Result<Identity, String> {
    if let Some(spec) = author_flag {
        return parse_author_spec(spec);
    }
    if !cfg_user_identity.is_empty() {
        return decode_user_identity_hex(cfg_user_identity);
    }
    Ok(Identity::ed25519(kp.public.0))
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
        let id = resolve_author(Some(&spec), &cfg_hex, &kp).unwrap();
        assert!(id.bytes.iter().all(|&b| b == 0x22));
    }

    #[test]
    fn resolve_author_uses_config_when_no_flag() {
        let kp = KeyPair::generate().unwrap();
        let mut cfg_hex = String::from("012000");
        cfg_hex.push_str(&"44".repeat(32));
        let id = resolve_author(None, &cfg_hex, &kp).unwrap();
        assert_eq!(id.kind, IdentityKind::Ed25519);
        assert!(id.bytes.iter().all(|&b| b == 0x44));
    }

    #[test]
    fn resolve_author_falls_back_to_pubkey() {
        let kp = KeyPair::generate().unwrap();
        let id = resolve_author(None, "", &kp).unwrap();
        assert_eq!(id.kind, IdentityKind::Ed25519);
        assert_eq!(id.bytes, kp.public.0.to_vec());
    }
}
