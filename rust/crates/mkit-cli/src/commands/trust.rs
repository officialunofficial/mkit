//! `mkit trust` — manage the commit-history allowed-signers file that
//! `mkit verify --trusted` cross-checks a commit/remix/tag's `signer`
//! against.
//!
//! ```text
//! mkit trust add <keyid> <pubkey-hex> [--kind ed25519|p256-sec1|secp256k1|bls12381-thr]
//!                [--trust-roots <path>] [--force]
//! mkit trust list [--trust-roots <path>] [--json]
//! mkit trust remove <keyid> [--trust-roots <path>] --yes
//! ```
//!
//! The file is the same `[[trust_root]]` TOML format `mkit
//! verify-attest --trust-roots` already reads (see
//! `commands/trust_roots.rs`) — one registry, shared by DSSE
//! attestation verification and commit/remix/tag signer verification,
//! keyed by the `TrustRoot` type `mkit-attest` already exposes. Path
//! defaults to the user-scoped `$XDG_CONFIG_HOME/mkit/trust-roots.toml`;
//! an in-repo path is refused unless passed explicitly via
//! `--trust-roots` (same hostile-clone defense as `verify-attest`, see
//! `docs/THREAT-MODEL.md` §5).

use std::io::Write as _;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use super::trust_roots::{
    self, TrustEntry, default_trust_roots_path, keyid_matches_pubkey, warn_if_unsafe_trust_roots,
};
use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit trust",
    about = "Manage the commit-history trust-roots file."
)]
struct TrustOpts {
    #[command(subcommand)]
    command: TrustCommand,
}

#[derive(Debug, Subcommand)]
enum TrustCommand {
    /// Add (or replace) a trusted signer.
    Add(AddOpts),
    /// List trusted signers.
    List(ListOpts),
    /// Remove a trusted signer.
    Remove(RemoveOpts),
}

#[derive(Debug, Parser)]
struct AddOpts {
    /// Identifier for this trust root, e.g. `ed25519:<hex-pubkey>` or a
    /// human label like `alice-laptop`. Free-form, but see `kind` for
    /// the canonical `<algorithm>:<hex-pubkey>` shape.
    keyid: String,
    /// Public key, lowercase hex. Ed25519 is 32 bytes; P-256/secp256k1
    /// SEC1 are 33 (compressed) or 65 (uncompressed) bytes; the
    /// BLS12-381 threshold cohort key (`bls-threshold` feature) is 96
    /// bytes.
    pubkey_hex: String,
    /// Trust-root kind. Commit/remix/tag signing is Ed25519-only
    /// today, so this defaults to `ed25519`; other kinds only matter
    /// for `mkit verify-attest`.
    #[arg(long, value_name = "KIND", default_value = "ed25519")]
    kind: String,
    #[arg(long, value_name = "PATH")]
    trust_roots: Option<String>,
    /// Overwrite an existing entry for this keyid.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Parser)]
struct ListOpts {
    #[arg(long, value_name = "PATH")]
    trust_roots: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct RemoveOpts {
    keyid: String,
    #[arg(long, value_name = "PATH")]
    trust_roots: Option<String>,
    #[arg(long)]
    yes: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<TrustOpts>("mkit trust", args) {
        Ok(opts) => opts,
        Err(code) => return code,
    };
    match opts.command {
        TrustCommand::Add(opts) => add(&opts),
        TrustCommand::List(opts) => list(&opts),
        TrustCommand::Remove(opts) => remove(&opts),
    }
}

/// Resolve the trust-roots path from an optional CLI flag, honoring
/// the same repo-local path-fencing every trust-consuming command
/// applies.
fn resolve_path(flag: Option<&str>) -> Result<PathBuf, u8> {
    let path = flag.map_or_else(default_trust_roots_path, PathBuf::from);
    // `mkit trust` has no repo context of its own (unlike `verify` /
    // `verify-attest`, which resolve a `.mkit` dir to fence against) —
    // it only needs to refuse an explicit-looking-but-actually-default
    // in-repo path when the CWD happens to be a repo. Fence against
    // `.mkit` under the current directory if one exists; otherwise
    // there is nothing to fence.
    let cwd = std::env::current_dir().unwrap_or_default();
    let mkit_dir = cwd.join(".mkit");
    warn_if_unsafe_trust_roots(&path, &mkit_dir, flag.is_some())?;
    Ok(path)
}

fn add(opts: &AddOpts) -> u8 {
    let path = match resolve_path(opts.trust_roots.as_deref()) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let Some(pk_bytes) = trust_roots::hex_decode(&opts.pubkey_hex) else {
        return emit_err(
            &format!("bad --pubkey-hex '{}': not valid hex", opts.pubkey_hex),
            exit::USAGE,
        );
    };
    if let Some(expected_len) = expected_pubkey_len(&opts.kind)
        && pk_bytes.len() != expected_len
    {
        return emit_err(
            &format!(
                "bad pubkey length for kind '{}': expected {expected_len} bytes, got {}",
                opts.kind,
                pk_bytes.len()
            ),
            exit::USAGE,
        );
    }
    if !keyid_matches_pubkey(&opts.keyid, &pk_bytes) {
        return emit_err(
            &format!(
                "keyid '{}' does not match the given pubkey — a `<algorithm>:<hex>` keyid must \
                 embed the same hex as --pubkey-hex (or the blake3 digest of it)",
                opts.keyid
            ),
            exit::USAGE,
        );
    }
    let mut entries = match trust_roots::load_entries(&path) {
        Ok(e) => e,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    if let Some(existing) = entries.iter().position(|e| e.keyid == opts.keyid) {
        if !opts.force {
            return emit_err(
                &format!(
                    "a trust root for keyid '{}' already exists — pass --force to replace it",
                    opts.keyid
                ),
                exit::USAGE,
            );
        }
        entries.remove(existing);
    }
    entries.push(TrustEntry {
        keyid: opts.keyid.clone(),
        kind: opts.kind.clone(),
        pubkey_hex: opts.pubkey_hex.to_ascii_lowercase(),
    });
    if let Err((msg, code)) = trust_roots::save(&path, &entries) {
        return emit_err(&msg, code);
    }
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(
        stdout,
        "added {} ({}) to {}",
        opts.keyid,
        opts.kind,
        path.display()
    );
    exit::OK
}

fn list(opts: &ListOpts) -> u8 {
    let path = match resolve_path(opts.trust_roots.as_deref()) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let entries = match trust_roots::load_entries(&path) {
        Ok(e) => e,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    let mut stdout = std::io::stdout().lock();
    if opts.json {
        use std::fmt::Write as _;
        let mut out = String::from("[");
        for (i, e) in entries.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"keyid\":{:?},\"kind\":{:?},\"pubkey_hex\":{:?}}}",
                e.keyid, e.kind, e.pubkey_hex
            );
        }
        out.push(']');
        let _ = writeln!(stdout, "{out}");
    } else if entries.is_empty() {
        let _ = writeln!(stdout, "no trust roots in {}", path.display());
    } else {
        for e in &entries {
            let _ = writeln!(stdout, "{}  [{}]  {}", e.keyid, e.kind, e.pubkey_hex);
        }
    }
    exit::OK
}

fn remove(opts: &RemoveOpts) -> u8 {
    if !opts.yes {
        return emit_err("mkit trust remove requires --yes", exit::USAGE);
    }
    let path = match resolve_path(opts.trust_roots.as_deref()) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let mut entries = match trust_roots::load_entries(&path) {
        Ok(e) => e,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    let Some(pos) = entries.iter().position(|e| e.keyid == opts.keyid) else {
        return emit_err(
            &format!("no trust root registered for keyid '{}'", opts.keyid),
            exit::GENERAL_ERROR,
        );
    };
    entries.remove(pos);
    if let Err((msg, code)) = trust_roots::save(&path, &entries) {
        return emit_err(&msg, code);
    }
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "removed {} from {}", opts.keyid, path.display());
    exit::OK
}

fn expected_pubkey_len(kind: &str) -> Option<usize> {
    match kind {
        "ed25519" => Some(32),
        #[cfg(feature = "bls-threshold")]
        "bls12381-thr" => Some(mkit_attest::BLS_THRESHOLD_PUBLIC_KEY_SIZE),
        // SEC1 p256/secp256k1 accept both 33 (compressed) and 65
        // (uncompressed) — length-checked by mkit-attest at verify
        // time instead of here.
        _ => None,
    }
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn parse_args(args: &[String]) -> Result<TrustOpts, clap::Error> {
        let mut full: Vec<String> = vec!["mkit trust".into()];
        full.extend_from_slice(args);
        TrustOpts::try_parse_from(full)
    }

    #[test]
    fn parse_add_defaults_kind_to_ed25519() {
        let args = vec!["add".into(), "keyid".into(), "aa".into()];
        let TrustCommand::Add(opts) = parse_args(&args).unwrap().command else {
            panic!("expected Add");
        };
        assert_eq!(opts.kind, "ed25519");
        assert!(!opts.force);
    }

    #[test]
    fn parse_remove_requires_yes_flag_at_runtime_not_parse_time() {
        let args = vec!["remove".into(), "keyid".into()];
        let TrustCommand::Remove(opts) = parse_args(&args).unwrap().command else {
            panic!("expected Remove");
        };
        assert!(!opts.yes);
    }

    #[test]
    fn add_list_remove_round_trip() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("trust-roots.toml");
        let hex = "11".repeat(32);
        let keyid = format!("ed25519:{hex}");

        let rc = add(&AddOpts {
            keyid: keyid.clone(),
            pubkey_hex: hex.clone(),
            kind: "ed25519".into(),
            trust_roots: Some(path.to_string_lossy().into_owned()),
            force: false,
        });
        assert_eq!(rc, exit::OK);

        let entries = trust_roots::load_entries(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].keyid, keyid);

        let rc = remove(&RemoveOpts {
            keyid: keyid.clone(),
            trust_roots: Some(path.to_string_lossy().into_owned()),
            yes: true,
        });
        assert_eq!(rc, exit::OK);
        assert!(trust_roots::load_entries(&path).unwrap().is_empty());
        let _ = fs::remove_dir_all(td.path());
    }

    #[test]
    fn add_rejects_keyid_pubkey_mismatch() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("trust-roots.toml");
        let hex = "22".repeat(32);
        let rc = add(&AddOpts {
            keyid: format!("ed25519:{}", "ff".repeat(32)),
            pubkey_hex: hex,
            kind: "ed25519".into(),
            trust_roots: Some(path.to_string_lossy().into_owned()),
            force: false,
        });
        assert_eq!(rc, exit::USAGE);
    }

    #[test]
    fn add_without_force_refuses_duplicate_keyid() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("trust-roots.toml");
        let hex = "33".repeat(32);
        let keyid = format!("ed25519:{hex}");
        let make = || AddOpts {
            keyid: keyid.clone(),
            pubkey_hex: hex.clone(),
            kind: "ed25519".into(),
            trust_roots: Some(path.to_string_lossy().into_owned()),
            force: false,
        };
        assert_eq!(add(&make()), exit::OK);
        assert_eq!(add(&make()), exit::USAGE);
        let mut forced = make();
        forced.force = true;
        assert_eq!(add(&forced), exit::OK);
        assert_eq!(trust_roots::load_entries(&path).unwrap().len(), 1);
    }

    #[test]
    fn remove_without_yes_is_refused() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("trust-roots.toml");
        let rc = remove(&RemoveOpts {
            keyid: "anything".into(),
            trust_roots: Some(path.to_string_lossy().into_owned()),
            yes: false,
        });
        assert_eq!(rc, exit::USAGE);
    }

    #[test]
    fn remove_unknown_keyid_is_an_error() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("trust-roots.toml");
        let rc = remove(&RemoveOpts {
            keyid: "nope".into(),
            trust_roots: Some(path.to_string_lossy().into_owned()),
            yes: true,
        });
        assert_eq!(rc, exit::GENERAL_ERROR);
    }

    #[test]
    fn list_json_emits_valid_array_shape() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("trust-roots.toml");
        let hex = "44".repeat(32);
        let keyid = format!("ed25519:{hex}");
        add(&AddOpts {
            keyid,
            pubkey_hex: hex,
            kind: "ed25519".into(),
            trust_roots: Some(path.to_string_lossy().into_owned()),
            force: false,
        });
        let rc = list(&ListOpts {
            trust_roots: Some(path.to_string_lossy().into_owned()),
            json: true,
        });
        assert_eq!(rc, exit::OK);
    }
}
