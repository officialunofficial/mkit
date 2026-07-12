//! `mkit verify <rev>` — verify the signature on a commit, remix, or
//! signed tag.
//!
//! ```text
//! mkit verify <rev> [--trusted] [--trust-roots <path>]
//! ```
//!
//! By default `mkit verify` only proves that the object's own embedded
//! `signer` public key produced the attached signature — it does NOT
//! check that key against any allow-list, so a signature from a freshly
//! generated attacker key verifies exactly the same as one from a key
//! the caller actually trusts (issue #693). Passing `--trusted` (or
//! `--trust-roots <path>`) additionally cross-checks `signer` against
//! the trust-roots registry `mkit trust add/list/remove` manages
//! (`commands/trust_roots.rs`), failing closed — exit code
//! [`exit::DATAERR`] — when the signer is not on the list, even if the
//! cryptographic signature itself is valid.
//!
//! `--trust-roots` defaults to the user-scoped
//! `$XDG_CONFIG_HOME/mkit/trust-roots.toml`; an in-repo path is refused
//! unless passed explicitly (same hostile-clone defense as
//! `verify-attest`, see `docs/THREAT-MODEL.md` §5).

use std::io::Write;
use std::path::PathBuf;

use clap::Parser;
use mkit_core::object::Object;
use mkit_core::sign::{verify_commit, verify_remix, verify_tag};
use mkit_core::store::ObjectStore;

use super::trust_roots;
use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit verify",
    about = "Verify the signature on a commit, remix, or signed tag."
)]
struct VerifyOpts {
    /// Revision to verify: an object hash (full or short), a branch /
    /// tag name, or `HEAD`. A tag name resolves to its annotated-tag
    /// object when one exists.
    revision: String,
    /// Also cross-check the signer against the trust-roots registry
    /// (default path), failing closed on an unlisted signer.
    #[arg(long)]
    trusted: bool,
    /// Path to a trust-roots TOML file. Implies `--trusted`.
    #[arg(long, value_name = "PATH")]
    trust_roots: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<VerifyOpts>("mkit verify", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let h = match super::revspec::resolve_revision(&store, &layout, &opts.revision) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("{e}"), exit::DATAERR),
    };
    let obj = match store.read_object(&h) {
        Ok(o) => o,
        Err(e) => return emit_err(&format!("read: {e}"), exit::NOINPUT),
    };
    let signer: [u8; 32] = match &obj {
        Object::Commit(c) => c.signer,
        Object::Remix(r) => r.signer,
        Object::Tag(t) => t.signer,
        _ => {
            return emit_err(
                "object is not a commit, remix, or signed tag",
                exit::DATAERR,
            );
        }
    };
    let res = match &obj {
        Object::Commit(c) => verify_commit(c),
        Object::Remix(r) => verify_remix(r),
        Object::Tag(t) => verify_tag(t),
        _ => unreachable!("checked above"),
    };
    let mut stdout = std::io::stdout().lock();
    if let Err(e) = res {
        let _ = writeln!(stdout, "bad: {e}");
        return exit::DATAERR;
    }

    let want_trust_check = opts.trusted || opts.trust_roots.is_some();
    if want_trust_check {
        let trust_path = opts
            .trust_roots
            .as_deref()
            .map_or_else(trust_roots::default_trust_roots_path, PathBuf::from);
        if let Err(code) = trust_roots::warn_if_unsafe_trust_roots(
            &trust_path,
            layout.common_dir(),
            opts.trust_roots.is_some(),
        ) {
            return code;
        }
        trust_roots::note_if_missing(&trust_path);
        let entries = match trust_roots::load_entries(&trust_path) {
            Ok(e) => e,
            Err((msg, code)) => return emit_err(&msg, code),
        };
        if let Some(keyid) = trust_roots::find_ed25519_signer(&entries, &signer) {
            let _ = writeln!(
                stdout,
                "ok: signature valid, signer trusted ({})",
                trust_roots::short_keyid(keyid)
            );
            return exit::OK;
        }
        let _ = writeln!(
            stdout,
            "bad: signature valid, but signer {} is not in the trust-roots registry ({})",
            mkit_core::hash::to_hex_bytes(&signer),
            trust_path.display()
        );
        return exit::DATAERR;
    }

    let _ = writeln!(stdout, "ok: signature valid");
    exit::OK
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[String]) -> Result<VerifyOpts, clap::Error> {
        let mut full: Vec<String> = vec!["mkit verify".into()];
        full.extend_from_slice(args);
        VerifyOpts::try_parse_from(full)
    }

    #[test]
    fn parse_args_defaults() {
        let p = parse_args(&["HEAD".into()]).unwrap();
        assert_eq!(p.revision, "HEAD");
        assert!(!p.trusted);
        assert!(p.trust_roots.is_none());
    }

    #[test]
    fn parse_args_accepts_trusted_and_trust_roots() {
        let p = parse_args(&[
            "HEAD".into(),
            "--trusted".into(),
            "--trust-roots".into(),
            "/tmp/tr.toml".into(),
        ])
        .unwrap();
        assert!(p.trusted);
        assert_eq!(p.trust_roots.as_deref(), Some("/tmp/tr.toml"));
    }
}
