//! `mkit export-legacy` — read-only escape hatch for a pre-merkle
//! (incompatible-format) repository (issue #713).
//!
//! `ObjectStore::open` permanently refuses a repository whose
//! `.mkit/format` marker isn't `bmt-v1` (SPEC-MERKLE-OBJECTS §7); that
//! gate is deliberate and stays (see `docs/adr/0001-merkelize-chunkedblob-and-tree.md`).
//! This command is the documented way out: it walks `<src>` using the
//! historical flat-BLAKE3 addressing rule, translates every object
//! reachable from its refs into a fresh current-format repository at
//! `<dst>`, and re-signs every `Commit`/`Remix`/`Tag` whose bytes changed
//! with a dedicated export key (see `mkit_core::ops::legacy_export` for
//! why re-signing is unavoidable). `<src>` is never written to.
//!
//! Each translated branch/tag head gets an `export-legacy/v1`
//! attestation recording the old->new commit id mapping, signed with the
//! same export key, so the translation is auditable rather than silently
//! reattributed.
//!
//! Scope: local branches (`refs/heads/*`) and tags (`refs/tags/*`), plus
//! `HEAD`. Remote-tracking refs (`refs/remotes/*`) are not translated —
//! they are cached copies of another repository's heads, which would
//! need their own export.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use clap::Parser;
use mkit_attest::{
    Envelope, PAYLOAD_TYPE_IN_TOTO, Sig, Signer as _, statement, store as attest_store,
};
use mkit_core::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::ops::legacy_export::{self, LegacyExportError};
use mkit_core::sign::{KeyPair, load_key, save_key};
use mkit_core::store::ObjectStore;

use crate::exit;
use crate::format;

/// `export-legacy/v1` predicate type (mirrors `git_import`'s
/// `git-import/v1` naming convention for translation provenance).
const PREDICATE_TYPE: &str =
    "https://github.com/officialunofficial/mkit/spec/predicate/export-legacy/v1";

/// Default re-signing key FILE NAME under `<dst>/.mkit/keys/` (the
/// source is read-only and never gets a key written into it). Joined
/// onto `RepoLayout::keys_dir()` at the call site rather than spelling
/// `keys/export-legacy.key` here, so it can never double up the `keys/`
/// segment.
const EXPORT_KEY_FILE_LEAF: &str = "export-legacy.key";

#[derive(Debug, Parser)]
#[command(
    name = "mkit export-legacy",
    about = "Translate a pre-merkle (incompatible-format) repository into a fresh current-format repository."
)]
struct ExportLegacyOpts {
    /// Path to the incompatible-format source repository. Read-only —
    /// never modified.
    src: String,
    /// Path for the new current-format repository. Must not already
    /// exist.
    dst: String,
    /// Path to the re-signing key (32-byte Ed25519 seed). Default:
    /// `<dst>/.mkit/keys/export-legacy.key`, generated on first use.
    #[arg(long, value_name = "PATH")]
    key: Option<String>,
    /// Machine-readable JSON on stdout.
    #[arg(long)]
    json: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match crate::clap_shim::parse::<ExportLegacyOpts>("mkit export-legacy", args) {
        Ok(o) => o,
        Err(code) => return code,
    };

    match run_export(&opts) {
        Ok(summary) => {
            summary.print(opts.json);
            exit::OK
        }
        Err((msg, code)) => emit_err(&msg, code),
    }
}

type CmdResult<T> = Result<T, (String, u8)>;

fn run_export(opts: &ExportLegacyOpts) -> CmdResult<Summary> {
    let src_layout = RepoLayout::single(PathBuf::from(&opts.src));
    let dst_layout = RepoLayout::single(PathBuf::from(&opts.dst));

    if dst_layout.common_dir().exists() {
        return Err((
            format!(
                "{} already contains a .mkit repository — export-legacy creates a fresh \
                 repository and refuses to write into an existing one",
                opts.dst
            ),
            exit::CANTCREAT,
        ));
    }

    // Classify BEFORE touching `dst` — an already-current or
    // unrecognised source must refuse cleanly without leaving a stray
    // empty repository behind.
    require_legacy_source(&src_layout, &opts.src)?;

    let dst = ObjectStore::init(&dst_layout)
        .map_err(|e| (format!("init {}: {e}", opts.dst), exit::CANTCREAT))?;

    let key_path: PathBuf = match &opts.key {
        Some(p) => PathBuf::from(p),
        None => dst_layout.keys_dir().join(EXPORT_KEY_FILE_LEAF),
    };
    let kp = load_or_generate_key(&key_path)?;

    let report = legacy_export::export_legacy_repo(&src_layout, &dst, &dst_layout, &kp)
        .map_err(|e| (e.to_string(), export_error_code(&e)))?;

    let attested = mint_attestations(&dst_layout, &dst, &report, &kp)?;

    Ok(Summary {
        src: opts.src.clone(),
        dst: opts.dst.clone(),
        key_path,
        report,
        attested,
    })
}

/// Refuse early — before `dst` is touched — if `src` is not a legacy
/// (pre-merkle, unmarked) repository. `export_legacy_repo` re-checks
/// this internally too (defense in depth), but by then `dst` has
/// already been `ObjectStore::init`-ed; this pre-check keeps a refused
/// run from leaving a stray empty repository on disk.
fn require_legacy_source(src_layout: &RepoLayout, src_display: &str) -> CmdResult<()> {
    let status = legacy_export::classify(src_layout)
        .map_err(|e| (format!("{src_display}: {e}"), exit::NOINPUT))?;
    match status {
        legacy_export::LegacyFormatStatus::Legacy => Ok(()),
        legacy_export::LegacyFormatStatus::AlreadyCurrent => {
            let e = LegacyExportError::AlreadyCurrentFormat(src_display.to_owned());
            Err((e.to_string(), export_error_code(&e)))
        }
        legacy_export::LegacyFormatStatus::Unknown(found) => {
            let e = LegacyExportError::UnknownFormat(src_display.to_owned(), found);
            Err((e.to_string(), export_error_code(&e)))
        }
    }
}

/// Map a translation failure to a CLI exit code. Data-shaped failures
/// (corrupt/missing legacy object, unrecognised format) are
/// [`exit::DATAERR`]; everything else — including any variant added
/// later, since `LegacyExportError` is `#[non_exhaustive]` — is a
/// general failure.
fn export_error_code(e: &LegacyExportError) -> u8 {
    match e {
        LegacyExportError::AlreadyCurrentFormat(_) | LegacyExportError::UnknownFormat(_, _) => {
            exit::USAGE
        }
        LegacyExportError::ObjectNotFound(_, _)
        | LegacyExportError::HashMismatch(_, _)
        | LegacyExportError::Decode(_, _)
        | LegacyExportError::TooDeep(_) => exit::DATAERR,
        _ => exit::GENERAL_ERROR,
    }
}

fn load_or_generate_key(path: &Path) -> CmdResult<KeyPair> {
    if path.exists() {
        return load_key(path).map_err(|e| {
            (
                format!("load export key {}: {e}", path.display()),
                exit::GENERAL_ERROR,
            )
        });
    }
    let kp = KeyPair::generate().map_err(|e| (format!("rng failed: {e}"), exit::GENERAL_ERROR))?;
    save_key(path, &kp).map_err(|e| {
        (
            format!("save export key {}: {e}", path.display()),
            exit::CANTCREAT,
        )
    })?;
    Ok(kp)
}

/// Mint one `export-legacy/v1` attestation per translated branch/tag
/// head, subject = the NEW commit-ish object, predicate = the OLD id it
/// was translated from. Mirrors `git_import::mint_attestations`.
fn mint_attestations(
    dst_layout: &RepoLayout,
    dst: &ObjectStore,
    report: &legacy_export::ExportReport,
    kp: &KeyPair,
) -> CmdResult<usize> {
    let mut count = 0usize;
    let mut heads: Vec<(&str, Hash, Hash)> = Vec::new();
    for (name, old, new) in &report.branches {
        heads.push((name.as_str(), *old, *new));
    }
    for (name, old, new) in &report.tags {
        heads.push((name.as_str(), *old, *new));
    }
    for (name, old, new) in heads {
        let new_bytes = dst.read(&new).map_err(|e| {
            (
                format!("read translated object {}: {e}", mkit_core::to_hex(&new)),
                exit::GENERAL_ERROR,
            )
        })?;
        let predicate = format!(
            "{{\"oldObjectId\":\"{}\",\"refName\":\"{}\",\"schemaVersion\":1,\"specVersion\":1}}",
            mkit_core::to_hex(&old),
            format::json_escape(name),
        );
        let stmt = statement::encode(&statement::Statement {
            subjects: vec![statement::Subject {
                name: Some(name.to_owned()),
                digest_blake3_hex: mkit_core::to_hex(&new),
                digest_sha256_hex: statement::sha256_hex(&new_bytes),
            }],
            predicate_type: PREDICATE_TYPE.to_owned(),
            predicate_jcs: predicate.as_bytes(),
        })
        .map_err(|e| (format!("encode statement: {e}"), exit::GENERAL_ERROR))?;
        let pae = mkit_attest::pae_of(PAYLOAD_TYPE_IN_TOTO, stmt.as_bytes());
        let mut signer = mkit_attest::RepoKeySigner::new(KeyPair {
            public: kp.public,
            secret: kp.secret.clone(),
        });
        let sig = signer
            .sign(&pae)
            .map_err(|e| (format!("sign attestation: {e}"), exit::GENERAL_ERROR))?;
        let keyid = signer
            .keyid()
            .map_err(|e| (format!("attestation keyid: {e}"), exit::GENERAL_ERROR))?;
        let envelope = Envelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.to_owned(),
            payload: stmt.into_bytes(),
            signatures: vec![Sig { keyid, sig }],
        };
        let encoded = envelope
            .encode()
            .map_err(|e| (format!("encode envelope: {e}"), exit::GENERAL_ERROR))?;
        attest_store::save(dst_layout, &new, encoded.as_bytes())
            .map_err(|e| (format!("save attestation: {e}"), exit::CANTCREAT))?;
        count += 1;
    }
    Ok(count)
}

struct Summary {
    src: String,
    dst: String,
    key_path: PathBuf,
    report: legacy_export::ExportReport,
    attested: usize,
}

impl Summary {
    fn print(&self, json: bool) {
        if json {
            let mut out = format!(
                "{{\"src\":\"{}\",\"dst\":\"{}\",\"key\":\"{}\",\"objectsTranslated\":{},\"attested\":{},\"branches\":[",
                format::json_escape(&self.src),
                format::json_escape(&self.dst),
                format::json_escape(&self.key_path.display().to_string()),
                self.report.objects_translated,
                self.attested,
            );
            for (i, (name, old, new)) in self.report.branches.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(
                    out,
                    "{{\"ref\":\"{}\",\"old\":\"{}\",\"new\":\"{}\"}}",
                    format::json_escape(name),
                    mkit_core::to_hex(old),
                    mkit_core::to_hex(new)
                );
            }
            out.push_str("],\"tags\":[");
            for (i, (name, old, new)) in self.report.tags.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(
                    out,
                    "{{\"ref\":\"{}\",\"old\":\"{}\",\"new\":\"{}\"}}",
                    format::json_escape(name),
                    mkit_core::to_hex(old),
                    mkit_core::to_hex(new)
                );
            }
            out.push(']');
            out.push('}');
            println!("{out}");
            return;
        }
        eprintln!(
            "exported {} -> {} ({} object(s) translated, {} attestation(s))",
            self.src, self.dst, self.report.objects_translated, self.attested
        );
        for (name, old, new) in &self.report.branches {
            println!(
                "branch {name}: {} -> {}",
                &mkit_core::to_hex(old)[..8],
                &mkit_core::to_hex(new)[..8]
            );
        }
        for (name, old, new) in &self.report.tags {
            println!(
                "tag {name}: {} -> {}",
                &mkit_core::to_hex(old)[..8],
                &mkit_core::to_hex(new)[..8]
            );
        }
        eprintln!("re-signing key: {}", self.key_path.display());
    }
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::ExportLegacyOpts;

    #[test]
    fn parse_required_positionals() {
        let p = ExportLegacyOpts::try_parse_from(["mkit export-legacy", "src", "dst"]).unwrap();
        assert_eq!(p.src, "src");
        assert_eq!(p.dst, "dst");
        assert!(p.key.is_none());
        assert!(!p.json);
    }

    #[test]
    fn parse_all_flags() {
        let p = ExportLegacyOpts::try_parse_from([
            "mkit export-legacy",
            "src",
            "dst",
            "--key",
            "mykey",
            "--json",
        ])
        .unwrap();
        assert_eq!(p.key.as_deref(), Some("mykey"));
        assert!(p.json);
    }

    #[test]
    fn parse_missing_dst_rejected() {
        assert!(ExportLegacyOpts::try_parse_from(["mkit export-legacy", "src"]).is_err());
    }
}
