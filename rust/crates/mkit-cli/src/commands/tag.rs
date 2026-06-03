//! `mkit tag` — list / create / delete tags.
//!
//! Three creation modes:
//!
//! * **Lightweight** (`mkit tag <name> [<commit>]`): writes a tag ref
//!   pointing straight at the target commit hash. No tag object.
//! * **Annotated** (`mkit tag -a <name> [-m <msg>] [<commit>]`): builds
//!   a [`Tag`] object (target, tagger identity, message, timestamp) and
//!   points the tag ref at the tag-object hash. Unsigned (zero
//!   signature).
//! * **Signed** (`mkit tag -s <name> [-m <msg>] [<commit>]`): an
//!   annotated tag whose 64-byte field is an Ed25519 signature over the
//!   canonical tag signing bytes under the distinct `mkit.tag\0` domain
//!   (SPEC-SIGNING §4a). Verify with `mkit verify <name>`.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use mkit_core::object::{Object, ObjectType, Tag};
use mkit_core::refs;
use mkit_core::serialize;
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::editor::spawn_editor;
use crate::exit;
use crate::format;

const TAG_EDITMSG_TEMPLATE: &str =
    "\n# Write a message for tag.\n# Lines starting with '#' are ignored.\n";

#[derive(Debug, Parser)]
#[command(name = "mkit tag", about = "List, create, or delete tags.")]
struct TagOpts {
    /// Delete the named tag instead of creating one.
    #[arg(short = 'd', long)]
    delete: bool,
    /// Create an unsigned annotated tag object.
    #[arg(short = 'a', long)]
    annotate: bool,
    /// Create a signed annotated tag object (implies -a).
    #[arg(short = 's', long)]
    sign: bool,
    /// Tag message. With -a/-s and no -m, `$EDITOR` is launched.
    #[arg(short = 'm', long)]
    message: Option<String>,
    /// Override the tagger Identity for this tag.
    #[arg(long = "author", value_name = "SPEC")]
    author_spec: Option<String>,
    /// Tag name. Omit to list all tags.
    name: Option<String>,
    /// Commit-ish to tag. Defaults to HEAD.
    target: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<TagOpts>("mkit tag", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    // -s implies -a (a signed tag is an annotated tag with a signature).
    let annotated = opts.annotate || opts.sign;

    match (opts.delete, opts.name.as_deref()) {
        (true, Some(name)) => match refs::delete_tag(&mkit_dir, name) {
            Ok(()) => exit::OK,
            Err(e) => emit_err(&format!("delete tag {name}: {e}"), exit::GENERAL_ERROR),
        },
        (true, None) => super::usage_error("usage: mkit tag -d <name>"),
        (false, None) => {
            if annotated || opts.message.is_some() {
                return super::usage_error("usage: mkit tag -a|-s <name> [-m <msg>] [<commit>]");
            }
            list(&mkit_dir)
        }
        (false, Some(name)) => {
            if annotated {
                create_annotated(&cwd, &mkit_dir, &opts, name)
            } else {
                if opts.message.is_some() {
                    return super::usage_error(
                        "the -m flag requires -a or -s (annotated/signed tag)",
                    );
                }
                create_lightweight(&cwd, &mkit_dir, name, opts.target.as_deref())
            }
        }
    }
}

fn list(mkit_dir: &std::path::Path) -> u8 {
    let tags = match refs::list_tags(mkit_dir) {
        Ok(t) => t,
        Err(e) => return emit_err(&format!("list tags: {e}"), exit::GENERAL_ERROR),
    };
    // Open the store from the repo root (parent of `.mkit`) so we can
    // peek at annotated-tag objects. Listing still works if this fails.
    let store = mkit_dir
        .parent()
        .and_then(|root| ObjectStore::open(root).ok());
    let mut stdout = std::io::stdout().lock();
    for t in tags {
        let short = t
            .hash
            .map(|h| format::short_hash(&h, 8))
            .unwrap_or_default();
        // Surface annotated-tag metadata: if the ref points at a Tag
        // object, mark it and show whether it carries a signature.
        let annotation = t.hash.and_then(|h| {
            let store = store.as_ref()?;
            match store.read_object(&h) {
                Ok(Object::Tag(tag)) => Some(if tag.signature == [0u8; 64] {
                    "\tannotated".to_string()
                } else {
                    "\tsigned".to_string()
                }),
                _ => None,
            }
        });
        let _ = writeln!(
            stdout,
            "{} {short}{}",
            t.name,
            annotation.unwrap_or_default()
        );
    }
    exit::OK
}

/// Resolve the target hash for `target_spec` (or HEAD when `None`).
fn resolve_target(
    store: &ObjectStore,
    mkit_dir: &std::path::Path,
    target_spec: Option<&str>,
) -> Result<mkit_core::hash::Hash, (String, u8)> {
    match target_spec {
        Some(spec) => super::revspec::resolve_revision(store, mkit_dir, spec)
            .map_err(|e| (format!("{e}"), exit::DATAERR)),
        None => match refs::resolve_head(mkit_dir) {
            Ok(Some(h)) => Ok(h),
            _ => Err(("no HEAD commit to tag".to_string(), exit::GENERAL_ERROR)),
        },
    }
}

fn create_lightweight(
    cwd: &std::path::Path,
    mkit_dir: &std::path::Path,
    name: &str,
    target_spec: Option<&str>,
) -> u8 {
    let store = match ObjectStore::open(cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let h = match resolve_target(&store, mkit_dir, target_spec) {
        Ok(h) => h,
        Err((m, c)) => return emit_err(&m, c),
    };
    // `Missing` (issue #206) refuses to silently overwrite an existing
    // tag of the same name.
    match refs::update_tag(mkit_dir, name, refs::RefWriteCondition::Missing, &h) {
        Ok(()) => exit::OK,
        Err(refs::RefError::Conflict(_)) => {
            emit_err(&format!("tag '{name}' already exists"), exit::CANTCREAT)
        }
        Err(e) => emit_err(&format!("write tag {name}: {e}"), exit::CANTCREAT),
    }
}

fn create_annotated(
    cwd: &std::path::Path,
    mkit_dir: &std::path::Path,
    opts: &TagOpts,
    name: &str,
) -> u8 {
    let store = match ObjectStore::open(cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let cfg = match crate::config::read_or_default(cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };

    // Resolve the target object and remember its type for the tag.
    let target = match resolve_target(&store, mkit_dir, opts.target.as_deref()) {
        Ok(h) => h,
        Err((m, c)) => return emit_err(&m, c),
    };
    let target_type = match store.read_object(&target) {
        Ok(o) => o.object_type(),
        Err(e) => return emit_err(&format!("read target: {e}"), exit::NOINPUT),
    };

    // ---- Resolve / prompt for message. ----
    let msg = match &opts.message {
        Some(m) => m.clone(),
        None => match spawn_editor(TAG_EDITMSG_TEMPLATE) {
            Ok(m) if !m.is_empty() => m,
            Ok(_) => return emit_err("empty tag message — aborting", exit::USAGE),
            Err(e) => return emit_err(&format!("editor: {e}"), exit::GENERAL_ERROR),
        },
    };

    // ---- Load signer (also used to derive the tagger fallback). ----
    let mut signer = match super::commit::load_commit_signer(cwd, &cfg) {
        Ok(s) => s,
        Err((m, c)) => return emit_err(&m, c),
    };
    let signer_public = match signer.public_key() {
        Ok(p) => p,
        Err((m, c)) => return emit_err(&m, c),
    };
    let tagger = match super::commit::resolve_author(
        opts.author_spec.as_deref(),
        &cfg.user_identity,
        &signer_public,
    ) {
        Ok(id) => id,
        Err(e) => return emit_err(&format!("tagger: {e}"), exit::CONFIG_ERROR),
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let mut tag = Tag {
        target,
        target_type,
        name: name.as_bytes().to_vec(),
        tagger,
        signer: signer_public,
        message: msg.as_bytes().to_vec(),
        timestamp,
        signature: [0u8; 64],
    };

    if opts.sign {
        match signer.sign_tag(&tag) {
            Ok(sig) => tag.signature = sig,
            Err((m, c)) => return emit_err(&m, c),
        }
    }
    // Annotated-but-unsigned tags keep the zero signature.

    let bytes = match serialize::serialize(&Object::Tag(tag)) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("serialize tag: {e}"), exit::DATAERR),
    };
    let tag_hash = match store.write(&bytes) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("store tag: {e}"), exit::CANTCREAT),
    };
    match refs::update_tag(mkit_dir, name, refs::RefWriteCondition::Missing, &tag_hash) {
        Ok(()) => {}
        Err(refs::RefError::Conflict(_)) => {
            return emit_err(&format!("tag '{name}' already exists"), exit::CANTCREAT);
        }
        Err(e) => return emit_err(&format!("write tag {name}: {e}"), exit::CANTCREAT),
    }
    let mut stderr = std::io::stderr().lock();
    let kind = if opts.sign { "signed" } else { "annotated" };
    let _ = writeln!(
        stderr,
        "created {kind} tag {name} -> {} ({})",
        format::short_hash(&target, 8),
        ObjectType::name(target_type),
    );
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
