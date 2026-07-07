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
use mkit_core::layout::RepoLayout;
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
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct TagOpts {
    /// Delete the named tag instead of creating one.
    #[arg(short = 'd', long)]
    delete: bool,
    /// List tags, optionally filtered by a shell glob pattern
    /// (`mkit tag -l 'v*'`).
    #[arg(short = 'l', long = "list")]
    list: bool,
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
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };

    // -s implies -a (a signed tag is an annotated tag with a signature).
    let annotated = opts.annotate || opts.sign;

    // `-l`/`--list` forces list mode, with the positional treated as a
    // glob filter (like `git tag -l '<pattern>'`). `-l` with `-d` is an
    // error, like git (the modes are mutually exclusive).
    if opts.list {
        if opts.delete {
            return super::usage_error("mkit tag: -l and -d are mutually exclusive");
        }
        return list(&layout, opts.name.as_deref());
    }

    match (opts.delete, opts.name.as_deref()) {
        (true, Some(name)) => {
            let was = refs::read_tag(&layout, name).ok().flatten();
            match refs::delete_tag(&layout, name) {
                Ok(()) => {
                    let mut stderr = std::io::stderr().lock();
                    match was {
                        Some(h) => {
                            let _ = writeln!(
                                stderr,
                                "Deleted tag '{name}' (was {})",
                                format::short_hash(&h, format::SUMMARY_ABBREV)
                            );
                        }
                        None => {
                            let _ = writeln!(stderr, "Deleted tag '{name}'");
                        }
                    }
                    exit::OK
                }
                Err(e) => emit_err(&format!("delete tag {name}: {e}"), exit::GENERAL_ERROR),
            }
        }
        (true, None) => super::usage_error("usage: mkit tag -d <name>"),
        (false, None) => {
            if annotated || opts.message.is_some() {
                return super::usage_error("usage: mkit tag -a|-s <name> [-m <msg>] [<commit>]");
            }
            list(&layout, None)
        }
        (false, Some(name)) => {
            if annotated {
                create_annotated(&layout, &opts, name)
            } else {
                if opts.message.is_some() {
                    return super::usage_error(
                        "the -m flag requires -a or -s (annotated/signed tag)",
                    );
                }
                create_lightweight(&layout, name, opts.target.as_deref())
            }
        }
    }
}

fn list(layout: &RepoLayout, pattern: Option<&str>) -> u8 {
    let mut tags = match refs::list_tags(layout) {
        Ok(t) => t,
        Err(e) => return emit_err(&format!("list tags: {e}"), exit::GENERAL_ERROR),
    };
    if let Some(pat) = pattern {
        tags.retain(|t| super::branch::glob_match(pat, &t.name));
    }
    // Open the store so we can peek at annotated-tag objects. Listing
    // still works if this fails.
    let store = ObjectStore::open(layout).ok();
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
    layout: &RepoLayout,
    target_spec: Option<&str>,
) -> Result<mkit_core::hash::Hash, (String, u8)> {
    match target_spec {
        Some(spec) => super::revspec::resolve_revision(store, layout, spec)
            .map_err(|e| (format!("{e}"), exit::DATAERR)),
        None => match refs::resolve_head(layout) {
            Ok(Some(h)) => Ok(h),
            _ => Err(("no HEAD commit to tag".to_string(), exit::GENERAL_ERROR)),
        },
    }
}

fn create_lightweight(layout: &RepoLayout, name: &str, target_spec: Option<&str>) -> u8 {
    let store = match ObjectStore::open(layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let h = match resolve_target(&store, layout, target_spec) {
        Ok(h) => h,
        Err((m, c)) => return emit_err(&m, c),
    };
    // A lightweight tag publishes a root ref to an existing object, so it is
    // also a gc root publisher: hold the lock and re-verify the target under
    // it before writing the ref, so a concurrent `gc --grace-secs 0` can't
    // prune the (possibly unreachable) target between resolve and publish
    // (#267).
    let _lock = match super::acquire_worktree_lock(layout) {
        Ok(l) => l,
        Err(code) => return code,
    };
    if !store.contains(&h) {
        return emit_err(
            &format!(
                "tag target {} no longer exists (pruned concurrently?); aborting",
                format::short_hash(&h, 8)
            ),
            exit::GENERAL_ERROR,
        );
    }
    // `Missing` (issue #206) refuses to silently overwrite an existing
    // tag of the same name.
    match refs::update_tag(layout, name, refs::RefWriteCondition::Missing, &h) {
        Ok(()) => exit::OK,
        Err(refs::RefError::Conflict(_)) => {
            emit_err(&format!("tag '{name}' already exists"), exit::CANTCREAT)
        }
        Err(e) => emit_err(&format!("write tag {name}: {e}"), exit::CANTCREAT),
    }
}

fn create_annotated(layout: &RepoLayout, opts: &TagOpts, name: &str) -> u8 {
    let store = match ObjectStore::open(layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let cfg = match crate::config::read_or_default(layout) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };

    // Resolve the target object and remember its type for the tag.
    let target = match resolve_target(&store, layout, opts.target.as_deref()) {
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
    let mut signer = match super::commit::load_commit_signer(layout, &cfg) {
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

    // Hold the repo lock across the tag-object write + ref publish so a
    // concurrent `gc --grace-secs 0` can't prune the just-written tag object
    // before its ref makes it reachable (#267). The repo was validated above
    // (store open), so a non-repo already reported cleanly — not as a lock
    // error. Acquired here (after the editor/signing) to keep the hold tight.
    let _lock = match super::acquire_worktree_lock(layout) {
        Ok(l) => l,
        Err(code) => return code,
    };
    // The target was resolved before the lock; re-verify it still exists now
    // that gc can't run, so we never publish a tag pointing at an object a
    // concurrent `gc --grace-secs 0` pruned in the meantime (#267).
    if !store.contains(&target) {
        return emit_err(
            &format!(
                "tag target {} no longer exists (pruned concurrently?); aborting",
                format::short_hash(&target, 8)
            ),
            exit::GENERAL_ERROR,
        );
    }

    let bytes = match serialize::serialize(&Object::Tag(tag)) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("serialize tag: {e}"), exit::DATAERR),
    };
    let tag_hash = match store.write(&bytes) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("store tag: {e}"), exit::CANTCREAT),
    };
    match refs::update_tag(layout, name, refs::RefWriteCondition::Missing, &tag_hash) {
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

use super::error as emit_err;
