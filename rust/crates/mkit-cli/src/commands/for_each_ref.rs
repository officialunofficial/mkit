//! `mkit for-each-ref [--format=<fmt>] [<pattern>...]` — iterate refs with
//! an optional format string, like `git for-each-ref`.
//!
//! Default line: `<objectname> <objecttype>\t<refname>`. `--format`
//! substitutes the common atoms `%(refname)`, `%(refname:short)`,
//! `%(objectname)`, `%(objectname:short)`, `%(objecttype)` (and `%%` for a
//! literal `%`). The object id is 64-hex BLAKE3. Optional patterns filter
//! to refs whose full name equals or is under the pattern.

use std::io::Write;

use clap::Parser;
use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;
use crate::format;

const DEFAULT_ABBREV: usize = 7;

#[derive(Debug, Parser)]
#[command(
    name = "mkit for-each-ref",
    about = "Iterate refs with an optional format."
)]
struct ForEachRefOpts {
    /// Output format with `%(atom)` substitutions.
    #[arg(long)]
    format: Option<String>,
    /// Optional ref-name patterns (prefix match) to filter the listing.
    patterns: Vec<String>,
}

struct RefRow {
    refname: String,
    short: String,
    hash: Hash,
    objtype: &'static str,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<ForEachRefOpts>("mkit for-each-ref", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = super::resolve_layout(&cwd);
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };

    let mut rows: Vec<RefRow> = Vec::new();
    let heads = match refs::list_refs(&layout) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("list refs: {e}"), exit::GENERAL_ERROR),
    };
    let tags = match refs::list_tags(&layout) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("list tags: {e}"), exit::GENERAL_ERROR),
    };
    push_rows(&store, &mut rows, &heads, "refs/heads/");
    push_rows(&store, &mut rows, &tags, "refs/tags/");
    match refs::list_remote_names(&layout) {
        Ok(remotes) => {
            for remote in remotes {
                match refs::list_remote_refs(&layout, &remote) {
                    Ok(rs) => {
                        push_rows(&store, &mut rows, &rs, &format!("refs/remotes/{remote}/"));
                    }
                    Err(e) => {
                        return emit_err(&format!("list remote refs: {e}"), exit::GENERAL_ERROR);
                    }
                }
            }
        }
        Err(e) => return emit_err(&format!("list remotes: {e}"), exit::GENERAL_ERROR),
    }
    rows.sort_by(|a, b| a.refname.cmp(&b.refname));

    if !opts.patterns.is_empty() {
        rows.retain(|r| {
            opts.patterns
                .iter()
                .any(|p| ref_matches_pattern(&r.refname, p))
        });
    }

    let mut stdout = std::io::stdout().lock();
    for r in &rows {
        let line = match &opts.format {
            Some(fmt) => match render_format(fmt, r) {
                Ok(s) => s,
                Err(msg) => return emit_err(&msg, exit::USAGE),
            },
            None => format!("{} {}\t{}", format::hex_hash(&r.hash), r.objtype, r.refname),
        };
        let _ = writeln!(stdout, "{line}");
    }
    exit::OK
}

/// git matches a ref against a literal pattern either completely or up to a
/// `/` boundary, so `refs/heads` and `refs/heads/` both select every branch
/// ref. Trim a trailing `/` from the pattern so it doesn't become an empty
/// (always-failing) `refs/heads//` component.
fn ref_matches_pattern(refname: &str, pattern: &str) -> bool {
    let p = pattern.trim_end_matches('/');
    refname == p || refname.starts_with(&format!("{p}/"))
}

fn push_rows(store: &ObjectStore, out: &mut Vec<RefRow>, rs: &[refs::Ref], prefix: &str) {
    for r in rs {
        let Some(h) = r.hash else { continue };
        out.push(RefRow {
            refname: format!("{prefix}{}", r.name),
            short: r.name.clone(),
            hash: h,
            objtype: object_type_name(store, &h),
        });
    }
}

/// git-compatible object type of the ref target (`commit`/`tag`/…; mkit's
/// `remix` is the one non-git type). Unreadable target → `commit` (the
/// dominant case) rather than failing the whole listing.
fn object_type_name(store: &ObjectStore, h: &Hash) -> &'static str {
    match store.read_object(h) {
        Ok(Object::Tag(_)) => "tag",
        Ok(Object::Tree(_)) => "tree",
        Ok(Object::Blob(_) | Object::ChunkedBlob(_)) => "blob",
        Ok(Object::Remix(_)) => "remix",
        // Commit is the dominant case; an unreadable target also defaults
        // here rather than failing the whole listing.
        _ => "commit",
    }
}

/// Substitute `%(atom)` tokens (and `%%`) in `fmt` for one ref row.
fn render_format(fmt: &str, r: &RefRow) -> Result<String, String> {
    let mut out = String::with_capacity(fmt.len());
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('%') => {
                chars.next();
                out.push('%');
            }
            Some('(') => {
                chars.next(); // consume '('
                let mut atom = String::new();
                let mut closed = false;
                for ac in chars.by_ref() {
                    if ac == ')' {
                        closed = true;
                        break;
                    }
                    atom.push(ac);
                }
                if !closed {
                    return Err(format!("unterminated format atom in '{fmt}'"));
                }
                out.push_str(&atom_value(&atom, r)?);
            }
            _ => out.push('%'),
        }
    }
    Ok(out)
}

fn atom_value(atom: &str, r: &RefRow) -> Result<String, String> {
    Ok(match atom {
        "refname" => r.refname.clone(),
        "refname:short" => r.short.clone(),
        "objectname" => format::hex_hash(&r.hash),
        "objectname:short" => format::short_hash(&r.hash, DEFAULT_ABBREV),
        "objecttype" => r.objtype.to_string(),
        other => return Err(format!("unsupported format atom: %({other})")),
    })
}

use super::error as emit_err;
