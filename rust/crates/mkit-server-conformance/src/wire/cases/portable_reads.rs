//! Canonical byte names, independent of checkout filesystem behavior.

use super::{CaseResult, Ctx, Failure, ensure, want_outcome};
use mkit_core::hash::{Hash, to_hex};
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::pack::PackWriter;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_core::store::MemorySource;
use mkit_core::verify::{Selector, build_disclosure_from, verify_disclosure};
use mkit_transport_connect::generated::{AdvanceOutcome, AdvanceRefsResponse};
use std::collections::BTreeMap;

/// Both inline native verification and scheduled Worker verification can publish
/// these fixtures. Pending is retried with exactly the same signed operation.
pub(super) async fn publish(ctx: &Ctx, pack: &[u8], head: Hash) -> Result<(String, u32), Failure> {
    publish_named(ctx, pack, head, "async-verify", Some(false)).await
}

pub(super) async fn publish_named(
    ctx: &Ctx,
    pack: &[u8],
    head: Hash,
    name: &str,
    visibility: Option<bool>,
) -> Result<(String, u32), Failure> {
    let (repository, advance) =
        super::indexed::ticketed_pair_in(ctx, pack, head, "async", true, name).await?;
    let mut pending = 0;
    for _ in 0..240 {
        match ctx.send::<AdvanceRefsResponse>(&advance).await? {
            Ok(response) => {
                want_outcome(
                    Ok(response.outcome.map_or(0, |outcome| outcome.to_i32())),
                    AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
                )?;
                if let Some(private) = visibility {
                    super::visibility::set_envelope(
                        ctx,
                        &ctx.v2_signer("repository-a")?,
                        &repository,
                        private,
                    )
                    .await?;
                }
                return Ok((repository, pending));
            }
            Err(error) => {
                ensure!(
                    error.code == "unavailable" && error.message == "pack verification pending",
                    "publish: {error}"
                );
                pending += 1;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
    Err("publication did not finish within the bounded retry window".into())
}

/// Assert payload metadata and GET/HEAD/conditional/range behavior at both
/// supported file selectors. The caller already published the exact bytes.
pub(super) async fn file_semantics(
    ctx: &Ctx,
    repository: &str,
    id: &Hash,
    path: &str,
    data: &[u8],
) -> CaseResult {
    let etag = format!("\"{}\"", to_hex(id));
    for url in [
        format!("/{repository}/-/objects/{}", to_hex(id)),
        format!("/{repository}/-/{}/-/{path}", ctx.head("async")),
    ] {
        for method in ["GET", "HEAD"] {
            let reply = ctx.client().read(method, &url, &[]).await?;
            ensure!(reply.status == 200, "{method} file: HTTP {}", reply.status);
            ensure!(
                reply.body.as_ref() == if method == "HEAD" { &[] } else { data },
                "{method} file bytes differ"
            );
            ensure!(
                reply
                    .headers
                    .get("content-length")
                    .and_then(|h| h.to_str().ok())
                    == Some(data.len().to_string().as_str()),
                "file payload length differs"
            );
            let ref_path = url.contains("/-/refs/");
            let expected_type = if ref_path {
                "text/plain; charset=utf-8"
            } else {
                "application/octet-stream"
            };
            ensure!(
                reply
                    .headers
                    .get("content-type")
                    .and_then(|h| h.to_str().ok())
                    == Some(expected_type),
                "file media type differs"
            );
            if ref_path {
                ensure!(
                    reply
                        .headers
                        .get("content-disposition")
                        .and_then(|h| h.to_str().ok())
                        .is_some_and(|h| h.starts_with("inline;") && h.contains(path)),
                    "file disposition differs"
                );
                ensure!(
                    reply
                        .headers
                        .get("x-content-type-options")
                        .is_some_and(|h| h == "nosniff"),
                    "file nosniff differs"
                );
            }
            ensure!(
                reply.headers.get("etag").and_then(|h| h.to_str().ok()) == Some(etag.as_str()),
                "file ETag differs"
            );
            ensure!(
                reply
                    .headers
                    .get("accept-ranges")
                    .is_some_and(|h| h == "bytes"),
                "file range discovery absent"
            );
        }
        let reply = ctx
            .client()
            .read("GET", &url, &[("if-none-match".into(), etag.clone())])
            .await?;
        ensure!(
            reply.status == 304 && reply.body.is_empty(),
            "conditional file read differs"
        );
        ranges(ctx, &url, data).await?;
    }
    Ok(())
}

async fn ranges(ctx: &Ctx, url: &str, data: &[u8]) -> CaseResult {
    for range in ["bytes=0-0", "bytes=0-", "bytes=-1"] {
        let reply = ctx
            .client()
            .read("GET", url, &[("range".into(), range.into())])
            .await?;
        if data.is_empty() {
            ensure!(
                reply.status == 416,
                "empty range {range}: HTTP {}",
                reply.status
            );
            ensure!(
                reply
                    .headers
                    .get("content-range")
                    .is_some_and(|h| h == "bytes */0"),
                "empty range total differs"
            );
        } else {
            let (start, end) = match range {
                "bytes=0-0" => (0, 0),
                "bytes=-1" => (data.len() - 1, data.len() - 1),
                _ => (0, data.len() - 1),
            };
            ensure!(
                reply.status == 206 && reply.body.as_ref() == &data[start..=end],
                "binary range {range} differs"
            );
            let expected = format!("bytes {start}-{end}/{}", data.len());
            ensure!(
                reply
                    .headers
                    .get("content-range")
                    .and_then(|h| h.to_str().ok())
                    == Some(expected.as_str()),
                "binary range metadata differs"
            );
            let head = ctx
                .client()
                .read("HEAD", url, &[("range".into(), range.into())])
                .await?;
            ensure!(
                head.status == 206 && head.body.is_empty(),
                "ranged HEAD differs"
            );
            ensure!(
                head.headers.get("content-length") == reply.headers.get("content-length")
                    && head.headers.get("content-range") == reply.headers.get("content-range"),
                "ranged HEAD metadata differs"
            );
        }
    }
    Ok(())
}

#[derive(Default)]
struct Directory {
    files: BTreeMap<Vec<u8>, Hash>,
    children: BTreeMap<Vec<u8>, Self>,
}

struct Fixture {
    writer: PackWriter,
    source: MemorySource,
    head: Hash,
    root: Hash,
}

impl Fixture {
    fn new(files: &[(Vec<Vec<u8>>, Vec<u8>)]) -> Result<Self, Failure> {
        let mut fixture = Self {
            writer: PackWriter::new_raw_only(),
            source: MemorySource::default(),
            head: [0; 32],
            root: [0; 32],
        };
        let mut root = Directory::default();
        for (path, data) in files {
            let id = fixture.push(Object::Blob(Blob { data: data.clone() }))?;
            let (name, parents) = path.split_last().ok_or("empty fixture path")?;
            let mut dir = &mut root;
            for parent in parents {
                dir = dir.children.entry(parent.clone()).or_default();
            }
            dir.files.insert(name.clone(), id);
        }
        let tree = fixture.tree(root)?;
        fixture.root = tree;
        let key = KeyPair::from_seed([0x34; 32]);
        let mut commit = Commit::new_unannotated(
            tree,
            vec![],
            Identity::ed25519(key.public.0),
            key.public.0,
            b"portable files".to_vec(),
            42,
            [0; 64],
        );
        commit.signature = sign_commit(&commit, &key).map_err(|e| e.to_string())?.0;
        fixture.head = fixture.push(Object::Commit(commit))?;
        Ok(fixture)
    }

    fn push(&mut self, object: Object) -> Result<Hash, Failure> {
        let id = object.id().map_err(|e| e.to_string())?;
        let bytes = serialize(&object).map_err(|e| e.to_string())?;
        self.source
            .insert(id, bytes.clone())
            .map_err(|e| e.to_string())?;
        self.writer
            .push_raw(id, &bytes)
            .map_err(|e| e.to_string())?;
        Ok(id)
    }

    fn tree(&mut self, dir: Directory) -> Result<Hash, Failure> {
        let mut entries: Vec<_> = dir
            .files
            .into_iter()
            .map(|(name, object_hash)| TreeEntry {
                name,
                object_hash,
                mode: EntryMode::Blob,
            })
            .collect();
        for (name, dir) in dir.children {
            entries.push(TreeEntry {
                name,
                object_hash: self.tree(dir)?,
                mode: EntryMode::Tree,
            });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        self.push(Object::Tree(Tree { entries }))
    }

    fn lookup(&self, path: &[Vec<u8>]) -> Result<Hash, Failure> {
        let path: Vec<_> = path.iter().map(Vec::as_slice).collect();
        let disclosure = build_disclosure_from(&self.source, &self.head, &path, Selector::Object)
            .map_err(|e| e.to_string())?;
        let verified = verify_disclosure(&self.head, &disclosure).map_err(|e| e.to_string())?;
        Ok(verified.leaf_id)
    }
}

fn escaped(path: &[Vec<u8>]) -> String {
    path.iter()
        .map(|name| {
            use std::fmt::Write as _;
            name.iter().fold(String::new(), |mut encoded, byte| {
                write!(encoded, "%{byte:02X}").expect("writing a String cannot fail");
                encoded
            })
        })
        .collect::<Vec<_>>()
        .join("/")
}

async fn roundtrip(ctx: &Ctx, files: &[(Vec<Vec<u8>>, Vec<u8>)], ref_reads: bool) -> CaseResult {
    let fixture = Fixture::new(files)?;
    let mut ids = Vec::new();
    for (path, data) in files {
        let id = fixture.lookup(path)?;
        ensure!(
            id == Object::Blob(Blob { data: data.clone() })
                .id()
                .map_err(|e| e.to_string())?,
            "exact core lookup differs"
        );
        ids.push(id);
    }
    let head = fixture.head;
    let root = fixture.root;
    let pack = fixture.writer.finish().map_err(|e| e.to_string())?;
    let (repository, pending) = publish(ctx, &pack, head).await?;
    for ((path, data), id) in files.iter().zip(&ids) {
        let object = ctx
            .client()
            .get(&format!("/{repository}/-/objects/{}", to_hex(id)))
            .await?;
        ensure!(
            object.status == 200 && object.body.as_ref() == data,
            "object bytes differ: HTTP {}",
            object.status
        );
        let url = format!("/{repository}/-/{}/-/{}", ctx.head("async"), escaped(path));
        let reply = ctx.client().get(&url).await?;
        if ref_reads {
            ensure!(
                reply.status == 200 && reply.body.as_ref() == data,
                "exact ref path differs: HTTP {}",
                reply.status
            );
        } else {
            ensure!(
                reply.status == 400,
                "HTTP path over 1024 decoded bytes must be rejected, got {}",
                reply.status
            );
        }
    }
    if ctx.case == "files.byte_distinct_names" {
        let reply = ctx
            .client()
            .get(&format!("/{repository}/-/objects/{}", to_hex(&root)))
            .await?;
        ensure!(
            reply.status == 200,
            "published byte-name tree: HTTP {}",
            reply.status
        );
        let Object::Tree(tree) =
            mkit_core::verify::verify_object_id(&reply.body, &root).map_err(|e| e.to_string())?
        else {
            return Err("byte-name root is not a tree".into());
        };
        let names: Vec<_> = tree
            .entries
            .iter()
            .map(|entry| entry.name.as_slice())
            .collect();
        ensure!(
            names
                == [
                    b"File.txt".as_slice(),
                    "e\u{301}.txt".as_bytes(),
                    b"file.txt",
                    "\u{e9}.txt".as_bytes()
                ],
            "published names are not in canonical byte order"
        );
    }
    ctx.set_note(format!("files={} pending_polls={pending} core_lookup=exact object_readback=exact ref_readback={ref_reads}", files.len()));
    Ok(())
}

pub(super) async fn empty(ctx: Ctx) -> CaseResult {
    let files = [(vec![b"empty.txt".to_vec()], Vec::new())];
    let fixture = Fixture::new(&files)?;
    let id = fixture.lookup(&files[0].0)?;
    let head = fixture.head;
    let pack = fixture.writer.finish().map_err(|e| e.to_string())?;
    let (repository, _) = publish(&ctx, &pack, head).await?;
    file_semantics(&ctx, &repository, &id, "empty.txt", &[]).await
}

pub(super) async fn deep_tree(ctx: Ctx) -> CaseResult {
    // 100 directories plus the file; 101 authenticated path steps, below 128.
    let mut path: Vec<_> = (0..100).map(|_| b"d".to_vec()).collect();
    path.push(b"leaf.txt".to_vec());
    roundtrip(&ctx, &[(path, b"deep leaf".to_vec())], true).await
}

pub(super) async fn long_path(ctx: Ctx) -> CaseResult {
    // Eight legal 255-byte components plus one byte and eight separators = 2049;
    // shorten the final long component by one for exactly 2048 decoded bytes.
    let mut path = vec![vec![b'p'; 255]; 8];
    path[7].pop();
    path.push(b"f".to_vec());
    ensure!(
        path.iter().map(Vec::len).sum::<usize>() + path.len() - 1 == 2048,
        "long path fixture length"
    );
    roundtrip(&ctx, &[(path, b"long leaf".to_vec())], false).await
}

pub(super) async fn byte_names(ctx: Ctx) -> CaseResult {
    let names = [
        b"File.txt".to_vec(),
        b"file.txt".to_vec(),
        "e\u{301}.txt".as_bytes().to_vec(),
        "\u{e9}.txt".as_bytes().to_vec(),
    ];
    let files: Vec<_> = names
        .into_iter()
        .enumerate()
        .map(|(i, name)| (vec![name], format!("distinct payload {i}").into_bytes()))
        .collect();
    let fixture = Fixture::new(&files)?;
    let ids: std::collections::BTreeSet<_> = files
        .iter()
        .map(|(path, _)| fixture.lookup(path))
        .collect::<Result<_, _>>()?;
    ensure!(ids.len() == files.len(), "byte names alias object ids");
    roundtrip(&ctx, &files, true).await
}

pub(super) fn single_file_pack(path: &[u8], data: &[u8]) -> Result<(Vec<u8>, Hash, Hash), Failure> {
    let fixture = Fixture::new(&[(vec![path.to_vec()], data.to_vec())])?;
    let id = fixture.lookup(&[path.to_vec()])?;
    Ok((
        fixture.writer.finish().map_err(|e| e.to_string())?,
        fixture.head,
        id,
    ))
}

pub(super) async fn path_limits(ctx: Ctx) -> CaseResult {
    let mut path = vec![vec![b'p'; 255]; 4];
    path[3].pop();
    path.push(b"f".to_vec());
    ensure!(
        path.iter().map(Vec::len).sum::<usize>() + path.len() - 1 == 1024,
        "HTTP boundary fixture length"
    );
    let fixture = Fixture::new(&[(path.clone(), b"boundary".to_vec())])?;
    let head = fixture.head;
    let pack = fixture.writer.finish().map_err(|e| e.to_string())?;
    let (repository, _) = publish(&ctx, &pack, head).await?;
    let base = format!("/{repository}/-/{}/-/", ctx.head("async"));
    let reply = ctx
        .client()
        .get(&format!("{base}{}", escaped(&path)))
        .await?;
    ensure!(
        reply.status == 200 && reply.body.as_ref() == b"boundary",
        "1024-byte path differs"
    );
    path.last_mut()
        .ok_or("missing boundary component")?
        .push(b'f');
    for rejected in [escaped(&path), "x".repeat(256)] {
        let reply = ctx.client().get(&format!("{base}{rejected}")).await?;
        ensure!(
            reply.status == 400,
            "over-limit HTTP path: {}",
            reply.status
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::store::MAX_TREE_DEPTH;
    use mkit_core::verify::VerifyError;

    #[test]
    fn core_path_depth_boundary_is_128_authenticated_steps() {
        for steps in [MAX_TREE_DEPTH, MAX_TREE_DEPTH + 1] {
            let path = vec![b"d".to_vec(); steps];
            let fixture = Fixture::new(&[(path.clone(), b"leaf".to_vec())]).unwrap();
            let names: Vec<_> = path.iter().map(Vec::as_slice).collect();
            let result =
                build_disclosure_from(&fixture.source, &fixture.head, &names, Selector::Object);
            if steps == MAX_TREE_DEPTH {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(VerifyError::TooManySteps(n)) if n == steps));
            }
        }
    }

    #[test]
    fn component_boundary_is_255_bytes_without_unicode_normalization() {
        let valid = Fixture::new(&[(vec![vec![b'x'; 255]], vec![1])]).unwrap();
        assert!(valid.lookup(&[vec![b'x'; 255]]).is_ok());
        assert!(Fixture::new(&[(vec![vec![b'x'; 256]], vec![1])]).is_err());
    }
}
