use super::grants::{environment_sharding, repository};
use super::visibility::{put_repo, repo_id};
use super::*;
use crate::pipeline::published::PublishedSource;
#[derive(Default)]
struct Source {
    calls: AtomicU32,
    inspection: AtomicBool,
    read_ref: AtomicBool,
    miss: AtomicBool,
}
impl PublishedSource for Source {
    fn inspection_configured(&self) -> bool {
        self.inspection.load(Ordering::SeqCst)
    }
    fn uses_published_values(&self) -> bool {
        // Switching inspection on simulates a source that still supplies live inputs.
        !self.inspection.load(Ordering::SeqCst)
    }
    fn read_ref_enabled(&self) -> bool {
        self.read_ref.load(Ordering::SeqCst)
    }
    fn bucket<'a>(
        &'a self,
        repo: &'a RepoId,
        partition: &'a Partition,
        _: u64,
    ) -> crate::BoxFuture<'a, crate::pipeline::published::PublishedBucket> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.miss.load(Ordering::SeqCst) {
                return Ok(None);
            }
            if D34Shards.ref_index(repo, HEAD) == *partition {
                Ok(Some(vec![(HEAD.into(), B)]))
            } else {
                Ok(Some(vec![]))
            }
        })
    }
}
#[test]
fn anonymous_only_after_authorization_signed_bypass_and_private_transition() {
    let owner = key(1);
    let wire_repo = repository(&owner);
    let mut e = environment_sharding(&owner, AuthorizerRole::Check, false, Sharding::D34);
    let repo = repo_id(&e, &owner);
    put_repo(&e, &repo, None);
    now(e.pipe.meta.inner.apply(
        &D34Shards.ref_index(&repo, HEAD),
        Batch::new()
            .put(
                keys::published_index(&repo.name, HEAD),
                codec::encode_ref_id(&A),
            )
            .put(
                keys::ref_index_key(&repo.name, HEAD),
                codec::encode_ref_id(&A),
            ),
    ))
    .unwrap();
    now(e.pipe.meta.inner.apply(
        &D34Shards.ref_shard(&repo, HEAD),
        Batch::new()
            .put(keys::ref_key(&repo.name, HEAD), codec::encode_ref_id(&A))
            .put(
                keys::published_ref(&repo.name, HEAD),
                codec::encode_ref_id(&A),
            ),
    ))
    .unwrap();
    let source = Arc::new(Source::default());
    e.pipe = e.pipe.with_published_source(source.clone());
    let anonymous = Req::unsigned(Procedure::ListRefs).header("x-repository", &wire_repo);
    let a = e.auth(&anonymous).unwrap();
    let page = block_on(e.pipe.list_refs(&a, "refs/heads/")).unwrap();
    assert_eq!(page[0].id, B);
    assert_eq!(source.calls.load(Ordering::SeqCst), 16);
    let signed = Req::signed_for(&owner, Procedure::ListRefs, &wire_repo, b"r", &nonce(1), T0);
    let a = e.auth(&signed).unwrap();
    assert_eq!(
        block_on(e.pipe.list_refs(&a, "refs/heads/")).unwrap()[0].id,
        A
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 16);
    let read = Req::unsigned(Procedure::ReadRef).header("x-repository", &wire_repo);
    let a = e.auth(&read).unwrap();
    assert_eq!(block_on(e.pipe.read_ref(&a, HEAD)).unwrap(), Some(A));
    source.read_ref.store(true, Ordering::SeqCst);
    assert_eq!(block_on(e.pipe.read_ref(&a, HEAD)).unwrap(), Some(B));
    let signed = Req::signed_for(&owner, Procedure::ReadRef, &wire_repo, b"r", &nonce(2), T0);
    let a = e.auth(&signed).unwrap();
    assert_eq!(block_on(e.pipe.read_ref(&a, HEAD)).unwrap(), Some(A));
    put_repo(&e, &repo, Some(codec::StoredVisibility::Private));
    let before = source.calls.load(Ordering::SeqCst);
    let a = e.auth(&anonymous).unwrap();
    assert_eq!(
        block_on(e.pipe.list_refs(&a, "")).unwrap_err().code(),
        Code::NotFound
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), before);
    put_repo(&e, &repo, Some(codec::StoredVisibility::Public));
    source.inspection.store(true, Ordering::SeqCst);
    source.miss.store(true, Ordering::SeqCst);
    assert_eq!(
        block_on(e.pipe.list_refs(&a, "")).unwrap_err().code(),
        Code::Unavailable
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), before);
    // Inspection keeps writers live and refuses signed readers as well.
    for (signer, expected) in [(&owner, true), (&key(2), false)] {
        let request = Req::signed_for(signer, Procedure::ListRefs, &wire_repo, b"r", &nonce(3), T0);
        let auth = e.auth(&request).unwrap();
        let page = block_on(e.pipe.list_refs(&auth, ""));
        if expected {
            assert_eq!(page.unwrap()[0].id, A);
        } else {
            assert_eq!(page.unwrap_err().code(), Code::Unavailable);
        }
        let request = Req::signed_for(signer, Procedure::ReadRef, &wire_repo, b"r", &nonce(4), T0);
        let auth = e.auth(&request).unwrap();
        let value = block_on(e.pipe.read_ref(&auth, HEAD));
        if expected {
            assert_eq!(value.unwrap(), Some(A));
        } else {
            assert_eq!(value.unwrap_err().code(), Code::Unavailable);
        }
    }
    assert_eq!(source.calls.load(Ordering::SeqCst), before);
    // Malformed signed requests never become anonymous snapshot reads.
    let malformed = anonymous.header("x-signature", "bad");
    assert!(e.auth(&malformed).is_err());
    assert_eq!(source.calls.load(Ordering::SeqCst), before);
}
#[test]
fn private_before_first_push_never_touches_source() {
    let owner = key(1);
    let mut e = environment_sharding(&owner, AuthorizerRole::Check, false, Sharding::D34);
    let repo = repo_id(&e, &owner);
    put_repo(&e, &repo, Some(codec::StoredVisibility::Private));
    let source = Arc::new(Source::default());
    e.pipe = e.pipe.with_published_source(source.clone());
    let a = e
        .auth(&Req::unsigned(Procedure::ListRefs).header("x-repository", &repository(&owner)))
        .unwrap();
    assert_eq!(
        block_on(e.pipe.list_refs(&a, "")).unwrap_err().code(),
        Code::NotFound
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
}

struct MixedSource {
    rows: Vec<(String, Hash)>,
}
impl PublishedSource for MixedSource {
    fn uses_published_values(&self) -> bool {
        true
    }
    fn inspection_configured(&self) -> bool {
        false
    }
    fn bucket<'a>(
        &'a self,
        repo: &'a RepoId,
        p: &'a Partition,
        _: u64,
    ) -> crate::BoxFuture<'a, crate::pipeline::published::PublishedBucket> {
        Box::pin(async move {
            let Partition::RefIndex { bucket, .. } = p else {
                return Ok(None);
            };
            if bucket % 2 == 1 {
                return Ok(None);
            }
            Ok(Some(
                self.rows
                    .iter()
                    .filter(|(n, _)| D34Shards.ref_index(repo, n) == *p)
                    .cloned()
                    .collect(),
            ))
        })
    }
}
#[test]
fn mixed_snapshot_live_pages_make_strict_progress_and_reject_foreign_tokens() {
    let owner = key(1);
    let mut e = environment_sharding(&owner, AuthorizerRole::Check, false, Sharding::D34);
    let repo = repo_id(&e, &owner);
    put_repo(&e, &repo, None);
    let names = (0..1000)
        .map(|n| format!("refs/heads/n{n:04}"))
        .collect::<Vec<_>>();
    for name in &names {
        now(e.pipe.meta.inner.apply(
            &D34Shards.ref_index(&repo, name),
            Batch::new().put(
                keys::published_index(&repo.name, name),
                codec::encode_ref_id(&A),
            ),
        ))
        .unwrap();
    }
    e.pipe = e.pipe.with_published_source(Arc::new(MixedSource {
        rows: names.iter().map(|n| (n.clone(), B)).collect(),
    }));
    let req = Req::unsigned(Procedure::ListRefs).header("x-repository", &repository(&owner));
    let a = e.auth(&req).unwrap();
    let mut token = None;
    let mut all = Vec::new();
    loop {
        let page = block_on(
            e.pipe
                .list_refs_page(&a, "refs/heads/", Some(7), token.as_deref()),
        )
        .unwrap();
        assert!(page.refs.len() <= 7);
        for entry in &page.refs {
            let full = format!("refs/heads/{}", entry.name);
            let Partition::RefIndex { bucket, .. } = D34Shards.ref_index(&repo, &full) else {
                unreachable!()
            };
            assert_eq!(entry.id, if bucket % 2 == 0 { B } else { A });
            all.push(full);
        }
        assert!(all.windows(2).all(|w| w[0] < w[1]));
        if let Some(next) = page.next {
            assert!(!page.refs.is_empty());
            assert_ne!(token, Some(next.clone()));
            token = Some(next);
        } else {
            break;
        }
    }
    assert_eq!(all, names);
    let page = block_on(e.pipe.list_refs_page(&a, "", Some(1), None)).unwrap();
    let other = Req::unsigned(Procedure::ListRefs).header(
        "x-repository",
        &format!("{}/other", repository(&owner).split('/').next().unwrap()),
    );
    let other = e.auth(&other).unwrap();
    let mut otherrepo = repo;
    otherrepo.name = RepoName::new("other").unwrap();
    put_repo(&e, &otherrepo, None);
    assert_eq!(
        block_on(
            e.pipe
                .list_refs_page(&other, "", Some(1), page.next.as_deref())
        )
        .err()
        .unwrap()
        .code(),
        Code::InvalidArgument
    );
}
