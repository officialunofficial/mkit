//! Proof contexts use published refs and membership, including warm cache hits.
use super::*;

struct Blocked(Hash);
impl TakedownGate for Blocked {
    fn stops_descent(&self, _: &RepoId, id: &Hash) -> bool {
        *id == self.0
    }
    fn check<'a>(
        &'a self,
        _: &'a RepoId,
        id: &'a Hash,
    ) -> crate::BoxFuture<'a, Result<TakedownVerdict, ServerError>> {
        Box::pin(async move {
            Ok(if *id == self.0 {
                TakedownVerdict::NotFound
            } else {
                TakedownVerdict::Clear
            })
        })
    }
}

struct FailedChunkGate(Hash);
impl TakedownGate for FailedChunkGate {
    fn check<'a>(
        &'a self,
        _: &'a RepoId,
        id: &'a Hash,
    ) -> crate::BoxFuture<'a, Result<TakedownVerdict, ServerError>> {
        Box::pin(async move {
            if *id == self.0 {
                Err(ServerError::new(Code::OutOfRange, "gate failed"))
            } else {
                Ok(TakedownVerdict::Clear)
            }
        })
    }
}

#[test]
fn range_proof_gate_errors_cannot_be_deferred_as_selector_errors() {
    let (fx, d) = published();
    let (fx, admission, proofs) = counters(fx);
    let fx = with_seams(fx, |s| {
        s.takedown = Arc::new(FailedChunkGate(id(&d.chunks[0])));
    });
    for method in ["GET", "HEAD"] {
        let got = read(fx.request(
            method,
            &fx.ref_url("room", "main", "chunked.bin"),
            Some("proof=1&range=0-0"),
            &[("if-none-match", "*")],
        ));
        assert_eq!(got.status, 503);
        assert_eq!(got.header("Cache-Control"), Some("no-store"));
        assert!(got.header("ETag").is_none());
    }
    assert!(admission.seen.lock().unwrap().is_empty());
    assert!(proofs.0.lock().unwrap().is_empty());
}

#[test]
fn proof_validators_precede_selector_and_cap_errors_without_building() {
    let (fx, d) = published();
    let (mut fx, admission, proofs) = counters(fx);
    let config = fx.pipe.cfg.http_objects.as_mut().unwrap();
    config.max_proof_content_bytes = 1;
    config.max_proof_bundle_bytes = 1;
    for (leaf, proof_path, selector) in [
        (id(&d.small), "small.txt", ""),
        (id(&d.small), "small.txt", "&range=0-1"),
        (id(&d.small), "small.txt", "&range=0-18446744073709551615"),
        (id(&d.root), "", "&range=0-0"),
    ] {
        let path = fx.object_url("room", &leaf);
        let query = format!(
            "proof=1&commit={}&path={proof_path}{selector}",
            to_hex(&d.head())
        );
        for method in ["GET", "HEAD"] {
            assert_eq!(
                read(fx.request(method, &path, Some(&query), &[])).status,
                416
            );
            assert_eq!(
                read(fx.request(method, &path, Some(&query), &[("if-none-match", "*")])).status,
                304
            );
        }
    }
    let fx = with_seams(fx, |s| {
        s.proofs = Arc::new(crate::http_objects::UnsupportedProofs);
    });
    for method in ["GET", "HEAD"] {
        assert_eq!(
            read(fx.request(
                method,
                &fx.ref_url("room", "main", "small.txt"),
                Some("proof=1"),
                &[("if-none-match", "*")]
            ))
            .status,
            304
        );
    }
    assert!(admission.seen.lock().unwrap().is_empty());
    assert!(proofs.0.lock().unwrap().is_empty());
}

fn counters(fx: Fx) -> (Fx, Arc<Admit>, Arc<Proofs>) {
    let admission = Arc::new(Admit {
        seen: Mutex::default(),
        ended: Arc::default(),
        challenge: false,
    });
    let proofs = Arc::new(Proofs(Mutex::default()));
    let fx = with_seams(fx, |s| {
        s.admission = admission.clone();
        s.proofs = proofs.clone();
    });
    (fx, admission, proofs)
}

fn same_response(got: &Got, expected: &Got) {
    assert_eq!(
        (got.status, &got.headers, &got.body),
        (expected.status, &expected.headers, &expected.body)
    );
}

#[test]
fn proof_context_requires_published_reachability_even_for_a_cached_leaf() {
    let fx = fixture();
    let d = data();
    let child = commit(&d.root, &[&d.commit], "child");
    let orphan = commit(&d.root, &[], "orphan");
    let mut objects = d.refs();
    objects.extend([&child, &orphan]);
    fx.push("room", &objects, id(&child), None);
    // The independently published member orphan shares the exact same leaf.
    // Leaf reachability must not establish reachability of its proof commit.
    assert_eq!(fx.get(&fx.object_url("room", &id(&d.small))).status, 200);
    let (fx, admission, proofs) = counters(fx);
    let path = fx.object_url("room", &id(&d.small));
    for method in ["GET", "HEAD"] {
        for proof_commit in [id(&child), d.head()] {
            let query = format!("proof=1&commit={}&path=small.txt", to_hex(&proof_commit));
            let cached = read(fx.request(method, &path, Some(&query), &[("if-none-match", "*")]));
            assert_eq!(cached.status, 304);
            assert_eq!(
                cached.header("X-Mkit-Commit"),
                Some(to_hex(&proof_commit).as_str())
            );
            assert_eq!(
                read(fx.request(method, &path, Some(&query), &[])).status,
                200
            );
        }
    }
    let admitted = admission.seen.lock().unwrap().len();
    let built = proofs.0.lock().unwrap().len();
    for method in ["GET", "HEAD"] {
        let missing = read(fx.request(method, &fx.object_url("room", &[99; 32]), None, &[]));
        for (proof_commit, proof_path) in [
            (id(&orphan), "small.txt"),
            ([98; 32], "small.txt"),
            (d.head(), "big.bin"),
            (d.head(), "missing"),
        ] {
            let query = format!("proof=1&commit={}&path={proof_path}", to_hex(&proof_commit));
            let got = read(fx.request(method, &path, Some(&query), &[("if-none-match", "*")]));
            same_response(&got, &missing);
        }
    }
    assert_eq!(admission.seen.lock().unwrap().len(), admitted);
    assert_eq!(proofs.0.lock().unwrap().len(), built);
}

#[test]
fn ref_proofs_never_fall_back_to_a_live_value() {
    let (fx, d) = published();
    let repo = fx.repo_id("room");
    let partition = fx.pipe.shards.ref_shard(&repo, HEAD);
    block_on(fx.pipe.meta.inner.apply(
        &partition,
        Batch::new().put(
            keys::ref_key(&repo.name, HEAD),
            codec::encode_ref_id(&[99; 32]),
        ),
    ))
    .unwrap();
    let (fx, admission, proofs) = counters(fx);
    let path = fx.ref_url("room", "main", "small.txt");
    let got = read(fx.request("GET", &path, Some("proof=1"), &[]));
    assert_eq!(got.status, 200);
    assert_eq!(
        got.header("X-Mkit-Commit"),
        Some(to_hex(&d.head()).as_str())
    );
    admission.seen.lock().unwrap().clear();
    proofs.0.lock().unwrap().clear();
    block_on(fx.pipe.meta.inner.apply(
        &partition,
        Batch::new().delete(keys::published_ref(&repo.name, HEAD)),
    ))
    .unwrap();
    for method in ["GET", "HEAD"] {
        let missing = read(fx.request(method, &fx.object_url("room", &[98; 32]), None, &[]));
        let got = read(fx.request(method, &path, Some("proof=1"), &[("if-none-match", "*")]));
        same_response(&got, &missing);
    }
    assert!(admission.seen.lock().unwrap().is_empty());
    assert!(proofs.0.lock().unwrap().is_empty());
}

#[test]
fn proof_context_is_404_whether_another_repository_has_its_canonical_objects() {
    let (fx, d) = published();
    let foreign = commit(&d.root, &[], "foreign");
    let (fx, admission, proofs) = counters(fx);
    let path = fx.object_url("room", &id(&d.small));
    let query = format!("proof=1&commit={}&path=small.txt", to_hex(&id(&foreign)));
    let before = ["GET", "HEAD"].map(|method| {
        let absent = read(fx.request(method, &path, Some(&query), &[("if-none-match", "*")]));
        assert_eq!(absent.status, 404);
        absent
    });
    // Global pack bytes and an extracted leaf now exist in another repo.
    let mut objects = d.refs();
    objects.push(&foreign);
    fx.push("other", &objects, id(&foreign), None);
    for (method, absent) in ["GET", "HEAD"].into_iter().zip(before) {
        let foreign_copy = read(fx.request(method, &path, Some(&query), &[("if-none-match", "*")]));
        same_response(&foreign_copy, &absent);
    }
    assert!(admission.seen.lock().unwrap().is_empty());
    assert!(proofs.0.lock().unwrap().is_empty());
}

#[test]
fn held_membership_overrides_warm_proof_validators_before_admission() {
    let (fx, d) = published();
    let path = fx.object_url("room", &id(&d.small));
    assert_eq!(fx.get(&path).status, 200);
    let repo = fx.repo_id("room");
    let located = block_on(crate::indexed::resolve::locate_split(
        &fx.pipe.meta,
        fx.pipe.shards.as_ref(),
        &repo,
        &[d.head()],
        fx.metrics.as_ref(),
    ))
    .unwrap()[&d.head()]
        .as_ref()
        .unwrap()
        .unwrap();
    let partition = fx.pipe.shards.ref_shard(&repo, HEAD);
    let key = keys::membership(&repo.name, &located.pack);
    let value = block_on(fx.pipe.meta.get(&partition, &key))
        .unwrap()
        .unwrap();
    let mut witness = crate::store::publication::Witness::decode(&value).unwrap();
    // Simulate the upstream authority's witness; this WP never applies holds.
    witness.held = true;
    block_on(
        fx.pipe
            .meta
            .inner
            .apply(&partition, Batch::new().put(key, witness.encode())),
    )
    .unwrap();
    let (fx, admission, proofs) = counters(fx);
    let query = format!("proof=1&commit={}&path=small.txt", to_hex(&d.head()));
    for method in ["GET", "HEAD"] {
        let missing = read(fx.request(method, &fx.object_url("room", &[99; 32]), None, &[]));
        for (url, query) in [
            (&path, query.as_str()),
            (&fx.ref_url("room", "main", "small.txt"), "proof=1"),
        ] {
            let got = read(fx.request(method, url, Some(query), &[("if-none-match", "*")]));
            same_response(&got, &missing);
        }
    }
    assert!(admission.seen.lock().unwrap().is_empty());
    assert!(proofs.0.lock().unwrap().is_empty());
}

#[test]
fn blocked_proof_ancestors_override_a_warm_leaf_cache() {
    let (fx, d) = published();
    let leaf = match &d.dir {
        Object::Tree(t) => t.entries[0].object_hash,
        _ => panic!("tree"),
    };
    let path = fx.object_url("room", &leaf);
    assert_eq!(fx.get(&path).status, 200);
    let (mut fx, admission, proofs) = counters(fx);
    let query = format!("proof=1&commit={}&path=dir/inner.txt", to_hex(&d.head()));
    for ancestor in [d.head(), id(&d.root), id(&d.dir)] {
        fx = with_seams(fx, |s| s.takedown = Arc::new(Blocked(ancestor)));
        for method in ["GET", "HEAD"] {
            let missing = read(fx.request(method, &fx.object_url("room", &[99; 32]), None, &[]));
            let got = read(fx.request(method, &path, Some(&query), &[("if-none-match", "*")]));
            same_response(&got, &missing);
        }
    }
    assert!(admission.seen.lock().unwrap().is_empty());
    assert!(proofs.0.lock().unwrap().is_empty());
}

#[test]
fn range_proof_checks_required_chunk_stops_before_validators_and_payment() {
    for membership_stop in [true, false] {
        let fx = fixture();
        let d = data();
        // Publish one surplus chunk in a different pack before the manifest.
        let root = tree(&[]);
        let initial = commit(&root, &[], "initial");
        let pack = fx.push("room", &[&root, &initial, &d.chunks[0]], id(&initial), None);
        let objects: Vec<_> = d
            .refs()
            .into_iter()
            .filter(|o| id(o) != id(&d.chunks[0]))
            .collect();
        fx.push("room", &objects, d.head(), Some((id(&initial), pack)));
        let path = fx.ref_url("room", "main", "chunked.bin");
        assert_eq!(fx.get(&path).status, 200);
        let (mut fx, admission, proofs) = counters(fx);
        if membership_stop {
            let repo = fx.repo_id("room");
            let partition = fx.pipe.shards.ref_shard(&repo, HEAD);
            let key = keys::membership(&repo.name, &pack);
            let value = block_on(fx.pipe.meta.get(&partition, &key))
                .unwrap()
                .unwrap();
            let mut witness = crate::store::publication::Witness::decode(&value).unwrap();
            witness.held = true;
            block_on(
                fx.pipe
                    .meta
                    .inner
                    .apply(&partition, Batch::new().put(key, witness.encode())),
            )
            .unwrap();
        } else {
            fx = with_seams(fx, |s| s.takedown = Arc::new(Blocked(id(&d.chunks[0]))));
        }
        // First-chunk, preceding-chunk and cross-chunk dependencies all stop.
        for range in ["0-0", "60000-60000", "59999-60000"] {
            for method in ["GET", "HEAD"] {
                let missing =
                    read(fx.request(method, &fx.object_url("room", &[99; 32]), None, &[]));
                let query = format!("proof=1&range={range}");
                for headers in [vec![], vec![("if-none-match", "*")]] {
                    let got = read(fx.request(method, &path, Some(&query), &headers));
                    same_response(&got, &missing);
                }
            }
        }
        assert!(admission.seen.lock().unwrap().is_empty());
        assert!(proofs.0.lock().unwrap().is_empty());
    }
}
