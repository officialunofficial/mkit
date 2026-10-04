//! Published reads must retain their authorization checks before validators.
use super::*;

fn counters(fx: Fx) -> (Fx, Arc<Admit>) {
    let admission = Arc::new(Admit {
        seen: Mutex::default(),
        ended: Arc::default(),
        challenge: false,
    });
    let fx = with_seams(fx, |s| s.admission = admission.clone());
    (fx, admission)
}

fn same_response(got: &Got, expected: &Got) {
    assert_eq!(
        (got.status, &got.headers, &got.body),
        (expected.status, &expected.headers, &expected.body)
    );
}

#[test]
fn ref_reads_never_fall_back_to_a_live_value() {
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
    let (fx, admission) = counters(fx);
    let path = fx.ref_url("room", "main", "small.txt");
    let got = read(fx.request("GET", &path, None, &[]));
    assert_eq!(got.status, 200);
    assert_eq!(
        got.header("X-Mkit-Commit"),
        Some(to_hex(&d.head()).as_str())
    );
    admission.seen.lock().unwrap().clear();
    block_on(fx.pipe.meta.inner.apply(
        &partition,
        Batch::new().delete(keys::published_ref(&repo.name, HEAD)),
    ))
    .unwrap();
    for method in ["GET", "HEAD"] {
        let missing = read(fx.request(method, &fx.object_url("room", &[98; 32]), None, &[]));
        let got = read(fx.request(method, &path, None, &[("if-none-match", "*")]));
        same_response(&got, &missing);
    }
    assert!(admission.seen.lock().unwrap().is_empty());
}

#[test]
fn held_membership_overrides_warm_validators_before_admission() {
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
    // Simulate the upstream authority's held witness.
    witness.held = true;
    block_on(
        fx.pipe
            .meta
            .inner
            .apply(&partition, Batch::new().put(key, witness.encode())),
    )
    .unwrap();
    let (fx, admission) = counters(fx);
    for method in ["GET", "HEAD"] {
        let missing = read(fx.request(method, &fx.object_url("room", &[99; 32]), None, &[]));
        for url in [&path, &fx.ref_url("room", "main", "small.txt")] {
            let got = read(fx.request(method, url, None, &[("if-none-match", "*")]));
            same_response(&got, &missing);
        }
    }
    assert!(admission.seen.lock().unwrap().is_empty());
}
