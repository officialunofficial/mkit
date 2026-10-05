//! Opt-in batching retains default admission, URL authority and output accounting.
use super::*;
use crate::pipeline::{ObjectReader, ReaderSession, ReaderView};
use std::collections::BTreeMap;

fn with_reader<T>(
    fx: &Fx,
    owner: bool,
    run: impl FnOnce(&ObjectReader<'_, SpyBlobs, Arc<Spy>, Hooks>) -> T,
) -> T {
    let req = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::ListRefs,
        fx.number(),
    );
    let lookup = |name: &str| {
        req.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
    };
    let meta = RequestMeta {
        procedure: req.procedure,
        header: &lookup,
        header_values: None,
        unary_body: Some(&req.body),
        transport_principal: None,
    };
    let reader = block_on(fx.pipe.object_reader(
        fx.repo_id("room"),
        if owner {
            ReaderView::Owner(&meta)
        } else {
            ReaderView::Public
        },
    ))
    .unwrap();
    run(&reader)
}

#[test]
fn opt_in_batch_limit_preserves_defaults_url_cap_and_duplicate_output_accounting() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| {
        c.url_tokens = Some(super::private_tokens::tokens());
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    for owner in [false, true] {
        with_reader(&fx, owner, |reader| {
            assert_eq!(
                block_on(reader.read_canonical(&[d.head(); 17]))
                    .unwrap_err()
                    .code(),
                crate::Code::InvalidArgument
            );
        });
    }
    for invalid in [0, 46, usize::MAX] {
        let reader = block_on(
            fx.pipe
                .object_reader(fx.repo_id("room"), ReaderView::Public),
        )
        .unwrap();
        let before = fx.pipe.meta.calls();
        assert_eq!(
            reader.with_batch_limit(invalid).err().unwrap().code(),
            crate::Code::InvalidArgument
        );
        assert_eq!(fx.pipe.meta.calls(), before);
    }
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap()
    .with_batch_limit(45)
    .unwrap();
    let ids: Vec<_> = [d.head(), id(&d.root), id(&d.small)]
        .into_iter()
        .cycle()
        .take(45)
        .collect();
    let canonical: BTreeMap<_, _> = [&d.commit, &d.root, &d.small]
        .into_iter()
        .map(|object| (id(object), serialize(object).unwrap()))
        .collect();
    let mut session = ReaderSession::default();
    assert_eq!(
        block_on(reader.read_canonical_in(&mut session, &ids)).unwrap(),
        ids.iter()
            .map(|id| Some(canonical[id].clone()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        session.used().output_bytes,
        ids.iter().map(|id| canonical[id].len() as u64).sum::<u64>()
    );
    assert!(
        block_on(reader.object_metadata_in(&mut session, &ids))
            .unwrap()
            .iter()
            .all(Option::is_some)
    );
    let before = fx.pipe.meta.calls();
    assert_eq!(
        block_on(reader.read_canonical(&[d.head(); 46]))
            .unwrap_err()
            .code(),
        crate::Code::InvalidArgument
    );
    assert_eq!(
        block_on(reader.issue_urls(&vec![crate::url_token::UrlTarget::Object(d.head()); 17], 60))
            .unwrap_err()
            .code(),
        crate::Code::InvalidArgument
    );
    assert_eq!(fx.pipe.meta.calls(), before);
}
