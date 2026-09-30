//! Real serving paths must enforce a held manifest's repository-specific chunk stop.
use super::*;
use crate::store::{BorrowedStore, ContentIndex};
use crate::takedown::denial::BlockAction;

#[test]
fn shared_chunk_stop_precedes_extracted_http_validators_proofs_and_pack_reads() {
    let tokens = crate::url_token::UrlTokenConfig::new(
        crate::url_token::UrlTokenKeys::new(zeroize::Zeroizing::new([13; 32]), vec![]).unwrap(),
    );
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.takedown_denial = true;
        cfg.url_tokens = Some(tokens.clone());
    });
    let shared = pattern(4000, 17);
    let extra = pattern(3000, 18);
    let (blocked, blocked_chunks) = manifest(&[&shared]);
    let (visible, chunks) = manifest(&[&shared, &extra]);
    let root = tree(&[("visible.bin", EntryMode::Blob, &visible)]);
    let head = commit(&root, &[], "shared chunk");
    let mut objects: Vec<_> = chunks.iter().collect();
    objects.extend([&blocked, &visible, &root, &head]);
    let pack = fx.push("room", &objects, id(&head), None);
    let foreign = fx.push(
        "other",
        &[&chunks[0], &chunks[1], &visible, &root, &head],
        id(&head),
        None,
    );
    let object_url = fx.object_url("room", &id(&visible));
    let ref_url = fx.ref_url("room", "main", "visible.bin");
    assert_eq!(fx.get(&object_url).status, 200);
    let token = tokens
        .mint(
            AUDIENCE,
            &fx.identity("room"),
            &crate::url_token::UrlTarget::Object(id(&visible)),
            0,
            fx.clock.now_ms(),
            60,
        )
        .unwrap();
    let token_query = format!("token={}", token.expose());
    fx.make_private("room");
    assert_eq!(
        read(fx.request("GET", &object_url, Some(&token_query), &[])).status,
        200
    );
    let repo = fx.repo_id("room");
    block_on(fx.pipe.meta.apply(
        &fx.pipe.shards.coordinator(&repo.namespace),
        Batch::new().put(
            keys::repo_visibility(&repo.name),
            codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                visibility: codec::StoredVisibility::Public,
                last_created_ms: 0,
                last_statement_id: None,
            }),
        ),
    ))
    .unwrap();
    let proofs = Arc::new(Proofs(Mutex::default()));
    let fx = with_seams(fx, |s| s.proofs = proofs.clone());
    block_on(
        ContentIndex::new(BorrowedStore(&fx.pipe.meta)).install_block_action(
            &id(&blocked),
            &BlockAction {
                id: [19; 32],
                takedown_id: [20; 32],
                reason: "manual".into(),
                blocked_at_ms: T0 as u64,
                chunk_ids: vec![id(&blocked_chunks[0])],
            },
            T0 as u64,
        ),
    )
    .unwrap();
    for path in [&object_url, &ref_url] {
        for method in ["GET", "HEAD"] {
            for headers in [
                vec![],
                vec![("if-none-match", "*")],
                vec![("range", "bytes=0-3")],
            ] {
                let got = read(fx.request(method, path, None, &headers));
                assert_eq!(got.status, 404, "{method} {path} {headers:?}");
                assert_eq!(got.header("Cache-Control"), Some("no-store"));
                assert!(got.header("ETag").is_none());
            }
        }
    }
    assert_eq!(
        read(fx.request("GET", &ref_url, Some("proof=1"), &[])).status,
        404
    );
    assert!(proofs.0.lock().unwrap().is_empty());
    fx.make_private("room");
    for method in ["GET", "HEAD"] {
        assert_eq!(
            read(fx.request(
                method,
                &object_url,
                Some(&token_query),
                &[("range", "bytes=0-3")]
            ))
            .status,
            404
        );
    }
    let begin = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::BeginUpload,
        fx.number(),
    );
    assert!(!matches!(
        block_on(fx.pipe.begin_upload(&fx.auth(&begin), HEAD, &pack, 100)).unwrap(),
        BeginUploadResult::AlreadyPresent
    ));
    assert_eq!(fx.get(&fx.object_url("other", &id(&visible))).status, 200);
    for (name, pack, expected) in [("room", pack, false), ("other", foreign, true)] {
        let request = signed(
            &fx.owner,
            &fx.identity(name),
            Procedure::PackExists,
            fx.number(),
        );
        fx.clear_calls();
        assert_eq!(
            block_on(fx.pipe.pack_exists(&fx.auth(&request), PackKey(pack))).unwrap(),
            expected
        );
        assert!(
            !fx.blob_calls(BlobKey::pack(pack)).contains(&"get"),
            "PackExists buffered pack bytes for a denial proof"
        );
        let request = signed(
            &fx.owner,
            &fx.identity(name),
            Procedure::DownloadPack,
            fx.number(),
        );
        let result = block_on(fx.pipe.download(&fx.auth(&request), PackKey(pack)));
        if expected {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.err().unwrap().code(), Code::NotFound);
        }
    }
}

#[test]
fn default_off_keeps_cached_reads_bounded_and_legacy_leaf_denial_strong() {
    let (fx, data) = published();
    assert!(!fx.pipe.cfg.takedown_denial);
    let url = fx.object_url("room", &id(&data.big));
    assert_eq!(fx.get(&url).status, 200);
    let before = fx.pipe.meta.calls();
    assert_eq!(fx.get(&url).status, 200);
    assert!(
        fx.pipe.meta.calls() - before < 100,
        "default-off read performed deployment-wide work"
    );
    block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta)).block(
        &id(&data.big),
        &crate::store::BlockEntry::new("manual", T0 as u64),
        T0 as u64,
    ))
    .unwrap();
    assert_uniform_404(&fx.get(&url));
    assert_uniform_404(&fx.get(&fx.ref_url("room", "main", "big.bin")));
}

#[test]
fn legacy_pack_denial_precedes_exists_download_and_already_present() {
    let fx = fixture();
    let data = data();
    let pack = fx.push("room", &data.refs(), data.head(), None);
    let extracted = fx.object_url("room", &id(&data.big));
    assert_eq!(fx.get(&extracted).status, 200);
    block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta)).block(
        &pack,
        &crate::store::BlockEntry::new("manual", T0 as u64),
        T0 as u64,
    ))
    .unwrap();
    assert_uniform_404(&fx.get(&extracted));
    let request = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::PackExists,
        fx.number(),
    );
    assert!(!block_on(fx.pipe.pack_exists(&fx.auth(&request), PackKey(pack))).unwrap());
    let request = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::DownloadPack,
        fx.number(),
    );
    assert_eq!(
        block_on(fx.pipe.download(&fx.auth(&request), PackKey(pack)))
            .err()
            .unwrap()
            .code(),
        Code::NotFound
    );
    let request = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::BeginUpload,
        fx.number(),
    );
    assert!(!matches!(
        block_on(fx.pipe.begin_upload(&fx.auth(&request), HEAD, &pack, 100)).unwrap(),
        BeginUploadResult::AlreadyPresent
    ));
}
