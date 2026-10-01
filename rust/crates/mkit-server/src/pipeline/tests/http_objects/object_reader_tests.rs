//! Canonical prefetch uses the real publication, authorization and index paths.
use super::*;
use crate::pipeline::{OBJECT_READER_BATCH, OBJECT_READER_CALLS, ReaderView};
use crate::store::{BorrowedStore, ContentIndex};

fn public_read(fx: &Fx, name: &str, ids: &[Hash]) -> Vec<Option<Vec<u8>>> {
    block_on(async {
        fx.pipe
            .object_reader(fx.repo_id(name), ReaderView::Public)
            .await
            .unwrap()
            .read_canonical(ids)
            .await
            .unwrap()
    })
}

fn owner_read(fx: &Fx, req: &Req, ids: &[Hash]) -> Result<Vec<Option<Vec<u8>>>, ServerError> {
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
    block_on(async {
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta))
            .await?
            .read_canonical(ids)
            .await
    })
}

fn owner_constructor<H: HookSet>(fx: &Fx<H>, req: &Req) -> Result<(), ServerError> {
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
    block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta)),
    )
    .map(|_| ())
}

#[test]
fn reader_matches_http_presence_and_preserves_order_duplicates_and_manifests() {
    let fx = fixture();
    let d = data();
    let orphan = blob(b"member without a tree edge");
    let mut objects = d.refs();
    objects.push(&orphan);
    fx.push("room", &objects, d.head(), None);
    let ids = [
        id(&d.small),
        id(&orphan),
        [81; 32],
        id(&d.manifest),
        id(&d.small),
    ];
    let canonical = public_read(&fx, "room", &ids);
    for (id, answer) in ids.iter().zip(&canonical) {
        assert_eq!(
            answer.is_some(),
            fx.get(&fx.object_url("room", id)).status == 200
        );
    }
    assert_eq!(canonical[0], Some(serialize(&d.small).unwrap()));
    assert_eq!(canonical[3], Some(serialize(&d.manifest).unwrap()));
    assert_ne!(canonical[3].as_ref().unwrap(), &d.whole());
    assert_eq!(canonical[0], canonical[4]);
    assert!(canonical[1].is_none() && canonical[2].is_none());
    fx.make_private("room");
    assert!(public_read(&fx, "room", &ids).iter().all(Option::is_none));
    for id in ids {
        assert_uniform_404(&fx.get(&fx.object_url("room", &id)));
    }
    let req = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::ListRefs,
        fx.number(),
    );
    assert_eq!(owner_read(&fx, &req, &ids).unwrap(), canonical);
}

#[test]
fn pending_membership_is_owner_only_and_held_membership_is_absent() {
    let mut fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| cfg.takedown_denial = true);
    fx.pipe = fx
        .pipe
        .with_publication_policy(Arc::new(super::super::indexed::InspectionPolicy(
            crate::store::publication::Clearance::Pending,
        )))
        .unwrap();
    let d = data();
    let pack = fx.push("room", &d.refs(), d.head(), None);
    let ids = [id(&d.small), id(&d.manifest), d.head()];
    assert_eq!(public_read(&fx, "room", &ids), vec![None; ids.len()]);
    for id in ids {
        assert_uniform_404(&fx.get(&fx.object_url("room", &id)));
    }
    let req = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::ListRefs,
        fx.number(),
    );
    assert!(
        owner_read(&fx, &req, &ids)
            .unwrap()
            .iter()
            .all(Option::is_some)
    );
    let repo = fx.repo_id("room");
    let partition = fx.pipe.shards.ref_shard(&repo, HEAD);
    let key = keys::membership(&repo.name, &pack);
    let raw = block_on(fx.pipe.meta.inner.get(&partition, &key))
        .unwrap()
        .unwrap();
    let mut witness = crate::store::publication::Witness::decode(&raw).unwrap();
    witness.held = true;
    block_on(
        fx.pipe
            .meta
            .inner
            .apply(&partition, Batch::new().put(key, witness.encode())),
    )
    .unwrap();
    assert_eq!(owner_read(&fx, &req, &ids).unwrap(), vec![None; ids.len()]);
}

#[test]
fn global_denial_filters_mixed_batches_for_both_views_after_cache_warming() {
    let (fx, d) = published();
    let ids = [id(&d.big), id(&d.small), [82; 32]];
    assert!(public_read(&fx, "room", &ids)[0].is_some());
    block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta)).block(
        &ids[0],
        &crate::store::BlockEntry::new("manual", T0 as u64),
        T0 as u64,
    ))
    .unwrap();
    let want = vec![None, Some(serialize(&d.small).unwrap()), None];
    assert_eq!(public_read(&fx, "room", &ids), want);
    let public = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    assert_eq!(
        block_on(public.object_sizes(&ids)).unwrap(),
        vec![None, Some(100), None]
    );
    assert_uniform_404(&fx.get(&fx.object_url("room", &ids[0])));
    assert_eq!(fx.get(&fx.object_url("room", &ids[1])).status, 200);
    let req = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::ListRefs,
        fx.number(),
    );
    assert_eq!(owner_read(&fx, &req, &ids).unwrap(), want);
}

#[test]
fn shared_manifest_chunk_denial_matches_http_and_preserves_unrelated_chunks() {
    let (fx, _, _, visible, _) =
        super::takedown_denial::shared_chunk_stop(Arc::new(Proofs(Mutex::default())));
    let shared = blob(&pattern(4000, 17));
    let extra = blob(&pattern(3000, 18));
    let ids = [id(&shared), id(&extra), [83; 32]];
    let canonical = vec![None, Some(serialize(&extra).unwrap()), None];
    let sizes = vec![None, Some(3000), None];
    for (id, expected) in ids.iter().zip(&canonical) {
        assert_eq!(
            fx.get(&fx.object_url("room", id)).status,
            if expected.is_some() { 200 } else { 404 }
        );
    }
    assert_uniform_404(&fx.get(&fx.object_url("room", &visible)));
    let public = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    assert_eq!(block_on(public.read_canonical(&ids)).unwrap(), canonical);
    assert_eq!(block_on(public.object_sizes(&ids)).unwrap(), sizes);
    assert_eq!(
        block_on(public.read_canonical(&[visible])).unwrap(),
        vec![None]
    );
    assert_eq!(
        block_on(public.object_sizes(&[visible])).unwrap(),
        vec![None]
    );
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
    let owner = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta)),
    )
    .unwrap();
    assert_eq!(block_on(owner.read_canonical(&ids)).unwrap(), canonical);
    assert_eq!(block_on(owner.object_sizes(&ids)).unwrap(), sizes);
    assert_eq!(
        block_on(owner.read_canonical(&[visible])).unwrap(),
        vec![None]
    );
    assert_eq!(
        block_on(owner.object_sizes(&[visible])).unwrap(),
        vec![None]
    );
}

struct WriterAuthority;
impl Authorizer for WriterAuthority {
    async fn authorize(&self, _: &Operation) -> Result<AuthzFacts, ServerError> {
        Ok(AuthzFacts {
            caller_view: CallerView::Writer,
            ..AuthzFacts::default()
        })
    }
}

#[test]
fn read_grant_with_authority_writer_view_cannot_construct_owner_reader() {
    use mkit_attest::grant::{AcceptedSchemes, Capabilities, OwnerScheme, RepoScope};
    let defaults = Hooks::new();
    let hooks = Hooks {
        authorizer: WriterAuthority,
        admission: defaults.admission,
        pre_receive: defaults.pre_receive,
        receipts: defaults.receipts,
        outcomes: defaults.outcomes,
    };
    let fx = fixture_tweaked(hooks, http_cfg(), |cfg| {
        cfg.authorizer_role = AuthorizerRole::Authority;
        cfg.grants = Some(
            GrantConfig::new(
                AUDIENCE,
                AcceptedSchemes::of(&[OwnerScheme::Ed25519]),
                vec![],
            )
            .unwrap(),
        );
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let grantee = key(56);
    let header = super::super::grants::grant(&fx.owner, &grantee, |grant| {
        grant.capabilities = Capabilities::Read;
        grant.ref_scopes = None;
        grant.scope = RepoScope::Repository(
            mkit_core::repo_identity::RepositoryIdentity::parse(&fx.identity("room")).unwrap(),
        );
    });
    let req = signed(
        &grantee,
        &fx.identity("room"),
        Procedure::ListRefs,
        fx.number(),
    )
    .header("x-write-grant", &header);
    // Existing read authorization accepts the authority's writer selection.
    let auth = fx.auth(&req);
    let op = fx
        .pipe
        .identify(
            &auth,
            OpKind::ListRefs {
                prefix: "refs/".into(),
            },
        )
        .unwrap();
    let authorized = block_on(fx.pipe.authorize_read(&op)).unwrap();
    assert_eq!(authorized.facts.caller_view, CallerView::Writer);
    assert!(authorized.facts.grant.is_some());
    assert!(
        !block_on(fx.pipe.list_refs(&auth, "refs/"))
            .unwrap()
            .is_empty()
    );
    fx.clear_calls();
    assert_eq!(
        owner_constructor(&fx, &req).unwrap_err().code(),
        Code::PermissionDenied
    );
    assert!(fx.calls.lock().unwrap().is_empty());
}

#[test]
fn chunk_sizes_share_one_manifest_walk_and_never_read_requested_frames() {
    let fx = fixture();
    let (manifest, chunks) = manifest(&[b"first", b"second", b"third"]);
    let root = tree(&[("file", EntryMode::Blob, &manifest)]);
    let head = commit(&root, &[], "sizes");
    let mut objects: Vec<_> = chunks.iter().collect();
    objects.extend([&manifest, &root, &head]);
    let pack = fx.push("room", &objects, id(&head), None);
    let repo = fx.repo_id("room");
    // Leave indexed sizes intact but make every requested frame unreadable.
    // Any attempt to acquire a requested object's byte range must now fail.
    for chunk in &chunks {
        let id = id(chunk);
        let key = keys::object_index(&repo.name, &id, &pack);
        let partition = fx.pipe.shards.object_index(&repo, &id);
        let raw = block_on(fx.pipe.meta.inner.get(&partition, &key))
            .unwrap()
            .unwrap();
        let mut row = codec::decode_object_index(&id, &raw).unwrap();
        row.frame_offset = 1 << 40;
        block_on(fx.pipe.meta.inner.apply(
            &partition,
            Batch::new().put(key, codec::encode_object_index(&id, &row).unwrap()),
        ))
        .unwrap();
    }
    fx.clear_calls();
    let before = fx.pipe.meta.calls();
    let mut ids: Vec<_> = chunks.iter().map(id).collect();
    ids.push(ids[0]);
    let reader = block_on(fx.pipe.object_reader(repo, ReaderView::Public)).unwrap();
    assert_eq!(
        block_on(reader.object_sizes(&ids)).unwrap(),
        vec![Some(5), Some(6), Some(5), Some(5)]
    );
    assert_eq!(
        fx.blob_calls(BlobKey::pack(pack))
            .iter()
            .filter(|op| **op == "get")
            .count(),
        6,
        "one pack prefix and frame each for commit, tree and manifest"
    );
    let blob_calls = u32::try_from(fx.calls.lock().unwrap().len()).unwrap();
    assert!(fx.pipe.meta.calls() - before + blob_calls <= OBJECT_READER_CALLS);
    for chunk in chunks {
        assert!(fx.blob_calls(BlobKey::object(id(&chunk))).is_empty());
    }
    assert_eq!(
        block_on(reader.read_canonical(&ids[..1]))
            .unwrap_err()
            .code(),
        Code::Unavailable,
        "the injected unreadable frame must reject actual byte acquisition"
    );
}

#[test]
fn sizes_refuse_an_unresolved_requested_ancestor_without_reading_it() {
    let (fx, d) = published();
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    fx.clear_calls();
    let error = block_on(reader.object_sizes(&[d.head(), id(&d.small)])).unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert!(fx.calls.lock().unwrap().is_empty());
    assert_eq!(
        block_on(reader.object_sizes(&[d.head()])).unwrap(),
        vec![Some(serialize(&d.commit).unwrap().len() as u64)]
    );
    assert!(fx.calls.lock().unwrap().is_empty());
}

#[test]
fn sizes_never_read_a_requested_delta_base_while_loading_an_ancestor() {
    let fx = fixture();
    let (manifest, chunks) = manifest(&[b"chunk"]);
    let root = tree(&[("file", EntryMode::Blob, &manifest)]);
    let head = commit(&root, &[], "delta base exclusion");
    let pack = fx.push(
        "room",
        &[&chunks[0], &manifest, &root, &head],
        id(&head),
        None,
    );
    let repo = fx.repo_id("room");
    let root_id = id(&root);
    let partition = fx.pipe.shards.object_index(&repo, &root_id);
    let key = keys::object_index(&repo.name, &root_id, &pack);
    let raw = block_on(fx.pipe.meta.inner.get(&partition, &key))
        .unwrap()
        .unwrap();
    let mut row = codec::decode_object_index(&root_id, &raw).unwrap();
    row.wire_type = 2;
    row.delta_base = Some(id(&chunks[0]));
    row.chain_depth = 1;
    block_on(fx.pipe.meta.inner.apply(
        &partition,
        Batch::new().put(key, codec::encode_object_index(&root_id, &row).unwrap()),
    ))
    .unwrap();
    let reader = block_on(fx.pipe.object_reader(repo, ReaderView::Public)).unwrap();
    fx.clear_calls();
    assert_eq!(
        block_on(reader.object_sizes(&[id(&chunks[0])]))
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    assert_eq!(
        fx.blob_calls(BlobKey::pack(pack)),
        vec!["get", "get", "get"],
        "commit prefix/frame and tree prefix; requested base must have no prefix or frame read"
    );
}

#[test]
fn enabled_denial_performs_one_descriptor_scan_for_the_entire_batch() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| cfg.takedown_denial = true);
    let contents: Vec<Vec<u8>> = (0..OBJECT_READER_BATCH)
        .map(|i| vec![u8::try_from(i).unwrap(); 20])
        .collect();
    let (manifest, chunks) = manifest(&contents.iter().map(Vec::as_slice).collect::<Vec<_>>());
    let root = tree(&[("file", EntryMode::Blob, &manifest)]);
    let head = commit(&root, &[], "full size batch");
    let mut objects: Vec<_> = chunks.iter().collect();
    objects.extend([&manifest, &root, &head]);
    fx.push("room", &objects, id(&head), None);
    let ids: Vec<_> = chunks.iter().map(id).collect();
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    for sizes in [true, false] {
        fx.pipe.meta.seen.lock().unwrap().clear();
        fx.clear_calls();
        let before = fx.pipe.meta.calls();
        if sizes {
            assert_eq!(
                block_on(reader.object_sizes(&ids)).unwrap(),
                vec![Some(20); OBJECT_READER_BATCH]
            );
        } else {
            assert_eq!(
                block_on(reader.read_canonical(&ids)).unwrap(),
                chunks
                    .iter()
                    .map(|c| Some(serialize(c).unwrap()))
                    .collect::<Vec<_>>()
            );
        }
        let scans = fx
            .pipe
            .meta
            .seen()
            .iter()
            .filter(|key| key.as_bytes() == b"b\0\xffdenial-action-descriptors-v2-index\0")
            .count();
        assert_eq!(scans, 4_096, "batch denial shares the deployment-wide scan");
        let metadata_calls = fx.pipe.meta.calls() - before;
        let blob_calls = u32::try_from(fx.calls.lock().unwrap().len()).unwrap();
        // Worker range reads charge both R2 metadata and body calls. The core
        // also reserves two auth calls (one already counted) and 16 gate calls.
        let physical = metadata_calls + 2 * blob_calls;
        let core = physical + 1 + u32::try_from(ids.len()).unwrap();
        eprintln!(
            "object reader batch=16 sizes={sizes} physical_calls={physical} core_calls={core}"
        );
        assert!(core <= OBJECT_READER_CALLS);
        assert_eq!(blob_calls, if sizes { 6 } else { 38 });
    }
}

#[test]
fn blob_sizes_are_payload_lengths_including_zero() {
    let fx = fixture();
    let empty = blob(b"");
    let small = blob(b"content");
    let root = tree(&[
        ("empty", EntryMode::Blob, &empty),
        ("small", EntryMode::Blob, &small),
    ]);
    let head = commit(&root, &[], "blob sizes");
    fx.push("room", &[&empty, &small, &root, &head], id(&head), None);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    assert_eq!(
        block_on(reader.object_sizes(&[id(&empty), id(&small)])).unwrap(),
        vec![Some(0), Some(7)]
    );
}

#[test]
fn prefetched_objects_build_verified_disclosures_identical_to_the_native_store() {
    use mkit_core::store::{MemorySource, ObjectStore};
    use mkit_core::verify::{Selector, build_disclosure, build_disclosure_from, verify_disclosure};
    let (fx, d) = published();
    let ids: Vec<_> = d.all.iter().map(id).collect();
    let bytes = public_read(&fx, "room", &ids);
    let mut source = MemorySource::default();
    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(&mkit_core::layout::RepoLayout::single(dir.path())).unwrap();
    for (id, canonical) in ids.into_iter().zip(bytes) {
        let canonical = canonical.unwrap();
        assert_eq!(store.write(&canonical).unwrap(), id);
        source.insert(id, canonical).unwrap();
    }
    for selector in [Selector::Object, Selector::Chunk(0), Selector::Chunk(2)] {
        let bundle =
            build_disclosure_from(&source, &d.head(), &[b"chunked.bin"], selector).unwrap();
        assert_eq!(
            bundle,
            build_disclosure(&store, &d.head(), &[b"chunked.bin"], selector).unwrap()
        );
        let verified = verify_disclosure(&d.head(), &bundle).unwrap();
        assert!(verified.signature_valid);
        assert_eq!(verified.leaf_id, id(&d.manifest));
    }
}

#[test]
fn owner_reader_refuses_unsigned_invalid_non_owner_and_other_repository_envelopes() {
    let (fx, _) = published();
    let identity = fx.identity("room");
    let unsigned = Req::unsigned(Procedure::ListRefs).header("x-repository", &identity);
    let invalid = signed(&fx.owner, &identity, Procedure::ListRefs, fx.number())
        .header("x-signature", &"00".repeat(64));
    let stranger = signed(&key(99), &identity, Procedure::ListRefs, fx.number());
    let foreign = signed(
        &fx.owner,
        &fx.identity("elsewhere"),
        Procedure::ListRefs,
        fx.number(),
    );
    let wrong_procedure = signed(&fx.owner, &identity, Procedure::ReadRef, fx.number());
    for req in [unsigned, invalid, stranger, foreign, wrong_procedure] {
        fx.clear_calls();
        assert!(owner_constructor(&fx, &req).is_err());
        assert!(
            fx.calls.lock().unwrap().is_empty(),
            "rejected owner read fetched object bytes"
        );
    }
}

#[test]
fn verified_write_grant_selects_writer_view_and_is_rechecked_each_batch() {
    use mkit_attest::grant::{AcceptedSchemes, Capabilities, OwnerScheme, RepoScope};
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.grants = Some(
            GrantConfig::new(
                AUDIENCE,
                AcceptedSchemes::of(&[OwnerScheme::Ed25519]),
                vec![],
            )
            .unwrap(),
        );
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    fx.make_private("room");
    let grantee = key(55);
    let header = super::super::grants::grant(&fx.owner, &grantee, |grant| {
        grant.capabilities = Capabilities::ReadWrite;
        grant.scope = RepoScope::Repository(
            mkit_core::repo_identity::RepositoryIdentity::parse(&fx.identity("room")).unwrap(),
        );
    });
    let req = signed(
        &grantee,
        &fx.identity("room"),
        Procedure::ListRefs,
        fx.number(),
    )
    .header("x-write-grant", &header);
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
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta)),
    )
    .unwrap();
    assert_eq!(
        block_on(reader.read_canonical(&[id(&d.small)])).unwrap(),
        vec![Some(serialize(&d.small).unwrap())]
    );
    let repo = fx.repo_id("room");
    block_on(fx.pipe.meta.inner.apply(
        &fx.pipe.shards.coordinator(&repo.namespace),
        Batch::new().put(keys::grant_epoch(), codec::encode_u64(1)),
    ))
    .unwrap();
    assert!(block_on(reader.read_canonical(&[id(&d.small)])).is_err());
}

#[test]
fn oversized_batches_are_rejected_before_authorization_or_storage_calls() {
    let (fx, d) = published();
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let ids = vec![d.head(); OBJECT_READER_BATCH + 1];
    let before = fx.pipe.meta.calls();
    fx.clear_calls();
    assert_eq!(
        block_on(reader.read_canonical(&ids)).unwrap_err().code(),
        Code::InvalidArgument
    );
    assert_eq!(
        block_on(reader.object_sizes(&ids)).unwrap_err().code(),
        Code::InvalidArgument
    );
    assert_eq!(fx.pipe.meta.calls(), before);
    assert!(fx.calls.lock().unwrap().is_empty());
    assert!(block_on(reader.read_canonical(&[])).unwrap().is_empty());
    assert!(block_on(reader.object_sizes(&[])).unwrap().is_empty());
    let at_limit = vec![d.head(); OBJECT_READER_BATCH];
    assert_eq!(
        block_on(reader.read_canonical(&at_limit)).unwrap(),
        vec![Some(serialize(&d.commit).unwrap()); OBJECT_READER_BATCH]
    );
    assert_eq!(
        block_on(reader.object_sizes(&at_limit)).unwrap(),
        vec![Some(serialize(&d.commit).unwrap().len() as u64); OBJECT_READER_BATCH]
    );
}

#[test]
fn duplicate_canonical_outputs_share_the_existing_decode_byte_limit() {
    let fx = fixture_with(
        Hooks::new(),
        HttpObjectsConfig {
            max_inline_object_bytes: 150_000,
            http_decode_budget: 150_000,
            ..http_cfg()
        },
    );
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let canonical = serialize(&d.big).unwrap();
    assert_eq!(
        block_on(reader.read_canonical(&[id(&d.big)])).unwrap(),
        vec![Some(canonical.clone())]
    );
    assert_eq!(
        block_on(reader.read_canonical(&[id(&d.big); 2])).unwrap(),
        vec![Some(canonical); 2]
    );
    let duplicates = vec![id(&d.big); OBJECT_READER_BATCH];
    assert_eq!(
        block_on(reader.read_canonical(&duplicates))
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    assert_eq!(
        block_on(reader.object_sizes(&duplicates)).unwrap(),
        vec![Some(70_000); OBJECT_READER_BATCH]
    );
}

fn assert_unresolvable_size_bases_absent(fx: &Fx, derived: &Object, derived_pack: Hash) {
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let repo = fx.repo_id("room");
    let partition = fx.pipe.shards.object_index(&repo, &id(derived));
    let index_key = keys::object_index(&repo.name, &id(derived), &derived_pack);
    let original = block_on(fx.pipe.meta.inner.get(&partition, &index_key))
        .unwrap()
        .unwrap();
    let indexed = codec::decode_object_index(&id(derived), &original).unwrap();
    assert!(
        !block_on(crate::indexed::resolve::member_dependencies_clear(
            &fx.pipe.meta,
            fx.pipe.shards.as_ref(),
            &repo,
            id(derived),
            crate::store::index::LocatedObject {
                pack: derived_pack,
                value: indexed
            },
            0,
            fx.pipe.metrics.as_ref(),
        ))
        .unwrap(),
        "a delta root exceeds a zero-hop bound"
    );
    let unresolved = [92; 32];
    let mut row = indexed;
    row.delta_base = Some(unresolved);
    block_on(fx.pipe.meta.inner.apply(
        &partition,
        Batch::new().put(
            index_key.clone(),
            codec::encode_object_index(&id(derived), &row).unwrap(),
        ),
    ))
    .unwrap();
    fx.clear_calls();
    assert_eq!(
        block_on(reader.object_sizes(&[id(derived)])).unwrap(),
        vec![None]
    );
    assert!(
        fx.calls.lock().unwrap().is_empty(),
        "missing bases use metadata only"
    );
    block_on(
        fx.pipe
            .meta
            .inner
            .apply(&partition, Batch::new().put(index_key, original)),
    )
    .unwrap();
}

fn assert_cyclic_size_bases_absent(fx: &Fx, derived: &Object, base: Hash, base_pack: Hash) {
    let repo = fx.repo_id("room");
    let partition = fx.pipe.shards.object_index(&repo, &base);
    let key = keys::object_index(&repo.name, &base, &base_pack);
    let original = block_on(fx.pipe.meta.inner.get(&partition, &key))
        .unwrap()
        .unwrap();
    let mut row = codec::decode_object_index(&base, &original).unwrap();
    row.wire_type = 2;
    row.chain_depth = 1;
    row.delta_base = Some(id(derived));
    block_on(fx.pipe.meta.inner.apply(
        &partition,
        Batch::new().put(
            key.clone(),
            codec::encode_object_index(&base, &row).unwrap(),
        ),
    ))
    .unwrap();
    let reader = block_on(fx.pipe.object_reader(repo, ReaderView::Public)).unwrap();
    fx.clear_calls();
    assert_eq!(
        block_on(reader.object_sizes(&[id(derived)])).unwrap(),
        vec![None]
    );
    assert!(
        fx.calls.lock().unwrap().is_empty(),
        "cyclic bases use metadata only"
    );
    block_on(
        fx.pipe
            .meta
            .inner
            .apply(&partition, Batch::new().put(key, original)),
    )
    .unwrap();
}

#[test]
fn sizes_respect_denied_delta_bases_with_global_scan_disabled() {
    for block_pack in [false, true] {
        let fx = fixture();
        let base = blob(b"base object payload");
        let old_root = tree(&[("base", EntryMode::Blob, &base)]);
        let old_head = commit(&old_root, &[], "old");
        let old_pack = fx.push("room", &[&base, &old_root, &old_head], id(&old_head), None);
        let derived = blob(b"derived object payload");
        let root = tree(&[("derived", EntryMode::Blob, &derived)]);
        let head = commit(&root, &[], "derived");
        let mut writer = PackWriter::new();
        writer
            .push_delta(
                &id(&base),
                &mkit_core::delta::encode(
                    &serialize(&base).unwrap(),
                    &serialize(&derived).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        for object in [&root, &head] {
            writer
                .push_raw(id(object), &serialize(object).unwrap())
                .unwrap();
        }
        let (outcome, derived_pack) = fx.push_pack(
            "room",
            &writer.finish().unwrap(),
            (HEAD, PACKMAP),
            id(&head),
            (Match(id(&old_head)), Match(old_pack)),
        );
        assert_eq!(outcome, AdvanceOutcome::Committed);
        let reader = block_on(
            fx.pipe
                .object_reader(fx.repo_id("room"), ReaderView::Public),
        )
        .unwrap();
        assert_eq!(
            block_on(reader.read_canonical(&[id(&derived)])).unwrap(),
            vec![Some(serialize(&derived).unwrap())]
        );
        assert_unresolvable_size_bases_absent(&fx, &derived, derived_pack);
        assert_cyclic_size_bases_absent(&fx, &derived, id(&base), old_pack);
        block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta)).block(
            &if block_pack { old_pack } else { id(&base) },
            &crate::store::BlockEntry::new("manual", T0 as u64),
            T0 as u64,
        ))
        .unwrap();
        assert_uniform_404(&fx.get(&fx.object_url("room", &id(&derived))));
        assert_eq!(
            block_on(reader.read_canonical(&[id(&derived)])).unwrap(),
            vec![None]
        );
        fx.clear_calls();
        assert_eq!(
            block_on(reader.object_sizes(&[id(&derived)])).unwrap(),
            vec![None]
        );
        assert!(
            fx.calls.lock().unwrap().is_empty(),
            "denied sizes use no object bytes"
        );
    }
}

#[test]
fn blocked_ancestor_pack_matches_http_absence() {
    let fx = fixture();
    let d = data();
    let old_pack = fx.push("room", &d.refs(), d.head(), None);
    let root = tree(&[("clear", EntryMode::Blob, &d.small)]);
    let head = commit(&root, &[], "new root pack");
    let mut writer = PackWriter::new_raw_only();
    for object in [&root, &head] {
        writer
            .push_raw(id(object), &serialize(object).unwrap())
            .unwrap();
    }
    let (outcome, pack) = fx.push_pack(
        "room",
        &writer.finish().unwrap(),
        (HEAD, PACKMAP),
        id(&head),
        (Match(d.head()), Match(old_pack)),
    );
    assert_eq!(outcome, AdvanceOutcome::Committed);
    block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta)).block(
        &pack,
        &crate::store::BlockEntry::new("manual", T0 as u64),
        T0 as u64,
    ))
    .unwrap();
    assert_uniform_404(&fx.get(&fx.object_url("room", &id(&d.small))));
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    assert_eq!(
        block_on(reader.read_canonical(&[id(&d.small)])).unwrap(),
        vec![None]
    );
    assert_eq!(
        block_on(reader.object_sizes(&[id(&d.small)])).unwrap(),
        vec![None]
    );
}

#[test]
fn sizes_use_the_same_clear_in_pack_delta_base_as_canonical_reads() {
    let fx = fixture();
    let base = blob(b"base object payload");
    let old_root = tree(&[("base", EntryMode::Blob, &base)]);
    let old_head = commit(&old_root, &[], "old duplicate base");
    let old_pack = fx.push("room", &[&base, &old_root, &old_head], id(&old_head), None);
    let derived = blob(b"derived object payload");
    let root = tree(&[("derived", EntryMode::Blob, &derived)]);
    // The generic member lookup picks the earlier blocked pack, while
    // canonical delta resolution correctly prefers its earlier in-pack base.
    let (pack_bytes, head) = (0..128)
        .find_map(|i| {
            let head = commit(&root, &[], &format!("clear duplicate-base pack {i}"));
            let mut writer = PackWriter::new();
            writer
                .push_raw(id(&base), &serialize(&base).unwrap())
                .unwrap();
            writer
                .push_delta(
                    &id(&base),
                    &mkit_core::delta::encode(
                        &serialize(&base).unwrap(),
                        &serialize(&derived).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap();
            for object in [&root, &head] {
                writer
                    .push_raw(id(object), &serialize(object).unwrap())
                    .unwrap();
            }
            let bytes = writer.finish().unwrap();
            (hash(&bytes) > old_pack).then_some((bytes, head))
        })
        .unwrap();
    let (outcome, _) = fx.push_pack(
        "room",
        &pack_bytes,
        (HEAD, PACKMAP),
        id(&head),
        (Match(id(&old_head)), Match(old_pack)),
    );
    assert_eq!(outcome, AdvanceOutcome::Committed);
    block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta)).block(
        &old_pack,
        &crate::store::BlockEntry::new("manual", T0 as u64),
        T0 as u64,
    ))
    .unwrap();
    assert_eq!(fx.get(&fx.object_url("room", &id(&derived))).status, 200);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    assert_eq!(
        block_on(reader.read_canonical(&[id(&derived)])).unwrap(),
        vec![Some(serialize(&derived).unwrap())]
    );
    assert_eq!(
        block_on(reader.object_sizes(&[id(&derived)])).unwrap(),
        vec![Some(22)]
    );
}

#[test]
fn blocked_ancestor_keeps_earlier_proven_batch_targets() {
    let fx = fixture();
    let clear_tree = tree(&[]);
    let clear = commit(&clear_tree, &[], "directly published clear tip");
    let hidden = blob(b"hidden behind a blocked ancestor pack");
    let root = tree(&[("hidden", EntryMode::Blob, &hidden)]);
    let head = commit(&root, &[], "blocked ancestry");
    fx.push_ref(
        "room",
        &[&clear_tree, &clear, &hidden],
        ("refs/heads/a-clear", "refs/mkit/packmap/a-clear"),
        id(&clear),
        (Missing, Missing),
    );
    let (_, pack) = fx.push_ref(
        "room",
        &[&root, &head],
        ("refs/heads/z-blocked", "refs/mkit/packmap/z-blocked"),
        id(&head),
        (Missing, Missing),
    );
    block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta)).block(
        &pack,
        &crate::store::BlockEntry::new("manual", T0 as u64),
        T0 as u64,
    ))
    .unwrap();
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let ids = [id(&clear), id(&hidden), [91; 32]];
    assert_eq!(
        block_on(reader.object_sizes(&ids)).unwrap(),
        vec![Some(serialize(&clear).unwrap().len() as u64), None, None]
    );
    assert_eq!(
        block_on(reader.read_canonical(&ids)).unwrap(),
        vec![Some(serialize(&clear).unwrap()), None, None]
    );
    assert_eq!(fx.get(&fx.object_url("room", &id(&clear))).status, 200);
    assert_uniform_404(&fx.get(&fx.object_url("room", &id(&hidden))));
}
