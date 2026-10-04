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
        block_on(public.metadata_sizes(&ids)).unwrap(),
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
    let (fx, _, _, visible, _) = super::takedown_denial::shared_chunk_stop();
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
    assert_eq!(block_on(public.metadata_sizes(&ids)).unwrap(), sizes);
    assert_eq!(
        block_on(public.read_canonical(&[visible])).unwrap(),
        vec![None]
    );
    assert_eq!(
        block_on(public.metadata_sizes(&[visible])).unwrap(),
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
    assert_eq!(block_on(owner.metadata_sizes(&ids)).unwrap(), sizes);
    assert_eq!(
        block_on(owner.read_canonical(&[visible])).unwrap(),
        vec![None]
    );
    assert_eq!(
        block_on(owner.metadata_sizes(&[visible])).unwrap(),
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
        block_on(reader.metadata_sizes(&ids)).unwrap(),
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
    // The requested ancestor is never read, so the descendant is unprovable: absent.
    assert_eq!(
        block_on(reader.metadata_sizes(&[d.head(), id(&d.small)])).unwrap(),
        vec![Some(serialize(&d.commit).unwrap().len() as u64), None]
    );
    assert!(fx.calls.lock().unwrap().is_empty());
    assert_eq!(
        block_on(reader.metadata_sizes(&[d.head()])).unwrap(),
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
        block_on(reader.metadata_sizes(&[id(&chunks[0])])).unwrap(),
        vec![None]
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
                block_on(reader.metadata_sizes(&ids)).unwrap(),
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
            .filter(|key| key.as_bytes() == b"b\0\xffdenial-descriptor-directory\0")
            .count();
        assert_eq!(scans, 16, "batch denial shares the deployment-wide scan");
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
        block_on(reader.metadata_sizes(&[id(&empty), id(&small)])).unwrap(),
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
        block_on(reader.metadata_sizes(&ids)).unwrap_err().code(),
        Code::InvalidArgument
    );
    assert_eq!(fx.pipe.meta.calls(), before);
    assert!(fx.calls.lock().unwrap().is_empty());
    assert!(block_on(reader.read_canonical(&[])).unwrap().is_empty());
    assert!(block_on(reader.metadata_sizes(&[])).unwrap().is_empty());
    let at_limit = vec![d.head(); OBJECT_READER_BATCH];
    assert_eq!(
        block_on(reader.read_canonical(&at_limit)).unwrap(),
        vec![Some(serialize(&d.commit).unwrap()); OBJECT_READER_BATCH]
    );
    assert_eq!(
        block_on(reader.metadata_sizes(&at_limit)).unwrap(),
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
        Code::ResourceExhausted
    );
    assert_eq!(
        block_on(reader.metadata_sizes(&duplicates)).unwrap(),
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
            crate::indexed::resolve::Caps::Legacy,
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
        block_on(reader.metadata_sizes(&[id(derived)])).unwrap(),
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
        block_on(reader.metadata_sizes(&[id(derived)])).unwrap(),
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
            block_on(reader.metadata_sizes(&[id(&derived)])).unwrap(),
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
        block_on(reader.metadata_sizes(&[id(&d.small)])).unwrap(),
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
        block_on(reader.metadata_sizes(&[id(&derived)])).unwrap(),
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
        block_on(reader.metadata_sizes(&ids)).unwrap(),
        vec![Some(serialize(&clear).unwrap().len() as u64), None, None]
    );
    assert_eq!(
        block_on(reader.read_canonical(&ids)).unwrap(),
        vec![Some(serialize(&clear).unwrap()), None, None]
    );
    assert_eq!(fx.get(&fx.object_url("room", &id(&clear))).status, 200);
    assert_uniform_404(&fx.get(&fx.object_url("room", &id(&hidden))));
}

fn url_fixture() -> (Fx, Data) {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| {
        c.url_tokens = Some(super::private_tokens::tokens());
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    (fx, d)
}

fn public_urls(
    fx: &Fx,
    targets: &[UrlTarget],
    ttl: u32,
) -> Result<Vec<Option<crate::pipeline::IssuedUrl>>, ServerError> {
    block_on(async {
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public)
            .await?
            .issue_urls(targets, ttl)
            .await
    })
}

#[test]
fn issue_urls_matches_individual_rpc_claims_and_validity() {
    let (fx, d) = url_fixture();
    let repo = fx.repo_id("room");
    block_on(fx.pipe.meta.inner.apply(
        &fx.pipe.shards.coordinator(&repo.namespace),
        Batch::new().put(keys::grant_epoch(), codec::encode_u64(7)),
    ))
    .unwrap();
    let targets = [
        UrlTarget::Object(id(&d.small)),
        UrlTarget::path(HEAD, "small.txt").unwrap(),
        UrlTarget::path(HEAD, "").unwrap(),
        UrlTarget::Object(id(&d.small)),
    ];
    for ttl in [0, 2, u32::MAX] {
        let batch = public_urls(&fx, &targets, ttl).unwrap();
        for (target, issued) in targets.iter().zip(batch) {
            let issued = issued.unwrap();
            let req = signed(
                &fx.owner,
                &fx.identity("room"),
                Procedure::IssueObjectUrl,
                fx.number(),
            );
            let rpc = block_on(
                fx.pipe
                    .issue_object_url(&fx.auth(&req), target.clone(), ttl),
            )
            .unwrap();
            // The fixed business clock makes even timestamps identical.
            assert_eq!(issued.expose(), rpc.expose());
            assert_eq!(issued.expires_at_ms, rpc.expires_at_ms);
            let bound = super::private_tokens::tokens()
                .precheck(issued.expose(), T0)
                .unwrap()
                .check_binding(
                    &crate::url_token::Binding {
                        audience: AUDIENCE,
                        repository: &fx.identity("room"),
                        target,
                    },
                    T0,
                    super::private_tokens::tokens().ttl_ms(),
                )
                .unwrap();
            assert_eq!(bound.epoch(), 7);
            assert!(bound.check_epoch(8).is_err());
            assert!(
                super::private_tokens::tokens()
                    .precheck(issued.expose(), T0)
                    .unwrap()
                    .check_binding(
                        &crate::url_token::Binding {
                            audience: AUDIENCE,
                            repository: &fx.identity("room"),
                            target
                        },
                        issued.expires_at_ms,
                        super::private_tokens::tokens().ttl_ms()
                    )
                    .is_err()
            );
        }
    }
}

#[test]
fn issue_urls_filters_denied_unreachable_and_private_public_view() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| {
        c.url_tokens = Some(super::private_tokens::tokens());
    });
    let d = data();
    let orphan = blob(b"unreachable member");
    let mut objects = d.refs();
    objects.push(&orphan);
    fx.push("room", &objects, d.head(), None);
    let targets = [
        UrlTarget::Object(id(&d.small)),
        UrlTarget::Object(id(&orphan)),
        UrlTarget::Object([91; 32]),
        UrlTarget::path(HEAD, "missing").unwrap(),
    ];
    assert_eq!(
        public_urls(&fx, &targets, 0)
            .unwrap()
            .iter()
            .map(Option::is_some)
            .collect::<Vec<_>>(),
        vec![true, false, false, false]
    );
    block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta)).block(
        &id(&d.small),
        &crate::store::BlockEntry::new("manual", T0 as u64),
        T0 as u64,
    ))
    .unwrap();
    assert!(
        public_urls(&fx, &targets, 0)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );
    fx.make_private("room");
    assert!(
        public_urls(&fx, &targets, 0)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );
}

#[test]
fn issue_urls_bounds_and_missing_keys_precede_storage() {
    let (mut fx, d) = url_fixture();
    let before = fx.pipe.meta.calls();
    assert_eq!(
        public_urls(
            &fx,
            &vec![UrlTarget::Object(d.head()); OBJECT_READER_BATCH + 1],
            0
        )
        .unwrap_err()
        .code(),
        Code::InvalidArgument
    );
    assert_eq!(fx.pipe.meta.calls(), before);
    assert!(public_urls(&fx, &[], 0).unwrap().is_empty());
    assert!(
        public_urls(
            &fx,
            &vec![UrlTarget::Object(d.head()); OBJECT_READER_BATCH],
            0
        )
        .unwrap()
        .iter()
        .all(Option::is_some)
    );
    fx.pipe.cfg.url_tokens = None;
    let before = fx.pipe.meta.calls();
    assert_eq!(
        public_urls(&fx, &[UrlTarget::Object(d.head())], 0)
            .unwrap_err()
            .code(),
        Code::Unimplemented
    );
    assert_eq!(fx.pipe.meta.calls(), before);
}

fn owner_urls(
    fx: &Fx,
    targets: &[UrlTarget],
) -> Result<Vec<Option<crate::pipeline::IssuedUrl>>, ServerError> {
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
    block_on(async {
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta))
            .await?
            .issue_urls(targets, 0)
            .await
    })
}

#[test]
fn issue_urls_owner_is_verified_private_and_still_published_only() {
    let (fx, d) = url_fixture();
    fx.make_private("room");
    let targets = [
        UrlTarget::Object(id(&d.small)),
        UrlTarget::path(HEAD, "small.txt").unwrap(),
    ];
    assert!(
        public_urls(&fx, &targets, 0)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );
    assert!(
        owner_urls(&fx, &targets)
            .unwrap()
            .iter()
            .all(Option::is_some)
    );
    block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta)).block(
        &id(&d.small),
        &crate::store::BlockEntry::new("manual", T0 as u64),
        T0 as u64,
    ))
    .unwrap();
    assert!(
        owner_urls(&fx, &targets)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );

    let mut pending = fixture_tweaked(Hooks::new(), http_cfg(), |c| {
        c.url_tokens = Some(super::private_tokens::tokens());
        c.takedown_denial = true;
    });
    pending.pipe = pending
        .pipe
        .with_publication_policy(Arc::new(super::super::indexed::InspectionPolicy(
            crate::store::publication::Clearance::Pending,
        )))
        .unwrap();
    pending.push("room", &d.refs(), d.head(), None);
    assert!(
        owner_urls(&pending, &targets)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );
}

struct SelectiveUrlHook {
    denied: Hash,
    code: Code,
}
impl Authorizer for SelectiveUrlHook {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        if matches!(&op.kind, OpKind::IssueObjectUrl { target: UrlTarget::Object(id), .. } if *id == self.denied)
        {
            Err(ServerError::new(self.code, "target refused"))
        } else {
            Ok(AuthzFacts::default())
        }
    }
}

#[test]
fn issue_urls_target_hook_denials_are_absent_but_store_failures_abort() {
    let d = data();
    for code in [
        Code::NotFound,
        Code::PermissionDenied,
        Code::Unauthenticated,
        Code::Unavailable,
    ] {
        let defaults = Hooks::new();
        let hooks = Hooks {
            authorizer: SelectiveUrlHook {
                denied: id(&d.small),
                code,
            },
            admission: defaults.admission,
            pre_receive: defaults.pre_receive,
            receipts: defaults.receipts,
            outcomes: defaults.outcomes,
        };
        let fx = fixture_tweaked(hooks, http_cfg(), |c| {
            c.url_tokens = Some(super::private_tokens::tokens());
        });
        fx.push("room", &d.refs(), d.head(), None);
        let reader = block_on(
            fx.pipe
                .object_reader(fx.repo_id("room"), ReaderView::Public),
        )
        .unwrap();
        let batch = block_on(reader.issue_urls(
            &[
                UrlTarget::Object(id(&d.small)),
                UrlTarget::Object(id(&d.big)),
            ],
            0,
        ));
        if code == Code::Unavailable {
            assert_eq!(batch.unwrap_err().code(), code);
        } else {
            assert_eq!(
                batch
                    .unwrap()
                    .iter()
                    .map(Option::is_some)
                    .collect::<Vec<_>>(),
                vec![false, true]
            );
        }
    }
}

#[test]
fn issue_urls_paths_and_reachability_share_one_decode_budget() {
    let leaf = blob(b"payload");
    let names = (0..60).map(|n| format!("file-{n:02}")).collect::<Vec<_>>();
    let root = tree(
        &names
            .iter()
            .map(|name| (name.as_str(), EntryMode::Blob, &leaf))
            .collect::<Vec<_>>(),
    );
    let head = commit(&root, &[], "path budget");
    // Exercise path-only and cumulative proof caps, then a successful larger budget.
    let traversal_bytes =
        (serialize(&root).unwrap().len() + serialize(&head).unwrap().len()) as u64;
    for numerator in [1, 3, 6] {
        let fx = fixture_tweaked(
            Hooks::new(),
            HttpObjectsConfig {
                http_decode_budget: traversal_bytes * numerator / 2,
                max_inline_object_bytes: EXTRACT_MIN + 10,
                ..http_cfg()
            },
            |c| c.url_tokens = Some(super::private_tokens::tokens()),
        );
        fx.push("room", &[&leaf, &root, &head], id(&head), None);
        let result = public_urls(&fx, &[UrlTarget::path(HEAD, "file-00").unwrap()], 0);
        if numerator < 6 {
            assert!(result.unwrap()[0].is_none());
        } else {
            assert!(result.unwrap()[0].is_some());
        }
        // Run the independent traversal after issuance so it cannot warm its cache.
        let reader = block_on(
            fx.pipe
                .object_reader(fx.repo_id("room"), ReaderView::Public),
        )
        .unwrap();
        if numerator == 1 {
            assert_eq!(
                block_on(reader.metadata_sizes(&[id(&leaf)])).unwrap(),
                vec![None]
            );
        } else {
            assert_eq!(
                block_on(reader.metadata_sizes(&[id(&leaf)])).unwrap(),
                vec![Some(7)]
            );
        }
    }
}

#[test]
fn private_default_fresh_repo_requires_explicit_public_for_connect_http_and_reader() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.default_repo_visibility = crate::pipeline::RepoVisibility::Private;
        cfg.url_tokens = Some(super::private_tokens::tokens());
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let repo = fx.repo_id("room");
    assert!(
        block_on(fx.pipe.meta.inner.get(
            &fx.pipe.shards.coordinator(&repo.namespace),
            &keys::repo_visibility(&repo.name)
        ))
        .unwrap()
        .is_none(),
        "first push does not store a visibility"
    );
    let anonymous = Req::unsigned(Procedure::ListRefs).header("x-repository", &fx.identity("room"));
    assert_eq!(
        block_on(fx.pipe.list_refs(&fx.auth(&anonymous), "refs/"))
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert_uniform_404(&fx.get(&fx.object_url("room", &id(&d.small))));
    assert_uniform_404(&fx.get(&fx.ref_url("room", "main", "small.txt")));
    assert_eq!(public_read(&fx, "room", &[id(&d.small)]), vec![None]);
    assert!(public_urls(&fx, &[UrlTarget::Object(id(&d.small))], 0).unwrap()[0].is_none());
    let set = signed(
        &fx.owner,
        &fx.identity("room"),
        Procedure::SetRepoVisibility,
        fx.number(),
    );
    block_on(fx.pipe.set_repo_visibility(
        &fx.auth(&set),
        VisibilityRequest::Envelope(crate::pipeline::RepoVisibility::Public),
    ))
    .unwrap();
    assert!(
        !block_on(fx.pipe.list_refs(&fx.auth(&anonymous), "refs/"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(fx.get(&fx.object_url("room", &id(&d.small))).status, 200);
    assert_eq!(fx.get(&fx.ref_url("room", "main", "small.txt")).status, 200);
    assert!(public_read(&fx, "room", &[id(&d.small)])[0].is_some());
    assert!(public_urls(&fx, &[UrlTarget::Object(id(&d.small))], 0).unwrap()[0].is_some());
}

#[test]
fn issue_urls_capped_preflight_hides_unreachable_and_denied_membership() {
    // One row truncates enumeration; two rows allow enumeration but cap the walk.
    for cap in [1, 2] {
        for blocked in [false, true] {
            let fx = fixture_tweaked(
                Hooks::new(),
                HttpObjectsConfig {
                    max_walk_objects: cap,
                    ..http_cfg()
                },
                |c| c.url_tokens = Some(super::private_tokens::tokens()),
            );
            let d = data();
            let orphan = blob(b"hidden unreachable member");
            let mut objects = d.refs();
            objects.push(&orphan);
            fx.push("room", &objects, d.head(), None);
            if blocked {
                block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta)).block(
                    &id(&orphan),
                    &crate::store::BlockEntry::new("manual", T0 as u64),
                    T0 as u64,
                ))
                .unwrap();
            }
            let proof_calls =
                [UrlTarget::Object([91; 32]), UrlTarget::Object(id(&orphan))].map(|target| {
                    let before = fx.pipe.meta.calls();
                    assert!(public_urls(&fx, &[target], 0).unwrap()[0].is_none());
                    fx.pipe.meta.calls() - before
                });
            assert_eq!(
                proof_calls[0], proof_calls[1],
                "membership must not change proof work"
            );
            let reader = block_on(
                fx.pipe
                    .object_reader(fx.repo_id("room"), ReaderView::Public),
            )
            .unwrap();
            assert_eq!(
                block_on(reader.metadata_sizes(&[id(&orphan)])).unwrap(),
                vec![None]
            );
        }
    }
}

#[test]
fn repeated_orphan_url_issuance_and_reads_expire_at_the_original_proof_deadline() {
    for delete in [false, true] {
        for surface in ["urls", "reader", "http"] {
            let fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| {
                c.url_tokens = Some(super::private_tokens::tokens());
            });
            let d = data();
            let pack = fx.push("room", &d.refs(), d.head(), None);
            let object = id(&d.small);
            let target = UrlTarget::Object(object);
            let token = public_urls(&fx, std::slice::from_ref(&target), 300).unwrap()[0]
                .clone()
                .unwrap();
            assert!(
                token.expires_at_ms > T0 + i64::try_from(http_cfg().reachability_lag_ms).unwrap()
            );
            let url = fx.object_url("room", &object);
            let etag = fx.get(&url).header("ETag").unwrap().to_owned();
            let repo = fx.repo_id("room");
            let partition = fx.pipe.shards.ref_shard(&repo, HEAD);
            let batch = if delete {
                Batch::new().delete(keys::published_ref(&repo.name, HEAD))
            } else {
                let (objects, _, head) = rewound();
                let refs: Vec<_> = objects.iter().collect();
                fx.push("room", &refs, id(&head), Some((d.head(), pack)));
                Batch::new().put(
                    keys::published_ref(&repo.name, HEAD),
                    codec::encode_ref_id(&id(&head)),
                )
            };
            block_on(fx.pipe.meta.inner.apply(&partition, batch)).unwrap();
            let half_lag = i64::try_from(http_cfg().reachability_lag_ms / 2).unwrap();
            for step in 1..=4 {
                fx.clock.advance(half_lag);
                let reachable = step < 2;
                match surface {
                    "urls" => assert_eq!(
                        public_urls(&fx, std::slice::from_ref(&target), 300).unwrap()[0].is_some(),
                        reachable,
                        "{surface}, delete={delete}, step={step}"
                    ),
                    "reader" => assert_eq!(
                        public_read(&fx, "room", &[object])[0].is_some(),
                        reachable,
                        "{surface}, delete={delete}, step={step}"
                    ),
                    _ => assert_eq!(fx.get(&url).status, if reachable { 200 } else { 404 }),
                }
                if !reachable {
                    assert_uniform_404(&fx.get(&url));
                    assert_uniform_404(&read(fx.request(
                        "GET",
                        &url,
                        None,
                        &[("If-None-Match", &etag)],
                    )));
                    assert_uniform_404(&read(fx.request(
                        "GET",
                        &url,
                        Some(&format!("token={}", token.expose())),
                        &[],
                    )));
                }
            }
        }
    }
}

#[test]
fn caller_cap_accounts_ancestors_and_duplicate_output_with_typed_exhaustion() {
    let fx = fixture();
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    // A walk the cap cannot afford is unprovable: absent, like an unknown id.
    assert_eq!(
        block_on(reader.read_canonical_with_limit(&[id(&d.big)], 1)).unwrap(),
        vec![None]
    );
    assert_eq!(
        block_on(reader.read_canonical_with_limit(&[id(&d.big); 2], 100_000))
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        block_on(reader.read_canonical_with_limit(&[d.head()], 4096)).unwrap(),
        vec![Some(serialize(&d.commit).unwrap())]
    );
    assert!(
        block_on(reader.read_canonical_with_limit(&[], 0))
            .unwrap()
            .is_empty()
    );
}
#[test]
fn typed_metadata_distinguishes_manifest_serialization_from_file_length() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| cfg.takedown_denial = true);
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    fx.clear_calls();
    let m =
        block_on(reader.object_metadata(&[id(&d.small), id(&d.manifest), id(&d.small)])).unwrap();
    let small = m[0].unwrap();
    assert_eq!(small.kind, ObjectType::Blob);
    assert_eq!(
        small.canonical_len,
        serialize(&d.small).unwrap().len() as u64
    );
    assert_eq!(small.logical_len, Some(small.canonical_len - 10));
    let manifest = m[1].unwrap();
    assert_eq!(manifest.kind, ObjectType::ChunkedBlob);
    assert_eq!(
        manifest.canonical_len,
        serialize(&d.manifest).unwrap().len() as u64
    );
    assert_eq!(manifest.logical_len, Some(d.whole().len() as u64));
    assert_eq!(m[0], m[2]);
    // Requested ancestors cannot be decoded to authorize other targets in the
    // same metadata batch. A root-only batch needs no ancestor reconstruction.
    let head = block_on(reader.object_metadata(&[d.head()])).unwrap()[0].unwrap();
    assert_eq!(head.kind, ObjectType::Commit);
    assert_eq!(head.logical_len, None);
}

#[test]
fn composed_canonical_and_metadata_batches_fit_one_request_allowance() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| cfg.takedown_denial = true);
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let parent = crate::indexed::budget::SliceBudget::new(crate::limits::OBJECT_READER_CALLS);
    *fx.pipe.meta.request_budget.lock().unwrap() = Some(parent.clone());
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    for _ in 0..3 {
        assert!(
            block_on(reader.read_canonical(&[id(&d.small), id(&d.manifest)]))
                .unwrap()
                .iter()
                .all(Option::is_some)
        );
        assert!(
            block_on(reader.object_metadata(&[id(&d.small), id(&d.manifest)]))
                .unwrap()
                .iter()
                .all(Option::is_some)
        );
    }
    let physical = parent.used() + 2 * u32::try_from(fx.calls.lock().unwrap().len()).unwrap();
    eprintln!("composed reader canonical+metadata batches=6 physical_calls={physical}");
    assert!(
        physical < 1000,
        "six composed batches retain request headroom"
    );
}

fn denied_orphan_matches_missing_before_reader_budget(metadata: bool, whole_pack: bool) {
    let cfg = HttpObjectsConfig {
        max_walk_objects: if metadata {
            1
        } else {
            http_cfg().max_walk_objects
        },
        ..http_cfg()
    };
    let fx = fixture_tweaked(Hooks::new(), cfg, |c| c.takedown_denial = true);
    let d = data();
    let orphan = blob(b"blocked orphan");
    let mut objects = d.refs();
    objects.push(&orphan);
    let pack = fx.push("room", &objects, d.head(), None);
    let denied = if whole_pack { pack } else { id(&orphan) };
    block_on(ContentIndex::new(BorrowedStore(&fx.pipe.meta)).block(
        &denied,
        &crate::store::BlockEntry::new("manual", T0 as u64),
        T0 as u64,
    ))
    .unwrap();
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    if metadata {
        let missing = block_on(reader.object_metadata(&[[91; 32]])).map_err(|e| e.code());
        let blocked = block_on(reader.object_metadata(&[id(&orphan)])).map_err(|e| e.code());
        assert_eq!(missing, Ok(vec![None]));
        assert_eq!(blocked, missing);
    } else {
        let missing =
            block_on(reader.read_canonical_with_limit(&[[91; 32]], 0)).map_err(|e| e.code());
        let blocked =
            block_on(reader.read_canonical_with_limit(&[id(&orphan)], 0)).map_err(|e| e.code());
        assert_eq!(missing, Ok(vec![None]));
        assert_eq!(blocked, missing);
    }
}

#[test]
fn denied_orphan_canonical_read_is_absent_before_byte_budget() {
    denied_orphan_matches_missing_before_reader_budget(false, false);
}

#[test]
fn denied_pack_canonical_read_is_absent_before_byte_budget() {
    denied_orphan_matches_missing_before_reader_budget(false, true);
}

#[test]
fn denied_orphan_metadata_is_absent_before_walk_budget() {
    denied_orphan_matches_missing_before_reader_budget(true, false);
}

#[test]
fn denied_pack_metadata_is_absent_before_walk_budget() {
    denied_orphan_matches_missing_before_reader_budget(true, true);
}

fn assert_same_response(a: &Got, b: &Got) {
    assert_eq!(a.status, b.status);
    assert_eq!(a.body, b.body);
    assert_eq!(a.headers, b.headers);
}

#[test]
fn unprovable_stored_ids_match_unknown_ids_for_public_readers_but_owners_get_typed_errors() {
    // Cap 1 truncates tip enumeration; cap 2 enumerates but cannot finish the walk.
    for cap in [1, 2] {
        let fx = fixture_tweaked(
            Hooks::new(),
            HttpObjectsConfig {
                max_walk_objects: cap,
                ..http_cfg()
            },
            |_| {},
        );
        let d = data();
        let orphan = blob(b"stored but unprovable orphan");
        let mut objects = d.refs();
        objects.push(&orphan);
        fx.push("room", &objects, d.head(), None);
        let (stored, unknown) = (id(&orphan), [91; 32]);
        let reader = block_on(
            fx.pipe
                .object_reader(fx.repo_id("room"), ReaderView::Public),
        )
        .unwrap();
        for target in [stored, unknown] {
            assert_eq!(block_on(reader.read_canonical(&[target])).unwrap(), [None]);
            assert_eq!(
                block_on(reader.read_canonical_with_limit(&[target], 1)).unwrap(),
                [None]
            );
            assert_eq!(block_on(reader.object_metadata(&[target])).unwrap(), [None]);
            assert_eq!(block_on(reader.metadata_sizes(&[target])).unwrap(), [None]);
        }
        assert_same_response(
            &fx.get(&fx.object_url("room", &stored)),
            &fx.get(&fx.object_url("room", &unknown)),
        );
        assert_uniform_404(&fx.get(&fx.object_url("room", &stored)));
        // The authorized owner view keeps the explicit typed errors.
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
        if cap == 2 {
            assert_eq!(
                block_on(owner.read_canonical_with_limit(&[stored], 1))
                    .unwrap_err()
                    .code(),
                Code::ResourceExhausted
            );
        } else {
            assert_eq!(
                block_on(owner.object_metadata(&[stored]))
                    .unwrap_err()
                    .code(),
                Code::ResourceExhausted
            );
        }
    }
}

fn with_owner_reader(
    fx: &Fx,
    run: impl FnOnce(&crate::pipeline::ObjectReader<'_, SpyBlobs, Arc<Spy>, Hooks>),
) {
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
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta)),
    )
    .unwrap();
    run(&reader);
}

#[test]
fn load_default_decode_cap_is_typed_exhaustion() {
    let d = data();
    let size = serialize(&d.big).unwrap().len() as u64;
    let fx = fixture_with(
        Hooks::new(),
        HttpObjectsConfig {
            max_inline_object_bytes: size,
            http_decode_budget: size,
            ..http_cfg()
        },
    );
    fx.push("room", &d.refs(), d.head(), None);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let error = block_on(reader.read_canonical(&[id(&d.big)])).unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
}

#[test]
fn too_many_rows_object_is_absent_without_failing_the_rest_of_the_batch() {
    let (fx, d) = published();
    let repo = fx.repo_id("room");
    let target = [90; 32];
    let partition = fx.pipe.shards.object_index(&repo, &target);
    let row = crate::store::index::IndexValue {
        frame_offset: 12,
        frame_length: 15,
        wire_type: 0,
        decoded_size: 10,
        chain_depth: 0,
        delta_base: None,
    };
    let encoded = codec::encode_object_index(&target, &row).unwrap();
    for chunk in (0..=crate::store::index::MAX_LOOKUP_ROWS)
        .collect::<Vec<_>>()
        .chunks(32)
    {
        let mut batch = Batch::new();
        for index in chunk {
            let mut pack = [0; 32];
            pack[..8].copy_from_slice(&u64::try_from(*index).unwrap().to_le_bytes());
            batch = batch.put(
                keys::object_index(&repo.name, &target, &pack),
                encoded.clone(),
            );
        }
        block_on(fx.pipe.meta.inner.apply(&partition, batch)).unwrap();
    }
    // R-148: a permanent row-cap miss is "not a member" for that id only, for
    // public and owner reads alike.
    let ids = [target, id(&d.small)];
    let expected = vec![None, Some(serialize(&d.small).unwrap())];
    assert_eq!(public_read(&fx, "room", &ids), expected);
    with_owner_reader(&fx, |reader| {
        assert_eq!(block_on(reader.read_canonical(&ids)).unwrap(), expected);
        let rows = block_on(reader.object_metadata(&ids)).unwrap();
        assert!(rows[0].is_none() && rows[1].is_some());
    });
}

#[test]
fn shared_sessions_enforce_each_aggregate_dimension_across_calls() {
    use crate::pipeline::{OBJECT_READER_LIMIT_MESSAGE, ReadLimits, ReaderSession};
    let (fx, d) = published();
    with_owner_reader(&fx, |reader| {
        let ids = [id(&d.small)];
        let mut probe = ReaderSession::default();
        assert!(block_on(reader.read_canonical_in(&mut probe, &ids)).unwrap()[0].is_some());
        let used = probe.used();
        assert!(used.storage_calls > 2);
        assert!(used.decoded_bytes > used.output_bytes);
        assert!(
            used.encoded_bytes > used.decoded_bytes,
            "range prefixes and frame headers are charged too"
        );
        let limits = [
            ReadLimits::new(used.storage_calls, u64::MAX, u64::MAX, u64::MAX),
            ReadLimits::new(u32::MAX, used.decoded_bytes, u64::MAX, u64::MAX),
            ReadLimits::new(u32::MAX, u64::MAX, used.encoded_bytes, u64::MAX),
            ReadLimits::new(u32::MAX, u64::MAX, u64::MAX, used.output_bytes),
        ];
        for limit in limits {
            let mut session = ReaderSession::new(limit);
            assert!(block_on(reader.read_canonical_in(&mut session, &ids)).unwrap()[0].is_some());
            let error = block_on(reader.read_canonical_in(&mut session, &ids)).unwrap_err();
            assert_eq!(
                (error.code(), error.public_message()),
                (Code::ResourceExhausted, OBJECT_READER_LIMIT_MESSAGE)
            );
            let spent = session.used();
            assert!(spent.storage_calls <= limit.storage_calls);
            assert!(spent.decoded_bytes <= limit.decoded_bytes);
            assert!(spent.encoded_bytes <= limit.encoded_bytes);
            assert!(spent.output_bytes <= limit.output_bytes);
        }
    });
}

#[test]
fn canonical_and_metadata_calls_share_one_session_call_ledger() {
    use crate::pipeline::{ReadLimits, ReaderSession};
    let (fx, d) = published();
    with_owner_reader(&fx, |reader| {
        let mut probe = ReaderSession::default();
        assert!(block_on(reader.object_metadata_in(&mut probe, &[d.head()])).unwrap()[0].is_some());
        let calls = probe.used().storage_calls;
        assert_eq!(probe.used().output_bytes, 0);
        let mut session =
            ReaderSession::new(ReadLimits::new(calls + 2, u64::MAX, u64::MAX, u64::MAX));
        assert!(
            block_on(reader.object_metadata_in(&mut session, &[d.head()])).unwrap()[0].is_some()
        );
        assert_eq!(
            block_on(reader.read_canonical_in(&mut session, &[d.head()]))
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
        assert_eq!(session.used().storage_calls, calls + 2);
    });
}

#[test]
fn session_output_counts_duplicates_without_duplicate_decode_work() {
    use crate::pipeline::{ReadLimits, ReaderSession};
    let (fx, d) = published();
    with_owner_reader(&fx, |reader| {
        let canonical = serialize(&d.small).unwrap();
        let limit = canonical.len() as u64 * 2;
        let mut session = ReaderSession::new(ReadLimits::new(u32::MAX, u64::MAX, u64::MAX, limit));
        assert_eq!(
            block_on(reader.read_canonical_in(&mut session, &[id(&d.small); 2])).unwrap(),
            [Some(canonical.clone()), Some(canonical)]
        );
        assert_eq!(session.used().output_bytes, limit);
        assert_eq!(
            block_on(reader.read_canonical_in(&mut session, &[id(&d.small)]))
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
        assert_eq!(session.used().output_bytes, limit);
    });
}

#[test]
fn session_caps_preserve_public_uniform_absence() {
    use crate::pipeline::{ReadLimits, ReaderSession};
    let fx = fixture();
    let d = data();
    let orphan = blob(b"unreachable member");
    let mut objects = d.refs();
    objects.push(&orphan);
    fx.push("room", &objects, d.head(), None);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    for limits in [
        ReadLimits::new(2, u64::MAX, u64::MAX, u64::MAX),
        ReadLimits::new(u32::MAX, 0, u64::MAX, u64::MAX),
        ReadLimits::new(u32::MAX, u64::MAX, 0, u64::MAX),
    ] {
        for target in [id(&orphan), [91; 32]] {
            let mut session = ReaderSession::new(limits);
            assert_eq!(
                block_on(reader.read_canonical_in(&mut session, &[target])).unwrap(),
                [None]
            );
            let mut session = ReaderSession::new(limits);
            assert_eq!(
                block_on(reader.object_metadata_in(&mut session, &[target])).unwrap(),
                [None]
            );
        }
    }
}

#[test]
fn inherited_invocation_call_exhaustion_is_typed_for_owner_reads() {
    let (fx, d) = published();
    with_owner_reader(&fx, |reader| {
        let before = fx.pipe.meta.calls();
        assert!(block_on(reader.read_canonical(&[id(&d.small)])).unwrap()[0].is_some());
        let parent = crate::indexed::budget::SliceBudget::new(fx.pipe.meta.calls() - before - 1);
        *fx.pipe.meta.request_budget.lock().unwrap() = Some(parent);
        assert_eq!(
            block_on(reader.read_canonical(&[id(&d.small)]))
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
    });
}

struct PausedFrame<'a> {
    inner: &'a SpyBlobs,
    pack: Hash,
}
impl BlobStore for PausedFrame<'_> {
    type Sink = <SpyBlobs as BlobStore>::Sink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        if *key == BlobKey::pack(self.pack) && range.is_some_and(|range| range.start >= 12) {
            std::future::pending().await
        } else {
            self.inner.get(key, range).await
        }
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.inner.head(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}

#[test]
fn cancelled_recursive_load_keeps_completed_base_decode_debit() {
    let debit = cancelled_load_debit(crate::indexed::resolve::Caps::Reader);
    assert_eq!(
        debit,
        serialize(&blob(b"base payload")).unwrap().len() as u64
    );
}

// HTTP serving charges retained bytes (here the retained base), as before.
#[test]
fn http_path_charges_retained_bytes_for_cancelled_loads() {
    let debit = cancelled_load_debit(crate::indexed::resolve::Caps::Legacy);
    assert_eq!(
        debit,
        serialize(&blob(b"base payload")).unwrap().len() as u64
    );
}

fn cancelled_load_debit(caps: crate::indexed::resolve::Caps) -> u64 {
    use crate::http_objects::resolve::{self, Env};
    use crate::pipeline::ReaderSession;
    use crate::store::view::ViewStore;
    let fx = fixture();
    let base = blob(b"base payload");
    let old_root = tree(&[("base", EntryMode::Blob, &base)]);
    let old_head = commit(&old_root, &[], "old");
    let old_pack = fx.push("room", &[&base, &old_root, &old_head], id(&old_head), None);
    let derived = blob(b"derived payload");
    let root = tree(&[("derived", EntryMode::Blob, &derived)]);
    let head = commit(&root, &[], "derived");
    let mut writer = PackWriter::new();
    writer
        .push_delta(
            &id(&base),
            &mkit_core::delta::encode(&serialize(&base).unwrap(), &serialize(&derived).unwrap())
                .unwrap(),
        )
        .unwrap();
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
        (Match(id(&old_head)), Match(old_pack)),
    );
    assert_eq!(outcome, AdvanceOutcome::Committed);
    let repo = fx.repo_id("room");
    let view = ViewStore {
        store: &fx.pipe.meta,
        repo: &repo,
        writer: true,
        policy: None,
    };
    let blobs = PausedFrame {
        inner: &fx.pipe.blobs,
        pack,
    };
    let no_reads = std::collections::BTreeSet::new();
    let env = Env {
        no_reads: &no_reads,
        blobs: &blobs,
        meta: &view,
        shards: fx.pipe.shards.as_ref(),
        repo: &repo,
        indexed: fx.pipe.cfg.indexed.as_ref().unwrap(),
        cfg: fx.pipe.cfg.http_objects.as_ref().unwrap(),
        metrics: fx.pipe.metrics.as_ref(),
        caps,
    };
    let located = block_on(resolve::locate(&env, id(&derived))).unwrap();
    let mut session = ReaderSession::default();
    {
        let (_, mut charge, _) = session.split(env.cfg.http_decode_budget);
        let mut future = Box::pin(resolve::load(
            &env,
            id(&derived),
            located,
            &mut charge.budget,
        ));
        assert!(
            block_on(std::future::poll_fn(|cx| std::task::Poll::Ready(
                future.as_mut().poll(cx)
            )))
            .is_pending()
        );
        drop(future);
    }
    session.used().decoded_bytes
}

#[test]
fn inherited_invocation_caps_during_authorization_are_typed() {
    let (fx, d) = published();
    with_owner_reader(&fx, |reader| {
        *fx.pipe.meta.request_budget.lock().unwrap() =
            Some(crate::indexed::budget::SliceBudget::new(0));
        assert_eq!(
            block_on(reader.read_canonical(&[id(&d.small)]))
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
        assert_eq!(
            block_on(reader.object_metadata(&[id(&d.small)]))
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
    });
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    for target in [id(&d.small), [91; 32]] {
        assert_eq!(
            block_on(reader.read_canonical(&[target]))
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
    }
}

#[test]
fn inherited_url_issuance_authorization_caps_are_typed() {
    let (fx, d) = url_fixture();
    *fx.pipe.meta.request_budget.lock().unwrap() =
        Some(crate::indexed::budget::SliceBudget::new(1));
    let error = public_urls(&fx, &[UrlTarget::Object(id(&d.small))], 0).unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
    assert_eq!(
        error.public_message(),
        crate::pipeline::OBJECT_READER_LIMIT_MESSAGE
    );
}

fn overflow_member_candidates(fx: &Fx, target: Hash) {
    let repo = fx.repo_id("room");
    let partition = fx.pipe.shards.object_index(&repo, &target);
    let row = crate::store::index::IndexValue {
        frame_offset: 12,
        frame_length: 15,
        wire_type: 0,
        decoded_size: 10,
        chain_depth: 0,
        delta_base: None,
    };
    let encoded = codec::encode_object_index(&target, &row).unwrap();
    for chunk in (0..=crate::store::index::MAX_LOOKUP_ROWS)
        .collect::<Vec<_>>()
        .chunks(32)
    {
        let mut batch = Batch::new();
        for index in chunk {
            let mut pack = [0; 32];
            pack[24..].copy_from_slice(&u64::try_from(*index).unwrap().to_be_bytes());
            batch = batch.put(
                keys::object_index(&repo.name, &target, &pack),
                encoded.clone(),
            );
        }
        block_on(fx.pipe.meta.inner.apply(&partition, batch)).unwrap();
    }
}

#[test]
fn public_membership_cap_preserves_other_proven_targets_with_denial_enabled() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |c| c.takedown_denial = true);
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    overflow_member_candidates(&fx, id(&d.small));
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    assert_eq!(
        block_on(reader.read_canonical(&[id(&d.small), id(&d.big)])).unwrap(),
        vec![None, Some(serialize(&d.big).unwrap())]
    );
    let rows = block_on(reader.object_metadata(&[id(&d.small), id(&d.big)])).unwrap();
    assert!(rows[0].is_none());
    assert!(rows[1].is_some());
}

fn published_external_delta_member() -> (Fx, Hash, Hash) {
    published_external_delta_member_with(fixture())
}

fn published_external_delta_member_with(fx: Fx) -> (Fx, Hash, Hash) {
    let base = blob(b"base payload");
    let old_root = tree(&[("base", EntryMode::Blob, &base)]);
    let old_head = commit(&old_root, &[], "old");
    let old_pack = fx.push("room", &[&base, &old_root, &old_head], id(&old_head), None);
    let derived = blob(b"derived payload");
    let root = tree(&[("derived", EntryMode::Blob, &derived)]);
    let head = commit(&root, &[], "derived");
    let mut writer = PackWriter::new();
    writer
        .push_delta(
            &id(&base),
            &mkit_core::delta::encode(&serialize(&base).unwrap(), &serialize(&derived).unwrap())
                .unwrap(),
        )
        .unwrap();
    for object in [&root, &head] {
        writer
            .push_raw(id(object), &serialize(object).unwrap())
            .unwrap();
    }
    let (outcome, _) = fx.push_pack(
        "room",
        &writer.finish().unwrap(),
        (HEAD, PACKMAP),
        id(&head),
        (Match(id(&old_head)), Match(old_pack)),
    );
    assert_eq!(outcome, AdvanceOutcome::Committed);
    (fx, id(&base), id(&derived))
}

#[test]
fn external_delta_base_membership_caps_are_typed_for_owner_reads() {
    let (fx, base, target) = published_external_delta_member();
    overflow_member_candidates(&fx, base);
    with_owner_reader(&fx, |reader| {
        assert_eq!(
            block_on(reader.read_canonical(&[target]))
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
        assert_eq!(
            block_on(reader.object_metadata(&[target]))
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
    });
}

#[test]
fn reader_delta_depth_caps_are_typed_without_changing_http_errors() {
    let (mut fx, _, target) = published_external_delta_member();
    fx.pipe.cfg.indexed.as_mut().unwrap().max_delta_chain_depth = 0;
    with_owner_reader(&fx, |reader| {
        assert_eq!(
            block_on(reader.read_canonical(&[target]))
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
        assert_eq!(
            block_on(reader.object_metadata(&[target]))
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
    });
    assert_eq!(fx.get(&fx.object_url("room", &target)).status, 503);
}

#[test]
fn proven_public_metadata_depth_cap_is_typed() {
    let (mut fx, _, target) = published_external_delta_member();
    fx.pipe.cfg.indexed.as_mut().unwrap().max_delta_chain_depth = 0;
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let error = block_on(reader.object_metadata(&[target])).unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
    assert_eq!(
        error.public_message(),
        crate::pipeline::OBJECT_READER_LIMIT_MESSAGE
    );
}

#[test]
fn proven_public_metadata_base_membership_cap_is_typed() {
    let (fx, base, target) = published_external_delta_member();
    overflow_member_candidates(&fx, base);
    let reader = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let error = block_on(reader.object_metadata(&[target])).unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
    assert_eq!(
        error.public_message(),
        crate::pipeline::OBJECT_READER_LIMIT_MESSAGE
    );
}

fn denial_fixture() -> (Fx, Hash, Hash) {
    published_external_delta_member_with(fixture_tweaked(Hooks::new(), http_cfg(), |c| {
        c.takedown_denial = true;
    }))
}

fn assert_typed_exhaustion(error: &ServerError) {
    assert_eq!(error.code(), Code::ResourceExhausted);
    assert_eq!(
        error.public_message(),
        crate::pipeline::OBJECT_READER_LIMIT_MESSAGE
    );
}

fn assert_denial_caps_typed(fx: &Fx, target: Hash) {
    let public = block_on(
        fx.pipe
            .object_reader(fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    assert_typed_exhaustion(&block_on(public.read_canonical(&[target])).unwrap_err());
    assert_typed_exhaustion(&block_on(public.object_metadata(&[target])).unwrap_err());
    with_owner_reader(fx, |reader| {
        assert_typed_exhaustion(&block_on(reader.read_canonical(&[target])).unwrap_err());
        assert_typed_exhaustion(&block_on(reader.object_metadata(&[target])).unwrap_err());
    });
}

#[test]
fn denial_traversal_depth_cap_is_typed_for_public_and_owner_reads() {
    let (mut fx, _, target) = denial_fixture();
    fx.pipe.cfg.indexed.as_mut().unwrap().max_delta_chain_depth = 0;
    assert_denial_caps_typed(&fx, target);
}

#[test]
fn denial_traversal_base_membership_cap_is_typed_for_public_and_owner_reads() {
    let (fx, base, target) = denial_fixture();
    overflow_member_candidates(&fx, base);
    assert_denial_caps_typed(&fx, target);
}

#[test]
fn corrupt_delta_cycles_remain_unavailable_instead_of_read_exhaustion() {
    let (fx, base, target) = published_external_delta_member();
    let repo = fx.repo_id("room");
    let view = crate::store::view::ViewStore {
        store: &fx.pipe.meta,
        repo: &repo,
        writer: true,
        policy: None,
    };
    let located = block_on(crate::indexed::resolve::locate_split(
        &view,
        fx.pipe.shards.as_ref(),
        &repo,
        &[base],
        fx.pipe.metrics.as_ref(),
    ))
    .unwrap()
    .remove(&base)
    .unwrap()
    .unwrap()
    .unwrap();
    let mut row = located.value;
    row.delta_base = Some(target);
    row.wire_type = 2;
    row.chain_depth = 1;
    block_on(fx.pipe.meta.inner.apply(
        &fx.pipe.shards.object_index(&repo, &base),
        Batch::new().put(
            keys::object_index(&repo.name, &base, &located.pack),
            codec::encode_object_index(&base, &row).unwrap(),
        ),
    ))
    .unwrap();
    with_owner_reader(&fx, |reader| {
        assert_eq!(
            block_on(reader.read_canonical(&[target]))
                .unwrap_err()
                .code(),
            Code::Unavailable
        );
    });
    assert_eq!(fx.get(&fx.object_url("room", &target)).status, 503);
}

#[test]
fn owner_reader_preserves_caller_budget_exhaustion_during_authorization() {
    use crate::indexed::budget::SliceBudget;
    let fx = fixture();
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
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
    for allowance in [0, 1] {
        let caller = SliceBudget::new(allowance);
        *fx.pipe.meta.request_budget.lock().unwrap() = Some(caller.clone());
        let result = block_on(async {
            let reader = fx
                .pipe
                .object_reader(fx.repo_id("room"), ReaderView::Owner(&meta))
                .await?;
            reader.object_metadata(&[id(&d.small)]).await
        });
        assert_eq!(result.unwrap_err().code(), Code::ResourceExhausted);
        assert_eq!(caller.used(), allowance);
    }
}

// Preserve existing mixed-size assertions through the supported metadata API.
impl<B: MultipartBlobStore, N: NamespaceStore + Clone + 'static, H: HookSet>
    crate::pipeline::ObjectReader<'_, B, N, H>
{
    async fn metadata_sizes(&self, ids: &[Hash]) -> Result<Vec<Option<u64>>, ServerError> {
        Ok(self
            .object_metadata(ids)
            .await?
            .into_iter()
            .map(|row| {
                row.map(|m| {
                    if m.kind == ObjectType::Blob {
                        m.logical_len.unwrap_or(0)
                    } else {
                        m.canonical_len
                    }
                })
            })
            .collect())
    }
}
