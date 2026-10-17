//! Indexed fork fixtures and semantic controls for the disposable reference host.
use super::*;
use crate::control::{
    ForkFixture, ForkFixtureQuery, ForkObservation, ForkQuery, ForkResultView, ForkSourceChange,
};
use mkit_core::{
    object::{Commit, Identity, Object, Tree},
    pack::{DecodeLimits, NoExternalBases, PackWriter, decode_entries_with},
    serialize::serialize,
    sign::{KeyPair, sign_commit},
};
use mkit_server::fork::{self, ForkJobV1, ForkResult, Phase};
use mkit_server::pipeline::{D34Shards, Sharding};
use mkit_server::store::adapter_spi::{
    index::{IndexEntry, IndexValue},
    publication::{Pair, Publication, Witness},
};
use mkit_server::store::content_shard;
use mkit_server::takedown::inventory;
use mkit_server::{BlobKey, BlobStore, PackSink};

#[derive(Clone)]
struct SourceFixture {
    source: RepoId,
    head: String,
    fixture: ForkFixture,
}

pub(super) struct ForkBinding {
    pub(super) core: RwLock<Arc<Core>>,
    config: PipelineConfig,
    fixtures: Mutex<BTreeMap<String, SourceFixture>>,
}

impl ForkBinding {
    pub(super) fn new(
        store: &ControlStore,
        blobs: &MemoryBlobStore,
        clock: &Arc<ManualClock>,
        config: &PipelineConfig,
    ) -> Result<Self, String> {
        let mut config = config.clone();
        config.sharding = Sharding::D34;
        config.indexed = Some(mkit_server::indexed::IndexedConfig::scheduled(1024 * 1024));
        config.write_quota = None;
        config.takedown_denial = false;
        Ok(Self {
            core: RwLock::new(build_core(store, blobs, clock, &config)?),
            config,
            fixtures: Mutex::default(),
        })
    }

    pub(super) async fn restart(
        &self,
        store: &ControlStore,
        blobs: &MemoryBlobStore,
        clock: &Arc<ManualClock>,
    ) -> Result<(), String> {
        *self.core.write().await = build_core(store, blobs, clock, &self.config)?;
        Ok(())
    }

    pub(super) fn handles(&self, repository: &str) -> bool {
        self.fixtures
            .lock()
            .unwrap()
            .iter()
            .any(|(destination, fixture)| {
                destination == repository
                    || format!(
                        "{}/{}",
                        fixture.source.namespace.as_str(),
                        fixture.source.name.as_str()
                    ) == repository
            })
    }
}

impl HostState {
    #[allow(clippy::too_many_lines)] // Seed a complete independent protocol fixture.
    pub(super) async fn prepare_fork(
        &self,
        query: ForkFixtureQuery,
    ) -> Result<ForkFixture, String> {
        let destination = self.repository(&query.destination)?;
        let signer = parse_hash(&query.signer)?;
        if destination.namespace.as_str() != format!("ed25519-{}", to_hex(&signer))
            || !mkit_server::refs::validate_ref_name(&query.source_head)
            || !query.source_head.starts_with("refs/heads/")
        {
            return Err("invalid fork fixture identity".into());
        }
        if self
            .forks
            .fixtures
            .lock()
            .unwrap()
            .contains_key(&query.destination)
        {
            return Err("fork fixture already exists".into());
        }
        let suffix = to_hex(&hash(query.destination.as_bytes()));
        let key = KeyPair::from_seed([0x73; 32]);
        let namespace = format!("ed25519-{}", to_hex(&key.public.0));
        let source = RepoId {
            namespace: parse_namespace(&namespace)?,
            name: RepoName::new(format!("fork-source-{}", &suffix[..16]))
                .map_err(|e| e.to_string())?,
        };
        let (bytes, map_bytes, tip, pack, packmap) =
            fixture_contents(query.source_head.as_bytes())?;
        let now = u64::try_from(self.clock.now_ms()).map_err(|e| e.to_string())?;
        self.seed_fork_pack(&source, &bytes, None, now).await?;
        self.seed_fork_pack(&source, &map_bytes, Some(&[pack]), now)
            .await?;
        let coordinator = D34Shards.coordinator(&source.namespace);
        self.store
            .apply(
                &coordinator,
                Batch::new()
                    .put(
                        keys::namespace_record(),
                        codec::encode_namespace_record(&codec::NamespaceRecord {
                            created_at_ms: now,
                            config_version: 1,
                        }),
                    )
                    .put(
                        keys::repo_record(&source.name),
                        codec::encode_repo_record(&codec::RepoRecord { created_at_ms: now }),
                    )
                    .put(
                        keys::repo_visibility(&source.name),
                        codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                            visibility: codec::StoredVisibility::Public,
                            last_created_ms: 0,
                            last_statement_id: None,
                            changed_ms: now,
                        }),
                    )
                    .put(
                        keys::repo_storage(&source.name),
                        codec::encode_repo_storage(&codec::RepoStorageV1 {
                            stored_bytes: u64::try_from(bytes.len() + map_bytes.len())
                                .map_err(|e| e.to_string())?,
                            ..Default::default()
                        }),
                    ),
            )
            .await
            .map_err(|e| e.to_string())?;
        let partition = D34Shards.ref_shard(&source, &query.source_head);
        let map_ref =
            mkit_attest::grant::head_packmap(&query.source_head).ok_or("invalid source head")?;
        self.store
            .apply(
                &partition,
                Batch::new()
                    .put(
                        keys::publication(&source.name, &query.source_head),
                        Publication {
                            sequence: 1,
                            published: 1,
                            boundary: 0,
                            generation: 0,
                            value: Pair {
                                head: Some(tip),
                                packmap: Some(packmap),
                            },
                        }
                        .encode()
                        .map_err(|e| e.to_string())?,
                    )
                    .put(
                        keys::ref_key(&source.name, &query.source_head),
                        codec::encode_ref_id(&tip),
                    )
                    .put(
                        keys::ref_key(&source.name, &map_ref),
                        codec::encode_ref_id(&packmap),
                    ),
            )
            .await
            .map_err(|e| e.to_string())?;
        let request = fork::ForkRequest {
            source: source.clone(),
            source_ref: query.source_head.clone(),
            expected_tip: tip,
            dest_visibility: mkit_attest::grant::Visibility::Public,
        };
        // Calibrate on a separate destination. Preparing a fixture never starts
        // its queried destination, and the calibration uses identical content.
        let calibration = RepoId {
            namespace: destination.namespace.clone(),
            name: RepoName::new(format!("fork-calibration-{}", &suffix[..16]))
                .map_err(|e| e.to_string())?,
        };
        // Register the fixture's authority facts without creating either
        // destination repository. Calibration may create the namespace record;
        // the real fork must still see a locally installed generation fence.
        let destination_coordinator = D34Shards.coordinator(&destination.namespace);
        if self
            .store
            .inner
            .get(&destination_coordinator, &keys::authority_generation())
            .await
            .map_err(|e| e.to_string())?
            .is_none()
        {
            self.store
                .apply(
                    &destination_coordinator,
                    Batch::new()
                        .require(mkit_server::Precondition::Absent(
                            keys::authority_generation(),
                        ))
                        .put(keys::authority_generation(), codec::encode_u64(0)),
                )
                .await
                .map_err(|e| e.to_string())?;
        }
        let spec = request.spec_for(calibration.clone());
        let env = fork::ForkEnv::from_config(
            &self.store,
            &D34Shards,
            self.clock.as_ref(),
            &self.forks.config,
        );
        let planned = fork::plan_fork(&env, &spec)
            .await
            .map_err(|e| e.error().to_string())?;
        let authority = self
            .store
            .inner
            .get(
                &D34Shards.coordinator(&destination.namespace),
                &keys::authority_generation(),
            )
            .await
            .map_err(|e| e.to_string())?;
        let fence = fork::FenceV1 {
            authority_generation: Some(
                authority
                    .as_ref()
                    .map(codec::decode_u64)
                    .transpose()
                    .map_err(|e| e.to_string())?
                    .unwrap_or(0),
            ),
            grant_epoch: None,
            create_namespace: true,
        };
        fork::start_planned(&env, &spec, None, Some(fence), planned)
            .await
            .map_err(|e| e.error().to_string())?;
        for _ in 0..64 {
            let report = fork::step(
                &env,
                &calibration,
                &mkit_server::budget::SliceBudget::new(fork::SLICE_CALLS),
            )
            .await
            .map_err(|e| e.error().to_string())?;
            if report.job.finished() {
                if report.job.failure.is_some() {
                    return Err("fork fixture calibration failed".into());
                }
                break;
            }
        }
        let advancing_commits = *self
            .store
            .fork_progress
            .lock()
            .unwrap()
            .get(&(
                D34Shards.coordinator(&calibration.namespace),
                keys::fork_job(&calibration.name),
            ))
            .ok_or("fork fixture has no preparation commits")?;
        let fixture = ForkFixture {
            source_repository: format!("{}/{}", source.namespace.as_str(), source.name.as_str()),
            source_head: query.source_head.clone(),
            tip: to_hex(&tip),
            packmap: to_hex(&packmap),
            packs: vec![to_hex(&packmap), to_hex(&pack)],
            objects: vec![to_hex(&packmap), to_hex(&tip)],
            advancing_commits,
        };
        self.forks.fixtures.lock().unwrap().insert(
            query.destination,
            SourceFixture {
                source,
                head: query.source_head,
                fixture: fixture.clone(),
            },
        );
        Ok(fixture)
    }

    #[allow(clippy::too_many_lines)] // Keep pack facts, indexes and membership construction together.
    async fn seed_fork_pack(
        &self,
        source: &RepoId,
        bytes: &[u8],
        listed: Option<&[Hash]>,
        now: u64,
    ) -> Result<(), String> {
        let pack = hash(bytes);
        let length = u64::try_from(bytes.len()).map_err(|e| e.to_string())?;
        // A fresh fixture restores only its own content's denial state. The
        // portable denial cases intentionally repeat identical pack contents
        // while selecting a different pack for each independent attempt.
        self.store
            .apply(
                &content_shard(&pack),
                Batch::new().delete(keys::block(&pack)),
            )
            .await
            .map_err(|e| e.to_string())?;
        let mut sink = self
            .blobs
            .begin(BlobKey::pack(pack), length)
            .await
            .map_err(|e| e.to_string())?;
        sink.write(bytes::Bytes::copy_from_slice(bytes))
            .await
            .map_err(|e| e.to_string())?;
        sink.commit().await.map_err(|e| e.to_string())?;
        let mut objects = Vec::new();
        if let Some(packs) = listed {
            inventory::stage_packlist(&self.store, &pack, length, None, packs, now)
                .await
                .map_err(|e| e.to_string())?;
        } else {
            decode_entries_with(
                bytes,
                &mut NoExternalBases,
                DecodeLimits::default(),
                |entry| {
                    objects.push((
                        entry.id,
                        entry.object,
                        IndexEntry {
                            object: entry.id,
                            value: IndexValue {
                                frame_offset: entry.frame_offset,
                                frame_length: entry.frame_length,
                                wire_type: entry.wire_type,
                                decoded_size: entry.bytes.len() as u64,
                                chain_depth: 0,
                                delta_base: None,
                            },
                        },
                    ));
                    Ok(())
                },
            )
            .map_err(|e| e.to_string())?;
        }
        for (id, object, _) in &objects {
            inventory::stage(&self.store, &pack, length, id, object, None, now)
                .await
                .map_err(|e| e.to_string())?;
        }
        let entries: Vec<_> = objects.into_iter().map(|(_, _, entry)| entry).collect();
        let shard = D34Shards.membership(source, &BlobKey::pack(pack));
        let plan = mkit_server::store::adapter_spi::index::plan_index_rows_direct(
            &D34Shards, source, &shard, &pack, &entries, now,
        )
        .map_err(|e| e.to_string())?;
        for direct in plan.direct {
            let mut batch = Batch::new();
            for (key, value) in direct.puts {
                batch = batch.put(key, value);
            }
            self.store
                .apply(&direct.target, batch)
                .await
                .map_err(|e| e.to_string())?;
        }
        inventory::complete(&self.store, &pack, length, now)
            .await
            .map_err(|e| e.to_string())?;
        let witness = Witness {
            generation: 0,
            sequence: 1,
            published: true,
            held: false,
            boundary: false,
        }
        .encode();
        self.store
            .apply(
                &shard,
                Batch::new()
                    .put(keys::membership(&source.name, &pack), witness.clone())
                    .put(keys::published_member(&source.name, &pack), witness)
                    .put(
                        keys::verification(&source.name, &pack),
                        mkit_server::indexed::state::encode(
                            &mkit_server::indexed::state::VerificationV1::Verified {
                                pack_len: length,
                                verified_at_ms: now,
                                publication: None,
                            },
                        ),
                    ),
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // One semantic snapshot under the mutation gate.
    pub(super) async fn observe_fork(&self, query: ForkQuery) -> Result<ForkObservation, String> {
        if query.replay.repository != query.destination {
            return Err("fork replay identity differs from destination".into());
        }
        let fixture = self
            .forks
            .fixtures
            .lock()
            .unwrap()
            .get(&query.destination)
            .cloned()
            .ok_or("unknown fork fixture")?;
        let dest = self.repository(&query.destination)?;
        let partition = D34Shards.coordinator(&dest.namespace);
        let guard = self.store.gate.lock().await;
        let reader = ObservationReader {
            host: self,
            partition: partition.clone(),
            _guard: guard,
        };
        let job = reader
            .read(keys::fork_job(&dest.name))
            .await?
            .as_ref()
            .map(fork::decode_job)
            .transpose()
            .map_err(|e| e.to_string())?;
        let mut staged_memberships = Vec::new();
        let mut visible_memberships = Vec::new();
        for pack in &query.packs {
            let id = parse_hash(pack)?;
            staged_memberships.push(
                job.as_ref()
                    .is_some_and(|job| job.packs.iter().any(|pack| pack.id == id)),
            );
            let raw = self
                .store
                .inner
                .get(
                    &D34Shards.membership(&dest, &BlobKey::pack(id)),
                    &keys::published_member(&dest.name, &id),
                )
                .await
                .map_err(|e| e.to_string())?;
            visible_memberships.push(
                raw.as_ref()
                    .map(Witness::decode)
                    .transpose()
                    .map_err(|e| e.to_string())?
                    .is_some_and(|w| w.visible(false, 0)),
            );
        }
        let ref_partition = D34Shards.ref_shard(&dest, &fixture.head);
        let head = self
            .store
            .inner
            .get(&ref_partition, &keys::ref_key(&dest.name, &fixture.head))
            .await
            .map_err(|e| e.to_string())?
            .as_ref()
            .map(codec::decode_ref_id)
            .transpose()
            .map_err(|e| e.to_string())?
            .map(|id| to_hex(&id));
        let map_ref =
            mkit_attest::grant::head_packmap(&fixture.head).ok_or("invalid source head")?;
        let packmap = self
            .store
            .inner
            .get(&ref_partition, &keys::ref_key(&dest.name, &map_ref))
            .await
            .map_err(|e| e.to_string())?
            .as_ref()
            .map(codec::decode_ref_id)
            .transpose()
            .map_err(|e| e.to_string())?
            .map(|id| to_hex(&id));
        let replay = reader
            .replay(&query.destination, Some(&query.replay))
            .await?;
        let rid = job
            .as_ref()
            .and_then(|job| job.settle.as_ref())
            .map(|s| s.rid.clone())
            .filter(|rid| !rid.is_empty());
        let outcome = reader.reservations(vec![rid]).await?.pop().flatten();
        let accepted = job.as_ref().and_then(|job| job.accepted.as_ref());
        Ok(ForkObservation {
            accepted: accepted.is_some(),
            failed: job.as_ref().is_some_and(|job| job.failure.is_some()),
            writable: job.as_ref().is_some_and(|job| job.phase == Phase::Done),
            head,
            packmap,
            staged_memberships,
            visible_memberships,
            progress_commits: self
                .store
                .fork_progress
                .lock()
                .unwrap()
                .get(&(partition, keys::fork_job(&dest.name)))
                .copied()
                .unwrap_or(0),
            result: accepted.map(result_view),
            replay,
            outcome,
        })
    }

    pub(super) async fn change_fork_source(
        &self,
        query: ForkQuery,
        change: ForkSourceChange,
    ) -> Result<(), String> {
        let fixture = self
            .forks
            .fixtures
            .lock()
            .unwrap()
            .get(&query.destination)
            .cloned()
            .ok_or("unknown fork fixture")?;
        let source = &fixture.source;
        let now = u64::try_from(self.clock.now_ms()).map_err(|e| e.to_string())?;
        match change {
            ForkSourceChange::Moved | ForkSourceChange::Unpublished => {
                let p = D34Shards.ref_shard(source, &fixture.head);
                let key = keys::publication(&source.name, &fixture.head);
                let mut publication = Publication::decode(
                    self.store
                        .get(&p, &key)
                        .await
                        .map_err(|e| e.to_string())?
                        .as_ref(),
                )
                .map_err(|e| e.to_string())?;
                publication.sequence += 1;
                publication.published = publication.sequence;
                publication.value = if change == ForkSourceChange::Moved {
                    let (bytes, map_bytes, tip, pack, packmap) =
                        fixture_contents(format!("{} moved", fixture.head).as_bytes())?;
                    self.seed_fork_pack(source, &bytes, None, now).await?;
                    self.seed_fork_pack(source, &map_bytes, Some(&[pack]), now)
                        .await?;
                    Pair {
                        head: Some(tip),
                        packmap: Some(packmap),
                    }
                } else {
                    Pair::default()
                };
                self.store
                    .apply(
                        &p,
                        Batch::new().put(key, publication.encode().map_err(|e| e.to_string())?),
                    )
                    .await
                    .map_err(|e| e.to_string())?;
            }
            ForkSourceChange::VisibilityRevoked => {
                self.store
                    .apply(
                        &D34Shards.coordinator(&source.namespace),
                        Batch::new()
                            .put(
                                keys::repo_visibility(&source.name),
                                codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                                    visibility: codec::StoredVisibility::Private,
                                    last_created_ms: now,
                                    last_statement_id: None,
                                    changed_ms: now,
                                }),
                            )
                            .put(
                                keys::repo_visibility_revision(&source.name),
                                codec::encode_u64(1),
                            ),
                    )
                    .await
                    .map_err(|e| e.to_string())?;
            }
            ForkSourceChange::Denied => {
                if query.packs.is_empty() {
                    return Err("denial needs at least one pack".into());
                }
                for pack in query.packs {
                    if !fixture.fixture.packs.contains(&pack) {
                        return Err("pack is outside fork fixture".into());
                    }
                    let pack = parse_hash(&pack)?;
                    self.store
                        .apply(
                            &content_shard(&pack),
                            Batch::new().put(
                                keys::block(&pack),
                                codec::encode_block_entry(&mkit_server::store::BlockEntry::new(
                                    "fork fixture denial",
                                    now,
                                )),
                            ),
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        Ok(())
    }

    pub(super) async fn invoke_fork(
        &self,
        headers: http::HeaderMap,
        body: bytes::Bytes,
    ) -> axum::response::Response {
        let core = self.forks.core.read().await.clone();
        let result = async {
            let request = fork::ForkRequest::parse(&body)?;
            let authenticated = core.authenticate(&mkit_server::pipeline::RequestMeta {
                procedure: mkit_server::Procedure::Fork,
                header: &|name| {
                    headers
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned)
                },
                header_values: None,
                unary_body: Some(&body),
                transport_principal: None,
            })?;
            core.fork_repo(&authenticated, request).await
        }
        .await;
        match result {
            Ok(result) => axum::Json(serde_json::json!({ "tip":to_hex(&result.tip), "source_sequence":result.source_sequence, "pack_count":result.pack_count, "pack_bytes":result.pack_bytes, "object_count":result.object_count, "membership_generation":result.membership_generation })).into_response(),
            Err(error) => (http::StatusCode::from_u16(error.http_status().unwrap_or_else(|| match error.code() { mkit_server::Code::NotFound => 404, mkit_server::Code::PermissionDenied => 403, mkit_server::Code::InvalidArgument => 400, mkit_server::Code::FailedPrecondition => 400, mkit_server::Code::Unavailable => 503, _ => 500 })).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR), axum::Json(serde_json::json!({"code": error.code().as_str(), "message": error.public_message()}))).into_response(),
        }
    }
}

fn result_view(result: &ForkResult) -> ForkResultView {
    ForkResultView {
        source_repository: result.source.clone(),
        source_head: result.source_ref.clone(),
        tip: to_hex(&result.tip),
        source_sequence: result.source_sequence,
        packmap: to_hex(&result.packmap),
        pack_count: result.pack_count,
        pack_bytes: result.pack_bytes,
        object_count: result.object_count,
        pack_set_digest: to_hex(&result.pack_set),
        membership_generation: result.membership_generation,
    }
}

pub(super) fn preparation(job: &ForkJobV1) -> bool {
    job.accepted.is_none() && job.failure.is_none()
}

#[allow(clippy::type_complexity)] // Fixture bytes and the three bound content identities.
fn fixture_contents(message: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Hash, Hash, Hash), String> {
    let key = KeyPair::from_seed([0x73; 32]);
    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let tree_id = tree.id().map_err(|e| e.to_string())?;
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(key.public.0),
        key.public.0,
        message.to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).map_err(|e| e.to_string())?.0;
    let commit = Object::Commit(commit);
    let tip = commit.id().map_err(|e| e.to_string())?;
    let mut writer = PackWriter::new_raw_only();
    for object in [&tree, &commit] {
        writer
            .push_raw(
                object.id().map_err(|e| e.to_string())?,
                &serialize(object).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
    }
    let bytes = writer.finish().map_err(|e| e.to_string())?;
    let pack = hash(&bytes);
    let map_bytes =
        mkit_core::transfer::encode_packlist(None, &[pack]).map_err(|e| e.to_string())?;
    let packmap = hash(&map_bytes);
    Ok((bytes, map_bytes, tip, pack, packmap))
}
