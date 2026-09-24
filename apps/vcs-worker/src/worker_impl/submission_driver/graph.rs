// SPDX-License-Identifier: MIT OR Apache-2.0
//! Resumable staged graph, origin, exact-set audit, and selected-fit phases.

use super::*;

impl RefStore {
    pub(super) async fn submission_seal_step(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
        deadline: i64,
    ) -> Result<Reply> {
        let bytes = self
            .submission_read_carrier(original, proof, deadline)
            .await?;
        let lifetime = self
            .submission_lifetime(&original.operation_id)?
            .ok_or_else(corrupt)?;
        let checked = match CheckedMkwu::open(
            &bytes,
            lifetime.update_len,
            from_hex(&lifetime.update_digest).map_err(|_| corrupt())?,
            from_hex(&lifetime.expected_base).map_err(|_| corrupt())?,
            portable(),
            staged(),
        ) {
            Ok(v) => v,
            Err(e) => {
                return self.refuse_staged_error(
                    identity,
                    proof,
                    original,
                    e,
                    "unsupported_profile",
                );
            }
        };
        let pack_key = hex::encode(checked.header().pack_hash());
        let pack_offset = checked.header().pack_offset();
        let pack_len = checked.header().pack_len();
        if pack_offset > 128 * 1024 || pack_len > MAX_PACK as usize {
            return self.submission_refuse(identity, proof, original, "resource_exhausted");
        }
        let mut inspection = default_staged_inspection_limits();
        inspection.max_object_bytes = inspection.max_object_bytes.min(portable().max_object_bytes);
        inspection.max_tree_bytes = inspection
            .max_tree_bytes
            .min(portable().max_tree_object_bytes);
        inspection.max_tree_entries = inspection.max_tree_entries.min(portable().max_tree_entries);
        inspection.max_manifest_chunks = inspection.max_manifest_chunks.min(32_768);
        if let Err(e) =
            StagedValidationContext::new(checked.header().clone(), portable(), staged(), inspection)
        {
            return self.refuse_staged_error(identity, proof, original, e, "unsupported_profile");
        }
        let begin =
            submission_wire::decode_begin(original.begin_body.as_bytes()).map_err(|_| corrupt())?;
        let changed: Vec<Vec<Vec<u8>>> = checked
            .header()
            .changes()
            .iter()
            .map(|change| change.path().clone())
            .collect();
        if !self.submission_changes_allowed(identity, proof, &begin, &changed)? {
            return self.submission_refuse(identity, proof, original, "invalid_candidate");
        }
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &bytes[..pack_offset],
        );
        let usage = checked.initial_usage();
        deadline_ok(deadline, proof)?;
        let owned = self.clone();
        let identity = identity.clone();
        let proof = proof.clone();
        let original = original.clone();
        self.ledger.transaction(move || {
            deadline_ok(deadline, &proof)?;
            let (mut lifetime, mut job) =
                owned.submission_attempt_current(&identity, &proof, &original)?;
            if job.phase != "seal" || !job.sealed_header.is_empty() || !job.pack_key.is_empty() {
                return Err(corrupt());
            }
            job.sealed_header = header;
            job.pack_key = pack_key;
            job.pack_offset = pack_offset as u64;
            job.pack_len = pack_len as u64;
            job.usage = usage.into();
            job.phase = "inventory".into();
            job.next_revision()?;
            job.idle_deadline = now().checked_add(ACTIVE_IDLE_MS).ok_or_else(corrupt)?;
            owned.submission_set_pin_expiry(&job.operation_id, job.idle_deadline, Some(now()))?;
            job.finish_attempt();
            lifetime.revision = job.revision.clone();
            owned.submission_save_job(&job, &lifetime.exact_ref)?;
            owned.submission_save_lifetime(&lifetime)?;
            let reply = Reply::json(&status(&lifetime, Some(&job)))?;
            owned.ledger.finish(&proof, &reply)?;
            Ok(reply)
        })
    }

    pub(super) async fn submission_inventory_step(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
        deadline: i64,
    ) -> Result<Reply> {
        let bytes = self
            .submission_read_carrier(original, proof, deadline)
            .await?;
        let lifetime = self
            .submission_lifetime(&original.operation_id)?
            .ok_or_else(corrupt)?;
        let checked = match CheckedMkwu::open(
            &bytes,
            lifetime.update_len,
            from_hex(&lifetime.update_digest).map_err(|_| corrupt())?,
            from_hex(&lifetime.expected_base).map_err(|_| corrupt())?,
            portable(),
            staged(),
        ) {
            Ok(v) => v,
            Err(e) => {
                return self.refuse_staged_error(identity, proof, original, e, "invalid_candidate");
            }
        };
        if hex::encode(checked.header().pack_hash()) != original.pack_key
            || checked.header().pack_offset() as u64 != original.pack_offset
            || checked.header().pack_len() as u64 != original.pack_len
        {
            return Err(corrupt());
        }
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &bytes[..original.pack_offset as usize],
        );
        if header != original.sealed_header {
            return Err(corrupt());
        }
        let mut inspection = default_staged_inspection_limits();
        inspection.max_object_bytes = inspection.max_object_bytes.min(portable().max_object_bytes);
        inspection.max_tree_bytes = inspection
            .max_tree_bytes
            .min(portable().max_tree_object_bytes);
        inspection.max_tree_entries = inspection.max_tree_entries.min(portable().max_tree_entries);
        inspection.max_manifest_chunks = inspection.max_manifest_chunks.min(32_768);
        let context = match StagedValidationContext::new(
            checked.header().clone(),
            portable(),
            staged(),
            inspection,
        ) {
            Ok(v) => v,
            Err(e) => {
                return self.refuse_staged_error(
                    identity,
                    proof,
                    original,
                    e,
                    "unsupported_profile",
                );
            }
        };
        let mut cursor = StagedInventoryCursor {
            next_ordinal: original.inventory_cursor,
            previous_id: if original.inventory_previous_id.is_empty() {
                None
            } else {
                Some(from_hex(&original.inventory_previous_id).map_err(|_| corrupt())?)
            },
            count: original.inventory_cursor,
            canonical_bytes: original.inventory_bytes,
        };
        let mut usage: StagedUpdateUsageV1 = original.usage.clone().into();
        let mut records = Vec::new();
        for entry in checked
            .pack()
            .entries()
            .skip(original.inventory_cursor as usize)
            .take(64)
        {
            let fact = match inspect_staged_inventory_object(entry.payload(), &context) {
                Ok(v) => v,
                Err(e) => {
                    return self.refuse_staged_error(
                        identity,
                        proof,
                        original,
                        e,
                        "invalid_candidate",
                    );
                }
            };
            let step = match advance_staged_inventory(
                &cursor,
                u64::from(entry.ordinal()),
                &fact,
                &context,
            ) {
                Ok(v) => v,
                Err(e) => {
                    return self.refuse_staged_error(
                        identity,
                        proof,
                        original,
                        e,
                        "invalid_candidate",
                    );
                }
            };
            usage = match apply_inventory_accounting(usage, &step, &context) {
                Ok(v) => v,
                Err(e) => {
                    return self.refuse_staged_error(
                        identity,
                        proof,
                        original,
                        e,
                        "invalid_candidate",
                    );
                }
            };
            cursor = step.cursor();
            let range = entry.payload_range();
            records.push(InventoryRecord {
                ordinal: u64::from(entry.ordinal()),
                id: hex::encode(step.id()),
                canonical_len: step.canonical_len(),
                payload_offset: original
                    .pack_offset
                    .checked_add(range.start as u64)
                    .ok_or_else(corrupt)?,
                payload_len: u64::try_from(range.len()).map_err(|_| corrupt())?,
            });
        }
        if records.is_empty() && cursor.count != u64::from(checked.pack().entry_count()) {
            return Err(corrupt());
        }
        let finished = cursor.count == u64::from(checked.pack().entry_count());
        let root = if finished {
            Some(
                start_snapshot_walk(
                    from_hex(&lifetime.expected_base).map_err(|_| corrupt())?,
                    SnapshotRole::BaseRoot,
                )
                .map_err(|_| corrupt())?,
            )
        } else {
            None
        };
        deadline_ok(deadline, proof)?;
        let owned = self.clone();
        let identity = identity.clone();
        let proof = proof.clone();
        let original = original.clone();
        self.ledger.transaction(move || {
            deadline_ok(deadline,&proof)?;
            let (mut lifetime,mut job)=owned.submission_attempt_current(&identity,&proof,&original)?;
            if job.phase!="inventory" || job.inventory_cursor!=original.inventory_cursor
                || job.inventory_previous_id!=original.inventory_previous_id { return Err(corrupt()); }
            for record in &records {
                owned.state.storage().sql().exec(
                    "INSERT INTO host_submission_inventory(operation_id,ordinal,object_id,canonical_len,payload_offset,payload_len) VALUES(?,?,?,?,?,?)",
                    vec![job.operation_id.clone().into(),i64::try_from(record.ordinal).map_err(|_|corrupt())?.into(),record.id.clone().into(),i64::try_from(record.canonical_len).map_err(|_|corrupt())?.into(),i64::try_from(record.payload_offset).map_err(|_|corrupt())?.into(),i64::try_from(record.payload_len).map_err(|_|corrupt())?.into()],
                )?;
                owned.state.storage().sql().exec(
                    "INSERT INTO host_submission_supplied(operation_id,object_id,canonical_len,payload_offset,payload_len) VALUES(?,?,?,?,?)",
                    vec![job.operation_id.clone().into(),record.id.clone().into(),i64::try_from(record.canonical_len).map_err(|_|corrupt())?.into(),i64::try_from(record.payload_offset).map_err(|_|corrupt())?.into(),i64::try_from(record.payload_len).map_err(|_|corrupt())?.into()],
                )?;
            }
            job.inventory_cursor=cursor.count;
            job.inventory_bytes=cursor.canonical_bytes;
            job.inventory_previous_id=cursor.previous_id.map_or(String::new(),hex::encode);
            job.supplied_objects=cursor.count;
            job.usage=usage.into();
            if let Some(root)=root {
                let count=owned.snapshot_count(
                    "SELECT COUNT(*) AS n FROM host_submission_inventory WHERE operation_id=?",
                    vec![job.operation_id.clone().into()],
                )?;
                if count!=job.inventory_cursor { return Err(corrupt()); }
                let encoded=serde_json::to_string(&Frontier::from_record(&root)).map_err(|_|corrupt())?;
                job.frontier_rows=1;
                job.frontier_bytes=encoded.len() as u64;
                job.frontier_next_seq=1;
                job.phase="base_walk".into();
                owned.state.storage().sql().exec(
                    "INSERT INTO host_submission_frontier(operation_id,phase,seq,document) VALUES(?,'base_walk',0,?)",
                    vec![job.operation_id.clone().into(),encoded.into()],
                )?;
            }
            job.next_revision()?;
            job.idle_deadline=now().checked_add(ACTIVE_IDLE_MS).ok_or_else(corrupt)?;
            owned.submission_set_pin_expiry(&job.operation_id,job.idle_deadline,Some(now()))?;
            job.finish_attempt();
            lifetime.revision=job.revision.clone();
            owned.submission_save_job(&job,&lifetime.exact_ref)?;
            owned.submission_save_lifetime(&lifetime)?;
            let reply=Reply::json(&status(&lifetime,Some(&job)))?;
            owned.ledger.finish(&proof,&reply)?;
            Ok(reply)
        })
    }

    pub(super) async fn submission_walk_step(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
        deadline: i64,
        candidate: bool,
    ) -> Result<Reply> {
        let phase = if candidate {
            "candidate_walk"
        } else {
            "base_walk"
        };
        let lifetime = self
            .submission_lifetime(&original.operation_id)?
            .ok_or_else(corrupt)?;
        let rows:Vec<Queued>=self.state.storage().sql().exec(
            "SELECT seq,document FROM host_submission_frontier WHERE operation_id=? AND phase=? ORDER BY seq LIMIT 1",
            vec![original.operation_id.clone().into(),phase.into()],
        )?.to_array()?;
        if rows.len() != 1 {
            return Err(corrupt());
        }
        let queued = &rows[0];
        let frontier: Frontier = serde_json::from_str(&queued.document).map_err(|_| corrupt())?;
        let record = frontier.record().map_err(|_| corrupt())?;
        let Some(parent_locator) =
            self.submission_source(&lifetime, original, &hex::encode(record.id()), candidate)?
        else {
            return self.submission_refuse(identity, proof, original, "invalid_candidate");
        };
        let parent_bytes = read_source!(
            self,
            identity,
            proof,
            original,
            &parent_locator,
            deadline,
            false
        );
        let limits = ObjectInspectionLimits {
            max_object_bytes: 2 * 1024 * 1024,
            max_tree_bytes: 2 * 1024 * 1024,
            max_tree_entries: 65_536,
            max_manifest_chunks: 32_768,
        };
        let parent =
            match inspect_snapshot_object(record.id(), &parent_bytes, record.role(), limits) {
                Ok(v) => v,
                Err(e) => {
                    return self.refuse_inspect_error(
                        identity,
                        proof,
                        original,
                        e,
                        matches!(&parent_locator, SourceLocator::Supplied { .. }),
                    );
                }
            };
        drop(parent_bytes);
        let mut chunks = Vec::new();
        let mut width = 64usize;
        if let SnapshotWalkRecord::ManifestPage { next_index, .. } = record {
            let (_, _, total) = parent.manifest().ok_or_else(corrupt)?;
            let start = next_index as usize;
            if start >= total {
                return Err(corrupt());
            }
            let ids = match next_manifest_ids(
                &record,
                &parent,
                NonZeroUsize::new((total - start).min(64)).ok_or_else(corrupt)?,
            ) {
                Ok(v) => v,
                Err(e) => return self.refuse_walk_error(identity, proof, original, e, candidate),
            };
            let mut planned = parent_locator.len();
            width = 0;
            for id in ids {
                let Some(locator) =
                    self.submission_source(&lifetime, original, &hex::encode(id), candidate)?
                else {
                    return self.submission_refuse(identity, proof, original, "invalid_candidate");
                };
                let Some(next) = planned.checked_add(locator.len()) else {
                    break;
                };
                if next > MAX_STEP_IO {
                    break;
                }
                let chunk_bytes =
                    read_source!(self, identity, proof, original, &locator, deadline, false);
                chunks.push(
                    match inspect_snapshot_object(*id, &chunk_bytes, SnapshotRole::Chunk, limits) {
                        Ok(v) => v,
                        Err(e) => {
                            return self.refuse_inspect_error(
                                identity,
                                proof,
                                original,
                                e,
                                matches!(&locator, SourceLocator::Supplied { .. }),
                            );
                        }
                    },
                );
                planned = next;
                width += 1;
            }
            if width == 0 {
                return self.submission_refuse(identity, proof, original, "resource_exhausted");
            }
        }
        let walk_limits = if candidate {
            staged().candidate_walk
        } else {
            staged().base_walk
        };
        let step = match advance_snapshot_walk(
            &record,
            &parent,
            &chunks,
            NonZeroUsize::new(width).ok_or_else(corrupt)?,
            &walk_limits,
        ) {
            Ok(v) => v,
            Err(e) => return self.refuse_walk_error(identity, proof, original, e, candidate),
        };
        let pre_newly = self.submission_new_seen(original, phase, step.observations())?;
        let prior: SnapshotWalkUsage = if candidate {
            original.usage.candidate_walk.clone().into()
        } else {
            original.usage.base_walk.clone().into()
        };
        if let Err(e) = apply_walk_accounting(prior, &step, &pre_newly, walk_limits) {
            return self.refuse_walk_error(identity, proof, original, e, candidate);
        }
        deadline_ok(deadline, proof)?;
        let owned = self.clone();
        let (identity_ref, proof_ref, original_ref) = (identity, proof, original);
        let identity = identity.clone();
        let proof = proof.clone();
        let original = original.clone();
        let document = queued.document.clone();
        let seq = queued.seq;
        let refusal = std::rc::Rc::new(std::cell::Cell::new(false));
        let marked = refusal.clone();
        let result=self.ledger.transaction(move || {
            deadline_ok(deadline,&proof)?;
            let (mut lifetime,mut job)=owned.submission_attempt_current(&identity,&proof,&original)?;
            if job.phase!=phase { return Err(corrupt()); }
            let current_rows:Vec<Queued>=owned.state.storage().sql().exec(
                "SELECT seq,document FROM host_submission_frontier WHERE operation_id=? AND phase=? AND seq=?",
                vec![job.operation_id.clone().into(),phase.into(),seq.into()],
            )?.to_array()?;
            if current_rows.len()!=1 || current_rows[0].document!=document { return Err(corrupt()); }
            let newly_seen=owned.submission_new_seen(&job,phase,step.observations())?;
            if newly_seen!=pre_newly {return Err(corrupt());}
            let prior:SnapshotWalkUsage=if candidate {job.usage.candidate_walk.clone().into()}else{job.usage.base_walk.clone().into()};
            let walk_limits=if candidate {staged().candidate_walk}else{staged().base_walk};
            let next=apply_walk_accounting(prior,&step,&newly_seen,walk_limits).map_err(|_|corrupt())?;
            let mut documents=Vec::new();
            let mut successor_bytes=0u64;
            for successor in step.successors() {
                let encoded=serde_json::to_string(&Frontier::from_record(successor)).map_err(|_|corrupt())?;
                if encoded.len()>8192 { return Err(corrupt()); }
                successor_bytes=successor_bytes.checked_add(encoded.len() as u64).ok_or_else(corrupt)?;
                documents.push(encoded);
            }
            let rows=job.frontier_rows.checked_sub(1).and_then(|n|n.checked_add(documents.len() as u64)).ok_or_else(corrupt)?;
            let bytes=job.frontier_bytes.checked_sub(document.len() as u64).and_then(|n|n.checked_add(successor_bytes)).ok_or_else(corrupt)?;
            if rows>100_000 || bytes>32*1024*1024 {marked.set(true);return Err(corrupt());}
            for id in &newly_seen {
                let len=step.observations().iter().find(|v|v.id()==*id).ok_or_else(corrupt)?.canonical_len();
                owned.state.storage().sql().exec(
                    "INSERT INTO host_submission_seen(operation_id,phase,object_id,canonical_len) VALUES(?,?,?,?)",
                    vec![job.operation_id.clone().into(),phase.into(),hex::encode(id).into(),i64::try_from(len).map_err(|_|corrupt())?.into()],
                )?;
            }
            for encoded in documents {
                let next_seq=i64::try_from(job.frontier_next_seq).map_err(|_|corrupt())?;
                owned.state.storage().sql().exec(
                    "INSERT INTO host_submission_frontier(operation_id,phase,seq,document) VALUES(?,?,?,?)",
                    vec![job.operation_id.clone().into(),phase.into(),next_seq.into(),encoded.into()],
                )?;
                job.frontier_next_seq=job.frontier_next_seq.checked_add(1).ok_or_else(corrupt)?;
            }
            owned.state.storage().sql().exec(
                "DELETE FROM host_submission_frontier WHERE operation_id=? AND phase=? AND seq=?",
                vec![job.operation_id.clone().into(),phase.into(),seq.into()],
            )?;
            job.frontier_rows=rows;
            job.frontier_bytes=bytes;
            if candidate {job.usage.candidate_walk=next.into();job.candidate_objects=next.objects;}
            else {job.usage.base_walk=next.into();job.base_objects=next.objects;}
            if rows==0 {
                job.phase=if candidate {"audit"}else{"diff_init"}.into();
                if candidate {job.audit_phase="base".into();}
            }
            job.next_revision()?;
            job.idle_deadline=now().checked_add(ACTIVE_IDLE_MS).ok_or_else(corrupt)?;
            owned.submission_set_pin_expiry(&job.operation_id,job.idle_deadline,Some(now()))?;
            job.finish_attempt();
            lifetime.revision=job.revision.clone();
            owned.submission_save_job(&job,&lifetime.exact_ref)?;
            owned.submission_save_lifetime(&lifetime)?;
            let reply=Reply::json(&status(&lifetime,Some(&job)))?;
            owned.ledger.finish(&proof,&reply)?;
            Ok(reply)
        });
        if refusal.get() {
            return self.submission_refuse(
                identity_ref,
                proof_ref,
                original_ref,
                "resource_exhausted",
            );
        }
        result
    }

    pub(super) async fn submission_diff_init(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
        deadline: i64,
    ) -> Result<Reply> {
        let lifetime = self
            .submission_lifetime(&original.operation_id)?
            .ok_or_else(corrupt)?;
        let context = self.submission_context(original)?;
        let base_id = context.header().base_id();
        let candidate_id = context.header().candidate_id();
        if hex::encode(base_id) != lifetime.expected_base {
            return Err(corrupt());
        }
        let base_locator = self
            .submission_source(&lifetime, original, &hex::encode(base_id), false)?
            .ok_or_else(corrupt)?;
        let Some(candidate_locator) =
            self.submission_source(&lifetime, original, &hex::encode(candidate_id), true)?
        else {
            return self.submission_refuse(identity, proof, original, "invalid_candidate");
        };
        if !matches!(candidate_locator, SourceLocator::Supplied { .. }) {
            return self.submission_refuse(identity, proof, original, "invalid_candidate");
        }
        let base_bytes = read_source!(
            self,
            identity,
            proof,
            original,
            &base_locator,
            deadline,
            false
        );
        let candidate_bytes = read_source!(
            self,
            identity,
            proof,
            original,
            &candidate_locator,
            deadline,
            false
        );
        let base = match inspect_snapshot_object(
            base_id,
            &base_bytes,
            SnapshotRole::BaseRoot,
            context.inspection(),
        ) {
            Ok(v) => v,
            Err(e) => return self.refuse_inspect_error(identity, proof, original, e, false),
        };
        let candidate = match inspect_staged_candidate(&candidate_bytes, &context) {
            Ok(v) => v,
            Err(e) => {
                return self.refuse_staged_error(identity, proof, original, e, "invalid_candidate");
            }
        };
        let signer = candidate.object().root().ok_or_else(corrupt)?.1;
        if hex::encode(signer) != lifetime.subject {
            return self.submission_refuse(identity, proof, original, "invalid_candidate");
        }
        let Ok(Object::Commit(commit)) = deserialize(&candidate_bytes) else {
            return self.submission_refuse(identity, proof, original, "invalid_candidate");
        };
        if commit.author != ObjectIdentity::ed25519(signer) || commit.signer != signer {
            return self.submission_refuse(identity, proof, original, "invalid_candidate");
        }
        let step = match start_changed_pairs(&base, &candidate, &context) {
            Ok(v) => v,
            Err(e) => {
                return self.refuse_staged_error(identity, proof, original, e, "invalid_candidate");
            }
        };
        let Some(pre_newly) = self.submission_new_required(original, step.observations())? else {
            return self.submission_refuse(identity, proof, original, "invalid_candidate");
        };
        if let Err(e) =
            apply_changed_accounting(original.usage.clone().into(), &step, &pre_newly, &context)
        {
            return self.refuse_staged_error(identity, proof, original, e, "invalid_candidate");
        }
        deadline_ok(deadline, proof)?;
        let owned = self.clone();
        let (identity_ref, proof_ref, original_ref) = (identity, proof, original);
        let identity = identity.clone();
        let proof = proof.clone();
        let original = original.clone();
        let refusal = std::rc::Rc::new(std::cell::Cell::new(false));
        let marked = refusal.clone();
        let result=self.ledger.transaction(move || {
            deadline_ok(deadline,&proof)?;
            let (mut lifetime,mut job)=owned.submission_attempt_current(&identity,&proof,&original)?;
            if job.phase!="diff_init" || job.frontier_rows!=0 {return Err(corrupt());}
            let newly=owned.submission_new_required(&job,step.observations())?.ok_or_else(corrupt)?;
            if newly!=pre_newly {return Err(corrupt());}
            let usage:StagedUpdateUsageV1=job.usage.clone().into();
            let next=apply_changed_accounting(usage,&step,&newly,&context).map_err(|_|corrupt())?;
            if step.successors().is_empty() || !step.files().is_empty() || !step.matched_indices().is_empty() {return Err(corrupt());}
            let mut documents=Vec::new();
            let mut bytes=0u64;
            for successor in step.successors() {
                let encoded=serde_json::to_string(&DiffFrontier::from_pair(successor)).map_err(|_|corrupt())?;
                if encoded.len()>8192 {return Err(corrupt());}
                bytes=bytes.checked_add(encoded.len() as u64).ok_or_else(corrupt)?;
                documents.push(encoded);
            }
            if documents.len()>100_000 || bytes>32*1024*1024 {marked.set(true);return Err(corrupt());}
            owned.submission_insert_required(&job,step.observations(),&newly)?;
            for encoded in documents {
                let seq=i64::try_from(job.frontier_next_seq).map_err(|_|corrupt())?;
                owned.state.storage().sql().exec(
                    "INSERT INTO host_submission_frontier(operation_id,phase,seq,document) VALUES(?,'diff_pairs',?,?)",
                    vec![job.operation_id.clone().into(),seq.into(),encoded.into()],
                )?;
                job.frontier_next_seq=job.frontier_next_seq.checked_add(1).ok_or_else(corrupt)?;
            }
            job.frontier_rows=step.successors().len() as u64;
            job.frontier_bytes=bytes;
            job.usage=next.into();
            job.required_objects=next.required_unique_ids;
            job.phase="diff_pairs".into();
            job.next_revision()?;
            job.idle_deadline=now().checked_add(ACTIVE_IDLE_MS).ok_or_else(corrupt)?;
            owned.submission_set_pin_expiry(&job.operation_id,job.idle_deadline,Some(now()))?;
            job.finish_attempt();
            lifetime.revision=job.revision.clone();
            owned.submission_save_job(&job,&lifetime.exact_ref)?;
            owned.submission_save_lifetime(&lifetime)?;
            let reply=Reply::json(&status(&lifetime,Some(&job)))?;
            owned.ledger.finish(&proof,&reply)?;
            Ok(reply)
        });
        if refusal.get() {
            return self.submission_refuse(
                identity_ref,
                proof_ref,
                original_ref,
                "resource_exhausted",
            );
        }
        result
    }

    pub(super) async fn submission_diff_pair_step(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
        deadline: i64,
    ) -> Result<Reply> {
        let lifetime = self
            .submission_lifetime(&original.operation_id)?
            .ok_or_else(corrupt)?;
        let context = self.submission_context(original)?;
        let rows:Vec<Queued>=self.state.storage().sql().exec(
            "SELECT seq,document FROM host_submission_frontier WHERE operation_id=? AND phase='diff_pairs' ORDER BY seq LIMIT 1",
            vec![original.operation_id.clone().into()],
        )?.to_array()?;
        if rows.len() != 1 {
            return Err(corrupt());
        }
        let queued = &rows[0];
        let stored: DiffFrontier = serde_json::from_str(&queued.document).map_err(|_| corrupt())?;
        let record = stored.pair().map_err(|_| corrupt())?;
        let old_locator = self
            .submission_source(&lifetime, original, &hex::encode(record.old_id()), false)?
            .ok_or_else(corrupt)?;
        let Some(new_locator) =
            self.submission_source(&lifetime, original, &hex::encode(record.new_id()), true)?
        else {
            return self.submission_refuse(identity, proof, original, "invalid_candidate");
        };
        let old_bytes = read_source!(
            self,
            identity,
            proof,
            original,
            &old_locator,
            deadline,
            false
        );
        let new_bytes = read_source!(
            self,
            identity,
            proof,
            original,
            &new_locator,
            deadline,
            false
        );
        let old = match inspect_snapshot_object(
            record.old_id(),
            &old_bytes,
            SnapshotRole::Tree,
            context.inspection(),
        ) {
            Ok(v) => v,
            Err(e) => return self.refuse_inspect_error(identity, proof, original, e, false),
        };
        let new = match inspect_snapshot_object(
            record.new_id(),
            &new_bytes,
            SnapshotRole::Tree,
            context.inspection(),
        ) {
            Ok(v) => v,
            Err(e) => return self.refuse_inspect_error(identity, proof, original, e, true),
        };
        let step = match advance_changed_pair(
            &record,
            &old,
            &new,
            &context,
            NonZeroUsize::new(64).ok_or_else(corrupt)?,
        ) {
            Ok(v) => v,
            Err(e) => {
                return self.refuse_staged_error(identity, proof, original, e, "invalid_candidate");
            }
        };
        let Some(pre_newly) = self.submission_new_required(original, step.observations())? else {
            return self.submission_refuse(identity, proof, original, "invalid_candidate");
        };
        if let Err(e) =
            apply_changed_accounting(original.usage.clone().into(), &step, &pre_newly, &context)
        {
            return self.refuse_staged_error(identity, proof, original, e, "invalid_candidate");
        }
        deadline_ok(deadline, proof)?;
        let owned = self.clone();
        let (identity_ref, proof_ref, original_ref) = (identity, proof, original);
        let identity = identity.clone();
        let proof = proof.clone();
        let original = original.clone();
        let document = queued.document.clone();
        let seq = queued.seq;
        let refusal = std::rc::Rc::new(std::cell::Cell::new(false));
        let marked = refusal.clone();
        let result=self.ledger.transaction(move || {
            deadline_ok(deadline,&proof)?;
            let (mut lifetime,mut job)=owned.submission_attempt_current(&identity,&proof,&original)?;
            if job.phase!="diff_pairs" {return Err(corrupt());}
            let prior:Vec<Queued>=owned.state.storage().sql().exec(
                "SELECT seq,document FROM host_submission_frontier WHERE operation_id=? AND phase='diff_pairs' AND seq=?",
                vec![job.operation_id.clone().into(),seq.into()],
            )?.to_array()?;
            if prior.len()!=1 || prior[0].document!=document {return Err(corrupt());}
            let newly=owned.submission_new_required(&job,step.observations())?.ok_or_else(corrupt)?;
            if newly!=pre_newly {return Err(corrupt());}
            let usage:StagedUpdateUsageV1=job.usage.clone().into();
            let next=apply_changed_accounting(usage,&step,&newly,&context).map_err(|_|corrupt())?;
            let mut documents=Vec::new();
            let mut successor_bytes=0u64;
            for value in step.successors() {
                let text=serde_json::to_string(&DiffFrontier::from_pair(value)).map_err(|_|corrupt())?;
                if text.len()>8192 {return Err(corrupt());}
                successor_bytes=successor_bytes.checked_add(text.len() as u64).ok_or_else(corrupt)?;
                documents.push(("diff_pairs",text));
            }
            for value in step.files() {
                let text=serde_json::to_string(&DiffFrontier::from_file(value)).map_err(|_|corrupt())?;
                if text.len()>8192 {return Err(corrupt());}
                successor_bytes=successor_bytes.checked_add(text.len() as u64).ok_or_else(corrupt)?;
                documents.push(("diff_files",text));
            }
            let rows=job.frontier_rows.checked_sub(1).and_then(|n|n.checked_add(documents.len() as u64)).ok_or_else(corrupt)?;
            let bytes=job.frontier_bytes.checked_sub(document.len() as u64).and_then(|n|n.checked_add(successor_bytes)).ok_or_else(corrupt)?;
            if rows>100_000 || bytes>32*1024*1024 {marked.set(true);return Err(corrupt());}
            owned.submission_insert_required(&job,step.observations(),&newly)?;
            for index in step.matched_indices() {
                if usize::try_from(*index).map_or(true,|v|v>=context.header().changes().len()) {return Err(corrupt());}
                owned.state.storage().sql().exec(
                    "INSERT INTO host_submission_matched(operation_id,change_index) VALUES(?,?)",
                    vec![job.operation_id.clone().into(),i64::from(*index).into()],
                )?;
                job.matched_changes=job.matched_changes.checked_add(1).ok_or_else(corrupt)?;
            }
            for (phase,text) in documents {
                let seq=i64::try_from(job.frontier_next_seq).map_err(|_|corrupt())?;
                owned.state.storage().sql().exec(
                    "INSERT INTO host_submission_frontier(operation_id,phase,seq,document) VALUES(?,?,?,?)",
                    vec![job.operation_id.clone().into(),phase.into(),seq.into(),text.into()],
                )?;
                job.frontier_next_seq=job.frontier_next_seq.checked_add(1).ok_or_else(corrupt)?;
            }
            owned.state.storage().sql().exec(
                "DELETE FROM host_submission_frontier WHERE operation_id=? AND phase='diff_pairs' AND seq=?",
                vec![job.operation_id.clone().into(),seq.into()],
            )?;
            job.frontier_rows=rows;
            job.frontier_bytes=bytes;
            job.usage=next.into();
            job.required_objects=next.required_unique_ids;
            let pairs=owned.snapshot_exists(
                "SELECT 1 AS found FROM host_submission_frontier WHERE operation_id=? AND phase='diff_pairs' LIMIT 1",
                vec![job.operation_id.clone().into()],
            )?;
            if !pairs {job.phase="diff_files".into();}
            job.next_revision()?;
            job.idle_deadline=now().checked_add(ACTIVE_IDLE_MS).ok_or_else(corrupt)?;
            owned.submission_set_pin_expiry(&job.operation_id,job.idle_deadline,Some(now()))?;
            job.finish_attempt();
            lifetime.revision=job.revision.clone();
            owned.submission_save_job(&job,&lifetime.exact_ref)?;
            owned.submission_save_lifetime(&lifetime)?;
            let reply=Reply::json(&status(&lifetime,Some(&job)))?;
            owned.ledger.finish(&proof,&reply)?;
            Ok(reply)
        });
        if refusal.get() {
            return self.submission_refuse(
                identity_ref,
                proof_ref,
                original_ref,
                "resource_exhausted",
            );
        }
        result
    }

    pub(super) async fn submission_diff_file_step(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
        deadline: i64,
    ) -> Result<Reply> {
        let lifetime = self
            .submission_lifetime(&original.operation_id)?
            .ok_or_else(corrupt)?;
        let context = self.submission_context(original)?;
        let rows:Vec<Queued>=self.state.storage().sql().exec(
            "SELECT seq,document FROM host_submission_frontier WHERE operation_id=? AND phase='diff_files' ORDER BY seq LIMIT 1",
            vec![original.operation_id.clone().into()],
        )?.to_array()?;
        if rows.len() != 1 {
            return Err(corrupt());
        }
        let queued = &rows[0];
        let stored: DiffFrontier = serde_json::from_str(&queued.document).map_err(|_| corrupt())?;
        let record = stored.file().map_err(|_| corrupt())?;
        let Some(file_locator) = self.submission_source(
            &lifetime,
            original,
            &hex::encode(record.expected_file_id()),
            true,
        )?
        else {
            return self.submission_refuse(identity, proof, original, "invalid_candidate");
        };
        if !matches!(file_locator, SourceLocator::Supplied { .. }) {
            return self.submission_refuse(identity, proof, original, "invalid_candidate");
        }
        let file_bytes = read_source!(
            self,
            identity,
            proof,
            original,
            &file_locator,
            deadline,
            false
        );
        let file = match inspect_snapshot_object(
            record.expected_file_id(),
            &file_bytes,
            SnapshotRole::File,
            context.inspection(),
        ) {
            Ok(v) => v,
            Err(e) => return self.refuse_inspect_error(identity, proof, original, e, true),
        };
        let mut chunks = Vec::new();
        let mut width = 64usize;
        let usage: StagedUpdateUsageV1 = original.usage.clone().into();
        if let RequiredFileRecord::ManifestPage { next_index, .. } = record {
            let (_, _, total) = file.manifest().ok_or_else(corrupt)?;
            let start = next_index as usize;
            if start >= total {
                return self.submission_refuse(identity, proof, original, "invalid_candidate");
            }
            let ids = match next_required_chunk_ids(
                &record,
                &file,
                &usage,
                &context,
                NonZeroUsize::new((total - start).min(64)).ok_or_else(corrupt)?,
            ) {
                Ok(v) => v,
                Err(e) => {
                    return self.refuse_staged_error(
                        identity,
                        proof,
                        original,
                        e,
                        "invalid_candidate",
                    );
                }
            };
            let mut planned = file_locator.len();
            width = 0;
            for id in ids {
                let Some(locator) =
                    self.submission_source(&lifetime, original, &hex::encode(id), true)?
                else {
                    return self.submission_refuse(identity, proof, original, "invalid_candidate");
                };
                if !matches!(locator, SourceLocator::Supplied { .. }) {
                    return self.submission_refuse(identity, proof, original, "invalid_candidate");
                }
                let Some(next) = planned.checked_add(locator.len()) else {
                    break;
                };
                if next > MAX_STEP_IO {
                    break;
                }
                let bytes =
                    read_source!(self, identity, proof, original, &locator, deadline, false);
                chunks.push(
                    match inspect_snapshot_object(
                        *id,
                        &bytes,
                        SnapshotRole::Chunk,
                        context.inspection(),
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            return self.refuse_inspect_error(identity, proof, original, e, true);
                        }
                    },
                );
                planned = next;
                width += 1;
            }
            if width == 0 {
                return self.submission_refuse(identity, proof, original, "resource_exhausted");
            }
        }
        let step = match advance_required_file(
            &record,
            &file,
            &chunks,
            NonZeroUsize::new(width).ok_or_else(corrupt)?,
            &usage,
            &context,
        ) {
            Ok(v) => v,
            Err(e) => {
                return self.refuse_staged_error(identity, proof, original, e, "invalid_candidate");
            }
        };
        let Some(pre_newly) = self.submission_new_required(original, step.observations())? else {
            return self.submission_refuse(identity, proof, original, "invalid_candidate");
        };
        if let Err(e) =
            apply_required_accounting(original.usage.clone().into(), &step, &pre_newly, &context)
        {
            return self.refuse_staged_error(identity, proof, original, e, "invalid_candidate");
        }
        deadline_ok(deadline, proof)?;
        let owned = self.clone();
        let (identity_ref, proof_ref, original_ref) = (identity, proof, original);
        let identity = identity.clone();
        let proof = proof.clone();
        let original = original.clone();
        let document = queued.document.clone();
        let seq = queued.seq;
        let refusal = std::rc::Rc::new(std::cell::Cell::new(None));
        let marked = refusal.clone();
        let result=self.ledger.transaction(move || {
            deadline_ok(deadline,&proof)?;
            let (mut lifetime,mut job)=owned.submission_attempt_current(&identity,&proof,&original)?;
            if job.phase!="diff_files" {return Err(corrupt());}
            let prior:Vec<Queued>=owned.state.storage().sql().exec(
                "SELECT seq,document FROM host_submission_frontier WHERE operation_id=? AND phase='diff_files' AND seq=?",
                vec![job.operation_id.clone().into(),seq.into()],
            )?.to_array()?;
            if prior.len()!=1 || prior[0].document!=document {return Err(corrupt());}
            let newly=owned.submission_new_required(&job,step.observations())?.ok_or_else(corrupt)?;
            if newly!=pre_newly {return Err(corrupt());}
            let previous:StagedUpdateUsageV1=job.usage.clone().into();
            let next=apply_required_accounting(previous,&step,&newly,&context).map_err(|_|corrupt())?;
            let mut documents=Vec::new();
            let mut successor_bytes=0u64;
            for successor in step.successors() {
                let encoded=serde_json::to_string(&DiffFrontier::from_file(successor)).map_err(|_|corrupt())?;
                if encoded.len()>8192 {return Err(corrupt());}
                successor_bytes=successor_bytes.checked_add(encoded.len() as u64).ok_or_else(corrupt)?;
                documents.push(encoded);
            }
            let rows=job.frontier_rows.checked_sub(1).and_then(|n|n.checked_add(documents.len() as u64)).ok_or_else(corrupt)?;
            let bytes=job.frontier_bytes.checked_sub(document.len() as u64).and_then(|n|n.checked_add(successor_bytes)).ok_or_else(corrupt)?;
            if rows>100_000 || bytes>32*1024*1024 {marked.set(Some("resource_exhausted"));return Err(corrupt());}
            owned.submission_insert_required(&job,step.observations(),&newly)?;
            for encoded in documents {
                let seq=i64::try_from(job.frontier_next_seq).map_err(|_|corrupt())?;
                owned.state.storage().sql().exec(
                    "INSERT INTO host_submission_frontier(operation_id,phase,seq,document) VALUES(?,'diff_files',?,?)",
                    vec![job.operation_id.clone().into(),seq.into(),encoded.into()],
                )?;
                job.frontier_next_seq=job.frontier_next_seq.checked_add(1).ok_or_else(corrupt)?;
            }
            owned.state.storage().sql().exec(
                "DELETE FROM host_submission_frontier WHERE operation_id=? AND phase='diff_files' AND seq=?",
                vec![job.operation_id.clone().into(),seq.into()],
            )?;
            job.frontier_rows=rows;
            job.frontier_bytes=bytes;
            job.usage=next.into();
            job.required_objects=next.required_unique_ids;
            if rows==0 {
                let matched=owned.snapshot_count(
                    "SELECT COUNT(*) AS n FROM host_submission_matched WHERE operation_id=?",
                    vec![job.operation_id.clone().into()],
                )?;
                let required=owned.snapshot_count(
                    "SELECT COUNT(*) AS n FROM host_submission_required WHERE operation_id=?",
                    vec![job.operation_id.clone().into()],
                )?;
                let supplied=owned.snapshot_count(
                    "SELECT COUNT(*) AS n FROM host_submission_supplied WHERE operation_id=?",
                    vec![job.operation_id.clone().into()],
                )?;
                let missing=owned.snapshot_exists(
                    "SELECT 1 AS found FROM host_submission_required r WHERE r.operation_id=? AND NOT EXISTS(SELECT 1 FROM host_submission_supplied s WHERE s.operation_id=r.operation_id AND s.object_id=r.object_id AND s.canonical_len=r.canonical_len) LIMIT 1",
                    vec![job.operation_id.clone().into()],
                )?;
                let extra=owned.snapshot_exists(
                    "SELECT 1 AS found FROM host_submission_supplied s WHERE s.operation_id=? AND NOT EXISTS(SELECT 1 FROM host_submission_required r WHERE r.operation_id=s.operation_id AND r.object_id=s.object_id AND r.canonical_len=s.canonical_len) LIMIT 1",
                    vec![job.operation_id.clone().into()],
                )?;
                if matched!=context.header().changes().len() as u64 || matched!=job.matched_changes
                    || required!=job.required_objects || supplied!=job.supplied_objects || required!=supplied || missing || extra
                {marked.set(Some("invalid_candidate"));return Err(corrupt());}
                let root=start_snapshot_walk(context.header().candidate_id(),SnapshotRole::CandidateRoot).map_err(|_|corrupt())?;
                let encoded=serde_json::to_string(&Frontier::from_record(&root)).map_err(|_|corrupt())?;
                if encoded.len()>8192 {return Err(corrupt());}
                let next_seq=i64::try_from(job.frontier_next_seq).map_err(|_|corrupt())?;
                owned.state.storage().sql().exec(
                    "INSERT INTO host_submission_frontier(operation_id,phase,seq,document) VALUES(?,'candidate_walk',?,?)",
                    vec![job.operation_id.clone().into(),next_seq.into(),encoded.clone().into()],
                )?;
                job.frontier_next_seq=job.frontier_next_seq.checked_add(1).ok_or_else(corrupt)?;
                job.frontier_rows=1;
                job.frontier_bytes=encoded.len() as u64;
                job.phase="candidate_walk".into();
            }
            job.next_revision()?;
            job.idle_deadline=now().checked_add(ACTIVE_IDLE_MS).ok_or_else(corrupt)?;
            owned.submission_set_pin_expiry(&job.operation_id,job.idle_deadline,Some(now()))?;
            job.finish_attempt();
            lifetime.revision=job.revision.clone();
            owned.submission_save_job(&job,&lifetime.exact_ref)?;
            owned.submission_save_lifetime(&lifetime)?;
            let reply=Reply::json(&status(&lifetime,Some(&job)))?;
            owned.ledger.finish(&proof,&reply)?;
            Ok(reply)
        });
        if let Some(code) = refusal.get() {
            return self.submission_refuse(identity_ref, proof_ref, original_ref, code);
        }
        result
    }

    pub(super) fn submission_audit_step(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
        deadline: i64,
    ) -> Result<Reply> {
        #[derive(Deserialize)]
        struct Row {
            object_id: String,
            canonical_len: i64,
        }
        #[derive(Deserialize)]
        struct MatchRow {
            change_index: i64,
        }
        let refusal = (identity.clone(), proof.clone(), original.clone());
        let owned = self.clone();
        let identity = identity.clone();
        let proof = proof.clone();
        let original = original.clone();
        let outcome=self.ledger.transaction(move || -> Result<Option<Reply>> {
            deadline_ok(deadline,&proof)?;
            let (mut lifetime,mut job)=owned.submission_attempt_current(&identity,&proof,&original)?;
            if job.phase!="audit" || job.frontier_rows!=0 {return Err(corrupt());}
            let phase=job.audit_phase.clone();
            let (table,filter)=match phase.as_str() {
                "base"=>("host_submission_seen",Some("base_walk")),
                "candidate"=>("host_submission_seen",Some("candidate_walk")),
                "required"=>("host_submission_required",None),
                "supplied"=>("host_submission_supplied",None),
                "matched"=>("host_submission_matched",None),
                _=>return Err(corrupt()),
            };
            let mut last=job.audit_cursor.clone();
            let mut count=0u64;
            if phase=="matched" {
                let cursor=if last.is_empty(){-1}else{last.parse::<i64>().map_err(|_|corrupt())?};
                let rows:Vec<MatchRow>=owned.state.storage().sql().exec(
                    "SELECT change_index FROM host_submission_matched WHERE operation_id=? AND change_index>? ORDER BY change_index LIMIT 64",
                    vec![job.operation_id.clone().into(),cursor.into()],
                )?.to_array()?;
                let context=owned.submission_context(&job)?;
                for row in &rows {
                    if row.change_index<0 || row.change_index as usize>=context.header().changes().len() {return Err(corrupt());}
                    last=row.change_index.to_string();count+=1;
                }
            } else {
                let query=if filter.is_some() {
                    format!("SELECT object_id,canonical_len FROM {table} WHERE operation_id=? AND phase=? AND object_id>? ORDER BY object_id LIMIT 64")
                }else{
                    format!("SELECT object_id,canonical_len FROM {table} WHERE operation_id=? AND object_id>? ORDER BY object_id LIMIT 64")
                };
                let params=if let Some(filter)=filter {vec![job.operation_id.clone().into(),filter.into(),last.clone().into()]}
                    else{vec![job.operation_id.clone().into(),last.clone().into()]};
                let rows:Vec<Row>=owned.state.storage().sql().exec(&query,params)?.to_array()?;
                #[derive(Deserialize)] struct Pin{index_job_id:String}
                let pin:Vec<Pin>=owned.state.storage().sql().exec(
                    "SELECT index_job_id FROM host_submission_pins WHERE operation_id=?",
                    vec![job.operation_id.clone().into()],
                )?.to_array()?;
                if pin.len()!=1 {return Err(corrupt());}
                for row in &rows {
                    if !crate::snapshot_wire::id(&row.object_id) || row.canonical_len<=0 {return Err(corrupt());}
                    let base=owned.snapshot_exists(
                        "SELECT 1 AS found FROM host_snapshot_catalog WHERE job_id=? AND object_id=? AND canonical_len=? LIMIT 1",
                        vec![pin[0].index_job_id.clone().into(),row.object_id.clone().into(),row.canonical_len.into()],
                    )?;
                    let supplied=owned.snapshot_exists(
                        "SELECT 1 AS found FROM host_submission_supplied WHERE operation_id=? AND object_id=? AND canonical_len=? LIMIT 1",
                        vec![job.operation_id.clone().into(),row.object_id.clone().into(),row.canonical_len.into()],
                    )?;
                    let required=owned.snapshot_exists(
                        "SELECT 1 AS found FROM host_submission_required WHERE operation_id=? AND object_id=? AND canonical_len=? LIMIT 1",
                        vec![job.operation_id.clone().into(),row.object_id.clone().into(),row.canonical_len.into()],
                    )?;
                    let valid=match phase.as_str(){"base"=>base,"candidate"=>base||supplied,"required"=>supplied,"supplied"=>required,_=>false};
                    if !valid && ["required","supplied"].contains(&phase.as_str()) {return Ok(None);}
                    if !valid {return Err(corrupt());}
                    last=row.object_id.clone();count+=1;
                    job.audit_bytes=job.audit_bytes.checked_add(u64::try_from(row.canonical_len).map_err(|_|corrupt())?).ok_or_else(corrupt)?;
                }
            }
            job.audit_rows=job.audit_rows.checked_add(count).ok_or_else(corrupt)?;
            job.audit_cursor=last;
            if count<64 {
                let expected=match phase.as_str(){
                    "base"=>(job.usage.base_walk.objects,job.usage.base_walk.canonical_bytes),
                    "candidate"=>(job.usage.candidate_walk.objects,job.usage.candidate_walk.canonical_bytes),
                    "required"=>(job.usage.required_unique_ids,job.usage.required_canonical_bytes),
                    "supplied"=>(job.inventory_cursor,job.inventory_bytes),
                    "matched"=>(job.matched_changes,0),_=>return Err(corrupt()),
                };
                if (job.audit_rows,job.audit_bytes)!=expected {return Err(corrupt());}
                job.audit_phase=match phase.as_str(){"base"=>"candidate","candidate"=>"required","required"=>"supplied","supplied"=>"matched","matched"=>"done",_=>return Err(corrupt())}.into();
                job.audit_cursor.clear();job.audit_rows=0;job.audit_bytes=0;
                if job.audit_phase=="done" {job.phase="fit".into();}
            }
            job.next_revision()?;job.idle_deadline=now().checked_add(ACTIVE_IDLE_MS).ok_or_else(corrupt)?;
            owned.submission_set_pin_expiry(&job.operation_id,job.idle_deadline,Some(now()))?;
            job.finish_attempt();lifetime.revision=job.revision.clone();
            owned.submission_save_job(&job,&lifetime.exact_ref)?;owned.submission_save_lifetime(&lifetime)?;
            let reply=Reply::json(&status(&lifetime,Some(&job)))?;owned.ledger.finish(&proof,&reply)?;
            Ok(Some(reply))
        })?;
        match outcome {
            Some(reply) => Ok(reply),
            None => self.submission_refuse(&refusal.0, &refusal.1, &refusal.2, "invalid_candidate"),
        }
    }

    pub(super) async fn submission_fit_step(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
        deadline: i64,
    ) -> Result<Reply> {
        let lifetime = self
            .submission_lifetime(&original.operation_id)?
            .ok_or_else(corrupt)?;
        let context = self.submission_context(original)?;
        let request =
            submission_wire::decode_begin(original.begin_body.as_bytes()).map_err(|_| corrupt())?;
        let paths: Vec<Vec<Vec<u8>>> = request
            .selected_paths
            .iter()
            .map(|path| path.iter().map(|part| part.as_bytes().to_vec()).collect())
            .collect();
        let root = context.header().candidate_id();
        let profile = super::super::snapshot_disclosure::limits();
        let mut builder = match PartialSnapshotBuilder::new(root, &paths, &profile) {
            Ok(v) => v,
            Err(e) => return self.refuse_partial_error(identity, proof, original, e),
        };
        let mut witness_ids = BTreeSet::new();
        let mut witness_bytes = 0u64;
        let mut reads = 0u64;
        let mut bytes_reserved = 0u64;
        while let Some(next) = builder.next_request() {
            deadline_ok(deadline, proof)?;
            if !self
                .submission_attempt_current(identity, proof, original)
                .is_ok()
            {
                return Err(corrupt());
            }
            let requested_id = next.id();
            let requested_role = next.role();
            let requested_max = next.max_bytes();
            let id = hex::encode(requested_id);
            let member=self.snapshot_exists(
                "SELECT 1 AS found FROM host_submission_seen WHERE operation_id=? AND phase='candidate_walk' AND object_id=? LIMIT 1",
                vec![original.operation_id.clone().into(),id.clone().into()],
            )?;
            if !member {
                return self.submission_refuse(identity, proof, original, "invalid_candidate");
            }
            let Some(locator) = self.submission_source(&lifetime, original, &id, true)? else {
                return self.submission_refuse(identity, proof, original, "invalid_candidate");
            };
            let length = usize::try_from(locator.len()).map_err(|_| corrupt())?;
            let new_witness =
                requested_role == PartialObjectRole::Tree && !witness_ids.contains(&requested_id);
            if length > requested_max
                || (new_witness && locator.len() > 1024 * 1024 - witness_bytes)
                || bytes_reserved
                    .checked_add(locator.len())
                    .is_none_or(|v| v > 4 * 1024 * 1024)
                || reads >= 2048
            {
                return self.submission_refuse(identity, proof, original, "resource_exhausted");
            }
            bytes_reserved += locator.len();
            reads += 1;
            let bytes = read_source!(self, identity, proof, original, &locator, deadline, true);
            deadline_ok(deadline, proof)?;
            self.submission_attempt_current(identity, proof, original)?;
            builder = match builder.supply(bytes) {
                Ok(v) => v,
                Err(e) => return self.refuse_partial_error(identity, proof, original, e),
            };
            if new_witness {
                witness_bytes += locator.len();
                witness_ids.insert(requested_id);
            }
        }
        let bundle = match builder.finish().and_then(|bundle| bundle.encode(&profile)) {
            Ok(v) if v.len() <= 4 * 1024 * 1024 => v,
            Ok(_) => {
                return self.submission_refuse(identity, proof, original, "resource_exhausted");
            }
            Err(e) => return self.refuse_partial_error(identity, proof, original, e),
        };
        if verify_partial_snapshot(root, &paths, &bundle, &profile).is_err() {
            return Err(corrupt());
        }
        deadline_ok(deadline, proof)?;
        self.submission_promote(identity, proof, original, deadline)
    }

    fn submission_promote(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
        deadline: i64,
    ) -> Result<Reply> {
        let owned = self.clone();
        let identity = identity.clone();
        let proof = proof.clone();
        let original = original.clone();
        self.ledger.transaction(move || {
            deadline_ok(deadline, &proof)?;
            let (mut lifetime, mut job) =
                owned.submission_attempt_current(&identity, &proof, &original)?;
            if job.phase != "fit"
                || job.audit_phase != "done"
                || job.frontier_rows != 0
                || job.state != "validating"
                || job.pack_key.is_empty()
                || job.carrier_etag.is_empty()
            {
                return Err(corrupt());
            }
            if owned.snapshot_exists(
                "SELECT 1 AS found FROM host_submission_frontier WHERE operation_id=? LIMIT 1",
                vec![job.operation_id.clone().into()],
            )? {
                return Err(corrupt());
            }
            let context = owned.submission_context(&job)?;
            if job.audit_rows != 0
                || !job.audit_cursor.is_empty()
                || job.matched_changes != context.header().changes().len() as u64
                || job.base_objects == 0
                || job.candidate_objects == 0
            {
                return Err(corrupt());
            }
            let mut meta = owned.submission_meta(&identity)?.ok_or_else(corrupt)?;
            meta.active = meta.active.checked_sub(1).ok_or_else(corrupt)?;
            let timestamp = now();
            let deadline = timestamp.checked_add(BULKY_MS).ok_or_else(corrupt)?;
            job.state = "validated".into();
            job.phase = "terminal".into();
            job.bulky_deadline = deadline;
            job.next_revision()?;
            job.finish_attempt();
            lifetime.state = job.state.clone();
            lifetime.revision = job.revision.clone();
            lifetime.terminal_at = timestamp;
            lifetime.terminal_progress = Some(progress(&job));
            owned.submission_set_pin_expiry(&job.operation_id, deadline, Some(timestamp))?;
            owned.submission_save_meta(&meta)?;
            owned.submission_save_job(&job, &lifetime.exact_ref)?;
            owned.submission_save_lifetime(&lifetime)?;
            let reply = Reply::json(&status(&lifetime, Some(&job)))?;
            owned.ledger.finish(&proof, &reply)?;
            Ok(reply)
        })
    }
}
