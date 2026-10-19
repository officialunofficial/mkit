//! Decoded-leaf reuse preserves evidence, refusals, work and execution order.
use super::*;
fn execution_limits() -> VerifyLimits {
    VerifyLimits {
        resident_bytes: 256 << 20,
        page_bytes: 8192,
        resident_pages: 1,
        acquisition_bytes: 64 << 10,
        ..limits()
    }
}
fn leaf_pack(count: u64) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for ordinal in 0..count {
        let size = if ordinal % 127 >= 120 { 80 << 10 } else { 4096 };
        let mut data = vec![0x41; size];
        data[..8].copy_from_slice(&ordinal.to_le_bytes());
        let (id, bytes) = blob(&data);
        writer.push_raw(id, &bytes).unwrap();
    }
    writer.finish().unwrap()
}

fn graph_pack() -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    let mut entries = Vec::new();
    for ordinal in 0..1200_u32 {
        let mut data = vec![0x41; if ordinal % 127 >= 120 { 80 << 10 } else { 4096 }];
        data[..4].copy_from_slice(&ordinal.to_le_bytes());
        let (id, bytes) = blob(&data);
        writer.push_raw(id, &bytes).unwrap();
        entries.push(TreeEntry {
            name: format!("file-{ordinal:04}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: id,
        });
    }
    let (tree_id, bytes) = canonical(&Object::Tree(Tree { entries }));
    writer.push_raw(tree_id, &bytes).unwrap();
    let mut parents = Vec::new();
    for _ in 0..3 {
        let (id, bytes) = signed_commit(tree_id, parents);
        writer.push_raw(id, &bytes).unwrap();
        parents = vec![id];
    }
    writer.finish().unwrap()
}

#[derive(Debug, PartialEq, Eq)]
struct DeterministicRun {
    outcome: Result<String, Failure>,
    pages: Vec<(PageCommitment, Vec<u8>)>,
    fragments: BTreeMap<u64, Vec<u8>>,
    work: u64,
}

fn scheduled_leaves(pack: &[u8], width: u8, enabled: bool) -> DeterministicRun {
    let mut host = Host::new(pack);
    let mut machine =
        VerifyDriver::new(source(pack), REPOSITORY, profile(), execution_limits(), 17).unwrap();
    if !enabled {
        machine.objects.prevent_decoded_leaves();
    }
    if width != 0 {
        machine = machine
            .with_compute(ComputeConfig::new(width).with_min_job_bytes(0))
            .unwrap();
    }
    let mut jobs = Vec::new();
    let mut cache_active = false;
    let mut fetches = 0;
    let mut peak = 0;
    let outcome = loop {
        match machine.step() {
            Err(error) => break Err(error),
            Ok(Step::Complete(pack)) => {
                break Ok(format!(
                    "{:?}",
                    (
                        pack.counts(),
                        pack.object_set_root(),
                        pack.ordinals(),
                        pack.occurrences(),
                        pack.dependencies(),
                        pack.head_facts(),
                    )
                ));
            }
            Ok(Step::Request(Request::Compute { job })) => {
                jobs.push(machine.take_compute(job).unwrap());
                peak = peak.max(jobs.len());
            }
            Ok(Step::Request(request)) => {
                fetches += usize::from(matches!(request, Request::EvidencePage { .. }));
                host.serve(&mut machine, &request).unwrap();
            }
            Ok(Step::ProvisionalObject(fragment)) => host
                .fragments
                .entry(fragment.ordinal)
                .or_default()
                .extend_from_slice(fragment.bytes),
            Ok(Step::RetainEvidence(page)) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Ok(Step::ReleasePage(_)) => (),
            Ok(Step::Progress) => {
                let outputs = std::thread::scope(|scope| {
                    let workers: Vec<_> = jobs
                        .drain(..)
                        .map(|job: ComputeJob| scope.spawn(move || job.run()))
                        .collect();
                    workers
                        .into_iter()
                        .map(|worker| worker.join().unwrap())
                        .collect::<Vec<_>>()
                });
                for output in outputs.into_iter().rev() {
                    assert_eq!(
                        machine.supply_compute(output).unwrap(),
                        ComputeDisposition::Accepted
                    );
                }
            }
        }
        cache_active |= machine.objects.decoded_leaves_enabled();
    };
    assert_eq!(cache_active, enabled, "decoded leaf cache activation");
    assert!(fetches > 0, "pack must fetch evicted evidence pages");
    if width > 1 {
        assert!(peak > 1, "test must execute overlapping jobs");
    }
    DeterministicRun {
        outcome,
        pages: host.pages,
        fragments: host.fragments,
        work: machine.usage().work,
    }
}

#[test]
fn leaf_only_exact_job_determinism_and_work() {
    let pack = graph_pack();
    let mut corrupt = pack.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    for (bytes, bad) in [(&pack, false), (&corrupt, true)] {
        let expected = scheduled_leaves(bytes, 0, false);
        if bad {
            assert_eq!(
                expected.outcome.as_ref().unwrap_err().code,
                FailureCode::PackfileCorrupted
            );
        } else {
            assert!(expected.outcome.is_ok());
        }
        for width in [0, 1, 2, 4, 8] {
            assert_eq!(
                scheduled_leaves(bytes, width, true),
                expected,
                "width={width}"
            );
        }
    }
}

fn limited_run(
    pack: &[u8],
    execution: VerifyLimits,
    enabled: bool,
) -> (Result<String, Failure>, crate::pack_verify::ResourceUsage) {
    let mut machine =
        VerifyDriver::new(source(pack), REPOSITORY, profile(), execution, 17).unwrap();
    if !enabled {
        machine.objects.prevent_decoded_leaves();
    }
    let outcome = Host::new(pack)
        .finish(&mut machine)
        .map(|pack| format!("{pack:?}"));
    (outcome, machine.usage())
}
#[test]
fn leaf_only_limit_refusals_and_work() {
    let pack = leaf_pack(320);
    let base = execution_limits();
    let (_, usage) = limited_run(&pack, base, false);
    let mut cases = Vec::new();
    for resident in [12, 16, 24, 48, 64, 96, 128, 256] {
        cases.push(VerifyLimits {
            resident_bytes: resident << 20,
            ..base
        });
    }
    for pages in [7, 8, 16, 24, 32, 48, 64, 128, 256] {
        cases.push(VerifyLimits {
            evidence_pages: pages,
            ..base
        });
    }
    for bytes in [8192, 16_384, 32_768, 65_536, 131_072, 262_144] {
        cases.push(VerifyLimits {
            evidence_bytes: bytes,
            ..base
        });
    }
    for delta in [0, 1, 1024, 65_536] {
        cases.push(VerifyLimits {
            work: usage.work.saturating_sub(delta),
            ..base
        });
    }
    for decoded in [1, 64 << 10, 128 << 10, 512 << 10, 1 << 20] {
        cases.push(VerifyLimits {
            decoded_bytes: decoded,
            ..base
        });
    }
    for limits in cases {
        let (a, ua) = limited_run(&pack, limits, false);
        let (b, ub) = limited_run(&pack, limits, true);
        assert_eq!(a, b, "{limits:?}");
        assert_eq!(ua.work, ub.work, "{limits:?}");
    }
}

fn advance_entry(machine: &mut VerifyDriver, host: &mut Host, ordinal: u64) {
    while machine.ordinal < ordinal || machine.work.is_some() || machine.op.is_some() {
        match machine.step().unwrap() {
            Step::Request(request) => host.serve(machine, &request).unwrap(),
            Step::ProvisionalObject(fragment) => host
                .fragments
                .entry(fragment.ordinal)
                .or_default()
                .extend_from_slice(fragment.bytes),
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Progress | Step::ReleasePage(_) => (),
            Step::Complete(_) => panic!("entry boundary missing"),
        }
    }
}

#[test]
fn decoded_leaf_storage_releases_before_later_entry_pressure() {
    let pack = leaf_pack(192);
    let execution = VerifyLimits {
        resident_bytes: 256 << 20,
        ..limits()
    };
    let mut eager = VerifyDriver::new(source(&pack), REPOSITORY, profile(), execution, 17).unwrap();
    eager.objects.prevent_decoded_leaves();
    let mut cached =
        VerifyDriver::new(source(&pack), REPOSITORY, profile(), execution, 17).unwrap();
    let (mut a, mut b) = (Host::new(&pack), Host::new(&pack));
    advance_entry(&mut eager, &mut a, 180);
    advance_entry(&mut cached, &mut b, 180);
    assert!(cached.objects.decoded_leaves_enabled());
    let pressure = eager.resources.available() - (6 << 20);
    eager.resources.reserve(pressure).unwrap();
    cached.resources.reserve(pressure).unwrap();
    advance_entry(&mut cached, &mut b, 181);
    assert!(!cached.objects.decoded_leaves_enabled());
    let expected = a.finish(&mut eager).unwrap();
    let actual = b.finish(&mut cached).unwrap();
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    assert_eq!(cached.usage().work, eager.usage().work);
}

fn checkpoint_at_boundary(machine: &mut VerifyDriver, host: &mut Host) -> Checkpoint {
    let ordinal = machine.ordinal;
    loop {
        match machine.checkpoint() {
            Ok(checkpoint) => {
                assert_eq!(checkpoint.meta().ordinal, ordinal);
                return Checkpoint::from_bytes(checkpoint.bytes(), execution_limits()).unwrap();
            }
            Err(error) => assert_eq!(error.code, FailureCode::CheckpointNotReady),
        }
        match machine.step().unwrap() {
            Step::Request(request) => host.serve(machine, &request).unwrap(),
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::ReleasePage(_) | Step::Progress => (),
            _ => panic!("checkpoint crossed entry boundary"),
        }
        assert_eq!(machine.ordinal, ordinal);
    }
}
#[test]
fn leaf_only_checkpoints_preserve_all_roots_pages_and_work() {
    let pack = leaf_pack(256);
    let execution = execution_limits();
    let mut eager = VerifyDriver::new(source(&pack), REPOSITORY, profile(), execution, 17).unwrap();
    eager.objects.prevent_decoded_leaves();
    let mut cached =
        VerifyDriver::new(source(&pack), REPOSITORY, profile(), execution, 17).unwrap();
    let (mut a, mut b) = (Host::new(&pack), Host::new(&pack));
    for ordinal in 129..256 {
        advance_entry(&mut eager, &mut a, ordinal);
        advance_entry(&mut cached, &mut b, ordinal);
        assert!(cached.objects.decoded_leaves_enabled());
        let expected = checkpoint_at_boundary(&mut eager, &mut a);
        let actual = checkpoint_at_boundary(&mut cached, &mut b);
        let mut expected_state = expected.decode(execution).unwrap();
        let mut actual_state = actual.decode(execution).unwrap();
        // Actual optional ownership changes only the peak resident statistic.
        expected_state.meta.usage.peak_resident_bytes = 0;
        actual_state.meta.usage.peak_resident_bytes = 0;
        assert_eq!(format!("{actual_state:?}"), format!("{expected_state:?}"));
        assert_eq!(b.pages, a.pages);
        eager = VerifyDriver::resume(
            source(&pack),
            REPOSITORY,
            profile(),
            execution,
            18 + ordinal,
            &expected,
        )
        .unwrap();
        eager.objects.prevent_decoded_leaves();
        cached = VerifyDriver::resume(
            source(&pack),
            REPOSITORY,
            profile(),
            execution,
            18 + ordinal,
            &actual,
        )
        .unwrap();
    }
    let expected = a.finish(&mut eager).unwrap();
    let actual = b.finish(&mut cached).unwrap();
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    assert_eq!(cached.usage().work, eager.usage().work);
}

#[test]
fn leaf_only_resource_and_content_refusals_keep_integrity_precedence() {
    let mut malformed = leaf_pack(192);
    malformed.truncate(malformed.len() - 32);
    malformed[8..12].copy_from_slice(&193_u32.to_le_bytes());
    malformed.extend_from_slice(&[0, 1, 0, 0, 0, 255]);
    malformed.extend_from_slice(&hash::hash(&malformed));
    let mut corrupt = malformed.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    for pages in [7, 32, 64, 128, 1_000_000] {
        let execution = VerifyLimits {
            evidence_pages: pages,
            ..execution_limits()
        };
        for (pack, corrupted) in [(&malformed, false), (&corrupt, true)] {
            let (expected, a) = limited_run(pack, execution, false);
            let (actual, b) = limited_run(pack, execution, true);
            let code = expected.as_ref().unwrap_err().code;
            if corrupted {
                assert_eq!(code, FailureCode::PackfileCorrupted);
            } else if pages == 1_000_000 {
                assert_eq!(code, FailureCode::NonCanonicalObject);
            }
            assert_eq!(actual, expected, "pages={pages}, corrupt={corrupted}");
            assert_eq!(a.work, b.work, "pages={pages}, corrupt={corrupted}");
        }
    }
}

#[test]
fn leaf_only_delta_base_reuse_preserves_all_job_counts() {
    let mut writer = PackWriter::new();
    let (base_id, base) = blob(&0_u32.to_le_bytes());
    for ordinal in 0..192_u32 {
        let (id, bytes) = blob(&ordinal.to_le_bytes());
        writer.push_raw(id, &bytes).unwrap();
    }
    let (_, target) = blob(b"delta target");
    writer
        .push_delta(&base_id, &delta::encode(&base, &target).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let expected = scheduled_leaves(&pack, 0, false);
    assert!(expected.outcome.is_ok());
    for width in [0, 1, 2, 4, 8] {
        assert_eq!(
            scheduled_leaves(&pack, width, true),
            expected,
            "width={width}"
        );
    }
}
