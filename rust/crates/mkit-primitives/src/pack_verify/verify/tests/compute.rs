//! Completion order is a host choice and never an acceptance input.
use super::*;

#[derive(Debug, PartialEq, Eq)]
struct Transcript {
    outcome: Result<String, Failure>,
    fragments: BTreeMap<u64, Vec<u8>>,
    pages: Vec<(PageCommitment, Vec<u8>)>,
}

fn artifact(pack: &VerifiedPack) -> String {
    format!(
        "{:?}{:?}{:?}{:?}",
        (pack.pack_id(), pack.len(), pack.is_empty(), pack.source()),
        (
            pack.counts(),
            pack.version(),
            pack.trailer(),
            pack.ruleset()
        ),
        (pack.profile(), pack.limits(), pack.object_set_root()),
        (
            pack.occurrences(),
            pack.dependencies(),
            pack.ordinals(),
            pack.head_facts()
        ),
    )
}

fn raw_pack(values: &[&[u8]]) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for value in values {
        let (id, bytes) = blob(value);
        writer.push_raw(id, &bytes).unwrap();
    }
    writer.finish().unwrap()
}

fn complete_jobs(
    machine: &mut VerifyDriver,
    jobs: &mut Vec<ComputeJob>,
    mode: Option<u64>,
    random: &mut u64,
) {
    if mode == Some(u64::MAX) {
        let outputs = std::thread::scope(|scope| {
            let workers: Vec<_> = jobs
                .drain(..)
                .map(|job| scope.spawn(move || job.run()))
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
    while !jobs.is_empty() {
        let index = match mode {
            Some(0) => 0,
            Some(1) => jobs.len() - 1,
            _ => {
                *random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                usize::try_from(*random % u64::try_from(jobs.len()).unwrap()).unwrap()
            }
        };
        let job = jobs.remove(index);
        let before = machine.usage();
        assert_eq!(
            machine.supply_compute(job.run()).unwrap(),
            ComputeDisposition::Accepted
        );
        assert_eq!(
            machine.usage(),
            before,
            "completion cannot merge or release early"
        );
    }
}

fn run(
    host: Host,
    budget: VerifyLimits,
    mode: Option<u64>,
) -> (
    Transcript,
    usize,
    super::super::super::resources::ResourceUsage,
) {
    run_config(host, budget, mode, 3, Some(0))
}

fn run_config(
    mut host: Host,
    budget: VerifyLimits,
    mode: Option<u64>,
    width: u8,
    minimum: Option<u64>,
) -> (Transcript, usize, crate::pack_verify::ResourceUsage) {
    let initial = VerifyDriver::new(source(&host.pack), REPOSITORY, profile(), budget, 17)
        .and_then(|machine| {
            if mode.is_some() {
                machine.with_compute(match minimum {
                    Some(bytes) => ComputeConfig::new(width).with_min_job_bytes(bytes),
                    None => ComputeConfig::new(width),
                })
            } else {
                Ok(machine)
            }
        });
    let mut machine = match initial {
        Ok(machine) => machine,
        Err(error) => {
            return (
                Transcript {
                    outcome: Err(error),
                    fragments: host.fragments,
                    pages: host.pages,
                },
                0,
                crate::pack_verify::ResourceUsage::default(),
            );
        }
    };
    let mut jobs = Vec::<ComputeJob>::new();
    let mut peak = 0;
    let mut random = mode.unwrap_or(0);
    let mut complete = None;
    for _ in 0..100_000 {
        assert!(machine.usage().resident_bytes <= budget.resident_bytes);
        let step = match machine.step() {
            Ok(step) => step,
            Err(error) => {
                complete = Some(Err(error));
                break;
            }
        };
        match step {
            Step::Request(Request::Compute { job }) => {
                let taken = machine.take_compute(job).unwrap();
                assert_eq!(taken.request(), job);
                assert_eq!(
                    machine.take_compute(job).unwrap_err().code,
                    FailureCode::InvalidResponse
                );
                assert_eq!(
                    machine.checkpoint().unwrap_err().code,
                    FailureCode::CheckpointNotReady
                );
                jobs.push(taken);
                peak = peak.max(jobs.len());
            }
            Step::Request(request) => {
                assert!(jobs.is_empty(), "acquisition escaped an outstanding batch");
                if let Err(error) = host.serve(&mut machine, &request) {
                    complete = Some(Err(error));
                    break;
                }
            }
            Step::Progress => complete_jobs(&mut machine, &mut jobs, mode, &mut random),
            Step::ReleasePage(_) => (),
            Step::ProvisionalObject(fragment) => {
                host.fragments
                    .entry(fragment.ordinal)
                    .or_default()
                    .extend_from_slice(fragment.bytes);
            }
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Complete(pack) => {
                complete = Some(Ok(artifact(&pack)));
                break;
            }
        }
        assert!(machine.usage().resident_bytes <= budget.resident_bytes);
    }
    (
        Transcript {
            outcome: complete.expect("bounded schedule terminated"),
            fragments: host.fragments,
            pages: host.pages,
        },
        peak,
        machine.usage(),
    )
}

fn parity(
    pack: &[u8],
    budget: VerifyLimits,
    external: Option<&(Hash, MemberFact, Vec<u8>)>,
    require_overlap: bool,
) {
    let host = || {
        let mut host = Host::new(pack);
        if let Some((id, member, bytes)) = external {
            host.externals.insert(*id, (member.clone(), bytes.clone()));
        }
        host
    };
    let (expected, _, serial_usage) = run(host(), budget, None);
    for schedule in [0, 1, 2, 7, 31, 255, 65_537] {
        let (actual, peak, usage) = run(host(), budget, Some(schedule));
        assert_eq!(actual, expected, "schedule={schedule}");
        if require_overlap {
            assert!(peak >= 2, "schedule never held concurrent work");
        }
        assert!(peak <= 3);
        assert_eq!(usage.work, serial_usage.work);
        assert_eq!(usage.evidence_bytes, serial_usage.evidence_bytes);
        assert_eq!(usage.evidence_pages, serial_usage.evidence_pages);
        assert!(usage.peak_resident_bytes <= budget.resident_bytes);
    }
}

#[test]
fn raw_duplicates_and_random_completion_orders_preserve_every_artifact() {
    let pack = raw_pack(&[
        b"alpha", b"beta", b"alpha", b"gamma", b"delta", b"epsilon", b"zeta",
    ]);
    parity(&pack, limits(), None, true);
    assert!(run(Host::new(&pack), limits(), None).0.outcome.is_ok());
}

#[test]
fn signed_and_delta_barriers_preserve_artifacts_and_dependencies() {
    let (base_id, base) = blob(b"base");
    let (middle_id, middle) = blob(b"middle");
    let (_, result) = blob(b"result");
    let (tree_id, tree_bytes) = tree(b"leaf", EntryMode::Blob, base_id);
    let (commit_id, commit) = signed_commit(tree_id, vec![]);
    let (tag_id, tag) = signed_tag(commit_id, ObjectType::Commit);
    let mut writer = PackWriter::new();
    writer.push_raw(base_id, &base).unwrap();
    writer.push_raw(tree_id, &tree_bytes).unwrap();
    writer.push_raw(commit_id, &commit).unwrap();
    writer.push_raw(tag_id, &tag).unwrap();
    writer
        .push_delta(&base_id, &delta::encode(&base, &middle).unwrap())
        .unwrap();
    writer
        .push_delta(&middle_id, &delta::encode(&middle, &result).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    parity(&pack, limits(), None, false);
    assert!(run(Host::new(&pack), limits(), None).0.outcome.is_ok());
    let mut writer = PackWriter::new();
    writer
        .push_delta(&base_id, &delta::encode(&base, &result).unwrap())
        .unwrap();
    parity(
        &writer.finish().unwrap(),
        limits(),
        Some(&(base_id, fact(base_id, &base, ObjectType::Blob), base)),
        false,
    );
}

#[test]
fn content_and_signature_faults_keep_serial_precedence() {
    let (id, bytes) = blob(b"valid");
    let malformed = [ObjectType::Blob as u8];
    let (commit_id, mut commit) = signed_commit([9; 32], vec![]);
    let last = commit.len() - 1;
    commit[last] ^= 1;
    for signed_first in [false, true] {
        let mut writer = PackWriter::new_raw_only();
        writer.push_raw(id, &bytes).unwrap();
        if signed_first {
            writer.push_raw(commit_id, &commit).unwrap();
        }
        writer.push_raw([4; 32], &malformed).unwrap();
        if !signed_first {
            writer.push_raw(commit_id, &commit).unwrap();
        }
        let pack = writer.finish().unwrap();
        assert!(run(Host::new(&pack), limits(), None).0.outcome.is_err());
        parity(&pack, limits(), None, false);
    }
    // Recompute integrity after corrupting later framing: the earlier entry's
    // canonical fault must still win over a speculative lookahead refusal.
    let mut pack = b"MKIT\x01\0\0\0\x02\0\0\0".to_vec();
    pack.push(0);
    pack.extend_from_slice(&1_u32.to_le_bytes());
    pack.extend_from_slice(&malformed);
    pack.push(255);
    pack.extend_from_slice(&0_u32.to_le_bytes());
    pack.extend_from_slice(&hash::hash(&pack));
    parity(&pack, limits(), None, false);
}

#[test]
fn configured_work_decoded_evidence_and_memory_ceilings_are_schedule_independent() {
    let pack = raw_pack(&[b"alpha", b"beta", b"gamma", b"delta"]);
    for budget in [
        VerifyLimits {
            work: 1,
            ..limits()
        },
        VerifyLimits {
            work: 16 << 20,
            ..limits()
        },
        VerifyLimits {
            decoded_bytes: 1,
            ..limits()
        },
        VerifyLimits {
            evidence_pages: 1,
            ..limits()
        },
        VerifyLimits {
            page_bytes: 256,
            resident_pages: 1,
            resident_bytes: 40 << 20,
            ..limits()
        },
        VerifyLimits {
            resident_bytes: 63 << 20,
            ..limits()
        },
    ] {
        parity(&pack, budget, None, false);
    }
    let budget = VerifyLimits {
        work: 16 << 20,
        ..limits()
    };
    let (result, peak, _) = run(Host::new(&pack), budget, Some(1));
    assert!(
        result.outcome.is_ok(),
        "low-work admission falls back to one job"
    );
    assert_eq!(peak, 1);
}

fn first_job(machine: &mut VerifyDriver, host: &mut Host) -> ComputeJob {
    for _ in 0..10_000 {
        match machine.step().unwrap() {
            Step::Request(Request::Compute { job }) => return machine.take_compute(job).unwrap(),
            Step::Request(request) => host.serve(machine, &request).unwrap(),
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Progress | Step::ReleasePage(_) => (),
            _ => panic!("expected first compute before any object"),
        }
    }
    panic!("bounded first compute request");
}

#[test]
fn opaque_completions_bind_generation_source_and_exact_issued_descriptor() {
    let pack = raw_pack(&[b"alpha", b"beta", b"gamma"]);
    let make = |pack: &[u8], generation| {
        VerifyDriver::new(source(pack), REPOSITORY, profile(), limits(), generation)
            .unwrap()
            .with_compute(ComputeConfig::new(3).with_min_job_bytes(0))
            .unwrap()
    };
    let mut host = Host::new(&pack);
    let mut machine = make(&pack, 17);
    let job = first_job(&mut machine, &mut host);
    let descriptor = job.request();
    let mut stale_machine = make(&pack, 16);
    let stale = first_job(&mut stale_machine, &mut Host::new(&pack));
    let before = machine.usage();
    assert_eq!(
        machine.supply_compute(stale.run()).unwrap(),
        ComputeDisposition::Stale
    );
    assert_eq!(machine.usage(), before);
    let other_pack = raw_pack(&[b"other", b"different"]);
    let mut other = make(&other_pack, 17);
    let other_job = first_job(&mut other, &mut Host::new(&other_pack));
    assert_eq!(
        machine.take_compute(other_job.request()).unwrap_err().code,
        FailureCode::InvalidResponse
    );
    assert_eq!(
        machine.supply_compute(other_job.run()).unwrap_err().code,
        FailureCode::InvalidResponse
    );
    assert_eq!(machine.usage(), before);
    let mut unissued_machine = make(&pack, 17);
    let _first = first_job(&mut unissued_machine, &mut Host::new(&pack));
    let Step::Request(Request::Compute { job: second }) = unissued_machine.step().unwrap() else {
        panic!("raw batch must expose the second outstanding ordinal");
    };
    let second_job = unissued_machine.take_compute(second).unwrap();
    assert_ne!(second_job.request().ordinal(), descriptor.ordinal());
    // This receiver has not transferred its second job to a worker yet.
    assert_eq!(
        machine.supply_compute(second_job.run()).unwrap_err().code,
        FailureCode::InvalidResponse
    );
    assert_eq!(machine.usage(), before);
    // A separate execution of exactly the same immutable job provides a real
    // opaque duplicate without adding a constructor for worker results.
    let mut duplicate_machine = make(&pack, 17);
    let duplicate = first_job(&mut duplicate_machine, &mut Host::new(&pack));
    assert_eq!(duplicate.request(), descriptor);
    assert_eq!(
        machine.supply_compute(job.run()).unwrap(),
        ComputeDisposition::Accepted
    );
    assert_eq!(
        machine.supply_compute(duplicate.run()).unwrap(),
        ComputeDisposition::Stale
    );
    assert_eq!(machine.usage(), before);
    assert_eq!(
        machine.checkpoint().unwrap_err().code,
        FailureCode::CheckpointNotReady
    );
    let verified = host.finish(&mut machine).unwrap();
    assert_eq!(verified.counts().entries, 3);
}

#[test]
fn drained_compute_run_resumes_without_serializing_jobs() {
    let pack = raw_pack(&[b"a", b"b", b"c", b"d", b"e", b"f", b"g"]);
    let mut host = Host::new(&pack);
    let mut machine = driver(&pack)
        .with_compute(ComputeConfig::new(3).with_min_job_bytes(0))
        .unwrap();
    let mut snapshot = None;
    for _ in 0..20_000 {
        match machine.step().unwrap() {
            Step::Request(request) => host.serve(&mut machine, &request).unwrap(),
            Step::ProvisionalObject(fragment) => {
                host.fragments
                    .entry(fragment.ordinal)
                    .or_default()
                    .extend_from_slice(fragment.bytes);
            }
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Progress | Step::ReleasePage(_) => (),
            Step::Complete(_) => break,
        }
        if machine.ordinal >= 3
            && let Ok(checkpoint) = machine.checkpoint()
        {
            snapshot = Some(Checkpoint::from_bytes(checkpoint.bytes(), limits()).unwrap());
            break;
        }
    }
    let snapshot = snapshot.expect("draining a batch exposes a checkpoint boundary");
    let mut resumed = VerifyDriver::resume(
        source(&pack),
        REPOSITORY,
        profile(),
        limits(),
        18,
        &snapshot,
    )
    .unwrap()
    .with_compute(ComputeConfig::new(3).with_min_job_bytes(0))
    .unwrap();
    let mut old_machine = driver(&pack)
        .with_compute(ComputeConfig::new(3).with_min_job_bytes(0))
        .unwrap();
    let old_job = first_job(&mut old_machine, &mut Host::new(&pack));
    let usage = resumed.usage();
    assert_eq!(
        resumed.supply_compute(old_job.run()).unwrap(),
        ComputeDisposition::Stale
    );
    assert_eq!(resumed.usage(), usage);
    let verified = host.finish(&mut resumed).unwrap();
    let expected = Host::new(&pack).finish(&mut driver(&pack)).unwrap();
    assert_eq!(artifact(&verified), artifact(&expected));
}

#[test]
fn portable_scheduling_contract_replays_its_declared_outcome() {
    let contract: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/compute/schedules.json")).unwrap();
    let payloads = contract["payloads"].as_array().unwrap();
    let payloads: Vec<&[u8]> = payloads
        .iter()
        .map(|value| value.as_str().unwrap().as_bytes())
        .collect();
    let pack = raw_pack(&payloads);
    let mut machine = driver(&pack);
    let verified = Host::new(&pack).finish(&mut machine).unwrap();
    let counts = verified.counts();
    assert_eq!(
        Some(counts.entries),
        contract["expected"]["entries"].as_u64()
    );
    assert_eq!(
        Some(counts.objects),
        contract["expected"]["objects"].as_u64()
    );
    assert_eq!(
        Some(counts.delta_entries),
        contract["expected"]["delta_entries"].as_u64()
    );
    // The shared harness uses the contract's bounded three-job envelope.
    assert_eq!(contract["max_jobs"].as_u64(), Some(3));
    let (baseline, _, _) = run(Host::new(&pack), limits(), None);
    for schedule in contract["schedules"].as_array().unwrap() {
        let mode = match schedule.as_str().unwrap() {
            "fifo" => 0,
            "lifo" => 1,
            "seeded" => 31,
            unknown => panic!("unknown portable schedule: {unknown}"),
        };
        let (actual, peak, _) = run(Host::new(&pack), limits(), Some(mode));
        assert_eq!(actual, baseline);
        assert_eq!(actual.outcome, Ok(artifact(&verified)));
        assert!(peak >= 2);
    }
}

fn admission_boundary(
    pack: &[u8],
    mut below: u64,
    mut above: u64,
    budget_at: impl Fn(u64) -> VerifyLimits,
) {
    assert!(run(Host::new(pack), budget_at(below), Some(0)).1 < 2);
    assert!(run(Host::new(pack), budget_at(above), Some(0)).1 >= 2);
    // Discover the public behavioral transition; no private reservation or
    // escrow formula is reproduced in this test.
    while above - below > 1 {
        let middle = below + (above - below) / 2;
        if run(Host::new(pack), budget_at(middle), Some(0)).1 >= 2 {
            above = middle;
        } else {
            below = middle;
        }
    }
    let threshold = above;
    for amount in [threshold - 1, threshold, threshold + 1] {
        let budget = budget_at(amount);
        let (serial, _, _) = run(Host::new(pack), budget, None);
        assert!(serial.outcome.is_ok(), "serial refused at budget {amount}");
        for mode in [0, 1] {
            let (scheduled, width, _) = run(Host::new(pack), budget, Some(mode));
            assert_eq!(scheduled, serial, "budget={amount}, schedule={mode}");
            assert!(scheduled.outcome.is_ok());
            if amount < threshold {
                assert_eq!(width, 1, "optional admission must fall back serially");
            } else {
                assert!(width >= 2, "expected the discovered overlap transition");
            }
        }
        parity(pack, budget, None, amount >= threshold);
    }
}

#[test]
fn optional_overlap_preserves_acceptance_at_discovered_work_and_memory_boundaries() {
    let pack = raw_pack(&[b"first", b"second", b"third"]);
    admission_boundary(&pack, 1, 64 << 20, |work| VerifyLimits { work, ..limits() });
    admission_boundary(&pack, 48 << 20, 64 << 20, |resident_bytes| VerifyLimits {
        resident_bytes,
        ..limits()
    });
}

#[test]
fn small_entries_use_no_jobs_by_default() {
    let pack = raw_pack(&[b"alpha", b"beta", b"gamma"]);
    let (serial, _, usage) = run(Host::new(&pack), limits(), None);
    for width in [1, 2, 4, 8, 16] {
        let (actual, peak, threaded_usage) =
            run_config(Host::new(&pack), limits(), Some(u64::MAX), width, None);
        assert_eq!(peak, 0, "small entries must avoid worker dispatch");
        assert_eq!(actual, serial);
        assert_eq!(threaded_usage.work, usage.work);
    }
}

fn mixed_threshold_pack(reverse: bool, malformed: bool) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    let ordinals: Vec<u32> = if reverse {
        (0..72).rev().collect()
    } else {
        (0..72).collect()
    };
    for ordinal in ordinals {
        // Many unique objects cross leaf splits and acquisition windows.
        // Adjacent small and large entries exercise both threshold transitions.
        let size = match ordinal % 4 {
            0 => 4096,
            1 => (64 << 10) - 11,
            2 => 70 << 10,
            _ => 128,
        };
        let mut value = vec![0x41; size];
        value[..4].copy_from_slice(&ordinal.to_le_bytes());
        let (id, canonical) = blob(&value);
        writer.push_raw(id, &canonical).unwrap();
    }
    if malformed {
        let invalid = [ObjectType::Blob as u8];
        writer.push_raw(hash::hash(&invalid), &invalid).unwrap();
    }
    writer.finish().unwrap()
}

#[test]
fn real_threads_and_job_counts_preserve_pages_roots_refusals_and_charges() {
    let pack = mixed_threshold_pack(false, false);
    let reversed = mixed_threshold_pack(true, false);
    let malformed = mixed_threshold_pack(false, true);
    let mut corrupt = pack.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    for bytes in [&pack, &reversed, &malformed, &corrupt] {
        let (serial, _, usage) = run(Host::new(bytes), limits(), None);
        for width in [0, 1, 2, 4, 8] {
            for minimum in [None, Some(0), Some(u64::MAX)] {
                let mode = (width != 0).then_some(u64::MAX);
                let (actual, peak, threaded_usage) =
                    run_config(Host::new(bytes), limits(), mode, width, minimum);
                assert_eq!(actual, serial, "width={width}, minimum={minimum:?}");
                assert_eq!(threaded_usage.work, usage.work);
                assert_eq!(threaded_usage.evidence_pages, usage.evidence_pages);
                assert_eq!(threaded_usage.evidence_bytes, usage.evidence_bytes);
                if width != 0 && minimum != Some(u64::MAX) {
                    assert!(peak > 0);
                }
            }
        }
    }
}

#[test]
fn mixed_inline_and_dispatched_entries_checkpoint_their_own_cursor() {
    let pack = mixed_threshold_pack(false, false);
    let (expected, _, _) = run(Host::new(&pack), limits(), None);
    for width in [1, 2, 4, 8] {
        for ordinal in [1, 3, 4, 17, 35, 69] {
            let mut host = Host::new(&pack);
            let mut machine = driver(&pack)
                .with_compute(ComputeConfig::new(width))
                .unwrap();
            loop {
                match machine.step().unwrap() {
                    Step::Request(request) => host.serve(&mut machine, &request).unwrap(),
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
                    Step::Complete(_) => panic!("missed boundary {ordinal}"),
                }
                if machine.ordinal == ordinal && machine.work.is_none() {
                    break;
                }
            }
            let snapshot = boundary_checkpoint(&mut machine, &mut host);
            assert_eq!(snapshot.meta().ordinal, ordinal);
            drop(machine);
            let mut resumed = VerifyDriver::resume(
                source(&pack),
                REPOSITORY,
                profile(),
                limits(),
                18,
                &snapshot,
            )
            .unwrap()
            .with_compute(ComputeConfig::new(width))
            .unwrap();
            let verified = host.finish(&mut resumed).unwrap();
            assert_eq!(Ok(artifact(&verified)), expected.outcome);
            assert_eq!(host.fragments, expected.fragments);
        }
    }
}

#[test]
fn large_raw_jobs_keep_the_same_path_below_their_size() {
    let mut writer = PackWriter::new_raw_only();
    for ordinal in 0..24_u32 {
        let mut value = vec![0x41; 100 << 10];
        value[..4].copy_from_slice(&ordinal.to_le_bytes());
        let (id, canonical) = blob(&value);
        writer.push_raw(id, &canonical).unwrap();
    }
    let pack = writer.finish().unwrap();
    for width in [1, 2, 4, 8] {
        let eager = run_config(Host::new(&pack), limits(), Some(u64::MAX), width, Some(0));
        let threshold = run_config(Host::new(&pack), limits(), Some(u64::MAX), width, None);
        assert_eq!(
            threshold, eager,
            "large-entry scheduling must stay identical"
        );
    }
}
