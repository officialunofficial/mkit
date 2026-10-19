//! Single-acquisition integrity, refusal precedence, and resumable progress.
use super::*;

#[test]
fn success_acquires_each_pack_byte_once() {
    let (id, bytes) = blob(&[42; 4096]);
    let mut writer = PackWriter::new_raw_only();
    for _ in 0..8 {
        writer.push_raw(id, &bytes).unwrap();
    }
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let mut machine = driver(&pack);
    let mut acquired = 0;
    loop {
        match machine.step().unwrap() {
            Step::Request(request) => {
                if let Request::Bytes {
                    source: ByteSource::Pack(_),
                    range,
                    ..
                } = request
                {
                    acquired += range.len;
                }
                host.serve(&mut machine, &request).unwrap();
            }
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
            Step::Complete(_) => break,
        }
    }
    assert_eq!(acquired, pack.len() as u64);
}

#[derive(Debug, Clone, Copy)]
enum Fault {
    External,
    LaterBase,
    Signature,
    Frame,
    Cap,
}

fn fault_pack(fault: Fault, corrupt: bool) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for byte in 1..=3 {
        let (id, bytes) = blob(&[byte; 1024]);
        writer.push_raw(id, &bytes).unwrap();
    }
    let mut pack = writer.finish().unwrap();
    pack.truncate(pack.len() - 32);
    let (_, good) = blob(b"last");
    let mut extra = Vec::new();
    let (kind, bytes) = match fault {
        Fault::External | Fault::LaterBase => {
            let (id, base) = blob(b"unavailable base");
            extra.extend_from_slice(&id);
            extra.extend_from_slice(&delta::encode(&base, &good).unwrap());
            (2, extra)
        }
        Fault::Signature => {
            let (_, mut bytes) = signed_commit([0; 32], vec![]);
            *bytes.last_mut().unwrap() ^= 1;
            (0, bytes)
        }
        Fault::Frame => (0x7f, good.clone()),
        Fault::Cap => (0, vec![0; usize::try_from(CANONICAL_BYTES).unwrap() + 1]),
    };
    pack.push(kind);
    pack.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
    pack.extend_from_slice(&bytes);
    let final_bytes = if matches!(fault, Fault::LaterBase) {
        blob(b"unavailable base").1
    } else {
        good
    };
    pack.push(0);
    pack.extend_from_slice(&u32::try_from(final_bytes.len()).unwrap().to_le_bytes());
    pack.extend_from_slice(&final_bytes);
    pack[8..12].copy_from_slice(&5u32.to_le_bytes());
    let trailer = hash::hash(&pack);
    pack.extend_from_slice(&trailer);
    if corrupt {
        *pack.last_mut().unwrap() ^= 1;
    }
    pack
}

fn fault_result(pack: &[u8], parallel: bool, resume_ordinal: Option<u64>) -> Failure {
    let mut host = Host::new(pack);
    host.members_absent = true;
    let mut machine = driver(pack);
    if parallel {
        machine = machine
            .with_compute(ComputeConfig::new(3).with_min_job_bytes(0))
            .unwrap();
    }
    let mut resumed = false;
    loop {
        let step = match machine.step() {
            Ok(step) => step,
            Err(error) => {
                assert!(
                    resume_ordinal.is_none() || resumed,
                    "requested entry boundary was not checkpointable"
                );
                return error;
            }
        };
        match step {
            Step::Request(request) => {
                if let Err(error) = host.serve(&mut machine, &request) {
                    assert!(
                        resume_ordinal.is_none() || resumed,
                        "requested entry boundary was not checkpointable"
                    );
                    return error;
                }
            }
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
            Step::Complete(_) => panic!("fault accepted"),
        }
        if !resumed
            && resume_ordinal == Some(machine.ordinal)
            && let Ok(checkpoint) = machine.checkpoint()
        {
            let checkpoint = Checkpoint::from_bytes(checkpoint.bytes(), limits()).unwrap();
            machine = VerifyDriver::resume(
                source(pack),
                REPOSITORY,
                profile(),
                limits(),
                18,
                &checkpoint,
            )
            .unwrap();
            if parallel && machine.phase == Phase::Entries {
                machine = machine
                    .with_compute(ComputeConfig::new(3).with_min_job_bytes(0))
                    .unwrap();
            }
            resumed = true;
        }
    }
}

#[test]
fn competing_faults_keep_integrity_and_wire_precedence_across_schedules_and_resume() {
    for fault in [
        Fault::External,
        Fault::LaterBase,
        Fault::Signature,
        Fault::Frame,
        Fault::Cap,
    ] {
        for corrupt in [false, true] {
            let pack = fault_pack(fault, corrupt);
            let expected = if corrupt {
                FailureCode::PackfileCorrupted
            } else {
                match fault {
                    Fault::External | Fault::LaterBase => FailureCode::ExternalBaseAbsent,
                    Fault::Signature => FailureCode::BadSignature,
                    Fault::Frame => FailureCode::InvalidEntryType,
                    Fault::Cap => FailureCode::PackfileTooLarge,
                }
            };
            let mut boundaries = vec![None, Some(1), Some(2), Some(3)];
            if matches!(fault, Fault::Signature) {
                boundaries.extend([Some(4), Some(5)]);
            } else if !corrupt && matches!(fault, Fault::External | Fault::LaterBase) {
                boundaries.push(Some(4));
            }
            // The complete Failure (code, location and detail), not only its
            // code, is the same under every schedule and resume boundary.
            let baseline = fault_result(&pack, false, None);
            assert_eq!(baseline.code, expected, "{fault:?}, corrupt={corrupt}");
            for parallel in [false, true] {
                for &boundary in &boundaries {
                    assert_eq!(
                        fault_result(&pack, parallel, boundary),
                        baseline,
                        "{fault:?}, corrupt={corrupt}, parallel={parallel}, boundary={boundary:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn first_committed_compute_entry_checkpoints_without_serializing_later_jobs() {
    let mut writer = PackWriter::new_raw_only();
    for byte in 1..=6 {
        let (id, bytes) = blob(&[byte; 1024]);
        writer.push_raw(id, &bytes).unwrap();
    }
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let mut machine = driver(&pack)
        .with_compute(ComputeConfig::new(3).with_min_job_bytes(0))
        .unwrap();
    let mut later = Vec::new();
    let checkpoint = loop {
        match machine.step().unwrap() {
            Step::Request(Request::Compute { job }) => {
                let output = machine.take_compute(job).unwrap().run();
                if job.ordinal() == 0 {
                    assert_eq!(
                        machine.supply_compute(output).unwrap(),
                        ComputeDisposition::Accepted
                    );
                } else {
                    later.push(output);
                }
            }
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
            Step::Complete(_) => panic!("completed with unsupplied later jobs"),
        }
        if machine.ordinal == 1 && machine.work.is_none() {
            // The first committed entry is durable while later jobs run.
            break boundary_checkpoint(&mut machine, &mut host);
        }
    };
    assert_eq!(
        later.len(),
        2,
        "the batch still has two caller-owned outputs"
    );
    drop(machine);
    let mut resumed = VerifyDriver::resume(
        source(&pack),
        REPOSITORY,
        profile(),
        limits(),
        18,
        &checkpoint,
    )
    .unwrap();
    for output in later {
        assert_eq!(
            resumed.supply_compute(output).unwrap(),
            ComputeDisposition::Stale
        );
    }
    let committed = checkpoint.meta().ordinal * 5 + checkpoint.meta().payload + 12;
    let range = finish_after_committed_boundary(&mut host, &mut resumed, committed, 6);
    assert_eq!(range.offset, committed);
}

fn finish_after_committed_boundary(
    host: &mut Host,
    machine: &mut VerifyDriver,
    committed: u64,
    entries: u64,
) -> ByteRange {
    let mut first_range = None;
    loop {
        match machine.step().unwrap() {
            Step::Request(request) => {
                if let Request::Bytes {
                    source: ByteSource::Pack(_),
                    range,
                    ..
                } = request
                {
                    first_range.get_or_insert(range);
                    assert!(
                        range.offset >= committed,
                        "resumed acquisition reread committed bytes"
                    );
                }
                host.serve(machine, &request).unwrap();
            }
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
            Step::Complete(verified) => {
                assert_eq!(verified.counts().entries, entries);
                break;
            }
        }
    }
    first_range.expect("resumed suffix acquisition")
}

#[test]
fn unavailable_external_acquisition_stays_retryable_before_integrity_verdict() {
    let (base_id, base) = blob(b"external source");
    let (_, target) = blob(b"result");
    let mut writer = PackWriter::new_raw_only();
    // The fault precedes another acquisition so the source cannot finish first.
    for byte in 0..3 {
        let (id, bytes) = blob(&vec![byte; 768 << 10]);
        writer.push_raw(id, &bytes).unwrap();
    }
    let mut pack = writer.finish().unwrap();
    pack.truncate(pack.len() - 32);
    let mut payload = base_id.to_vec();
    payload.extend_from_slice(&delta::encode(&base, &target).unwrap());
    let mut frame = vec![2];
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    frame.extend_from_slice(&payload);
    pack.splice(12..12, frame);
    pack[8..12].copy_from_slice(&4_u32.to_le_bytes());
    pack.extend_from_slice(&hash::hash(&pack));
    *pack.last_mut().unwrap() ^= 1;
    let mut host = Host::new(&pack);
    let mut machine = driver(&pack);
    loop {
        match machine.step().unwrap() {
            Step::Request(request @ Request::ExternalObject { .. }) => {
                assert_eq!(
                    host.serve(&mut machine, &request).unwrap_err().code,
                    FailureCode::UnavailableInput
                );
                assert!(
                    matches!(machine.step().unwrap(), Step::Request(repeated) if repeated == request)
                );
                host.members_absent = true;
                host.serve(&mut machine, &request).unwrap();
                assert_eq!(
                    host.finish(&mut machine).unwrap_err().code,
                    FailureCode::PackfileCorrupted
                );
                break;
            }
            Step::Request(request) => host.serve(&mut machine, &request).unwrap(),
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Progress | Step::ReleasePage(_) => (),
            _ => panic!("external base must be acquired first"),
        }
    }
}

#[test]
fn deferred_framing_fault_checkpoints_hash_progress_without_prefix_acquisition() {
    for corrupt in [false, true] {
        for parallel in [false, true] {
            let mut pack = fault_pack(Fault::Frame, false);
            pack.truncate(pack.len() - 32);
            for byte in 0..8 {
                let (_, bytes) = blob(&vec![byte; 200 << 10]);
                pack.push(0);
                pack.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
                pack.extend_from_slice(&bytes);
            }
            pack[8..12].copy_from_slice(&13u32.to_le_bytes());
            pack.extend_from_slice(&hash::hash(&pack));
            if corrupt {
                *pack.last_mut().unwrap() ^= 1;
            }
            let mut host = Host::new(&pack);
            let mut machine = driver(&pack);
            if parallel {
                machine = machine
                    .with_compute(ComputeConfig::new(3).with_min_job_bytes(0))
                    .unwrap();
            }
            let checkpoint = loop {
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
                    Step::Complete(_) => panic!("framing fault accepted"),
                }
                if machine.phase == Phase::Drain {
                    let checkpoint = machine.checkpoint().unwrap();
                    break Checkpoint::from_bytes(checkpoint.bytes(), limits()).unwrap();
                }
            };
            drop(machine);
            let mut resumed = VerifyDriver::resume(
                source(&pack),
                REPOSITORY,
                profile(),
                limits(),
                18,
                &checkpoint,
            )
            .unwrap();
            let mut acquired = 0;
            let error = loop {
                match resumed.step() {
                    Err(error) => break error,
                    Ok(Step::Request(request)) => {
                        if let Request::Bytes {
                            source: ByteSource::Pack(_),
                            range,
                            ..
                        } = request
                        {
                            assert!(range.offset >= limits().acquisition_bytes);
                            acquired += range.len;
                        }
                        host.serve(&mut resumed, &request).unwrap();
                    }
                    Ok(Step::Progress | Step::ReleasePage(_)) => (),
                    _ => panic!("integrity-only resume emitted entry data"),
                }
            };
            assert_eq!(acquired, pack.len() as u64 - limits().acquisition_bytes);
            assert_eq!(
                error.code,
                if corrupt {
                    FailureCode::PackfileCorrupted
                } else {
                    FailureCode::InvalidEntryType
                }
            );
        }
    }
}

#[test]
fn changed_resume_suffix_makes_the_driver_terminal() {
    let mut writer = PackWriter::new_raw_only();
    for byte in 1..=3 {
        let (id, bytes) = blob(&[byte; 1024]);
        writer.push_raw(id, &bytes).unwrap();
    }
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let mut machine = driver(&pack);
    let checkpoint = loop {
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
            Step::Complete(_) => panic!("first boundary skipped"),
        }
        if machine.ordinal == 1 && machine.work.is_none() {
            break boundary_checkpoint(&mut machine, &mut host);
        }
    };
    let mut resumed = VerifyDriver::resume(
        source(&pack),
        REPOSITORY,
        profile(),
        limits(),
        18,
        &checkpoint,
    )
    .unwrap();
    loop {
        match resumed.step().unwrap() {
            Step::Request(Request::Bytes {
                request,
                source: source @ ByteSource::Pack(_),
                range,
            }) => {
                assert!(range.offset > 0);
                let original = &pack[usize::try_from(range.offset).unwrap()
                    ..usize::try_from(range.offset + range.len).unwrap()];
                let mut changed = original.to_vec();
                changed[0] ^= 1;
                let failure = resumed
                    .supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value: Acquisition::Present(&changed),
                    })
                    .unwrap_err();
                assert_eq!(failure.code, FailureCode::PackfileCorrupted);
                assert_eq!(
                    resumed.step().unwrap_err().code,
                    FailureCode::InvalidResponse
                );
                assert_eq!(
                    resumed
                        .supply(Response::Bytes {
                            request,
                            source,
                            range,
                            value: Acquisition::Present(original)
                        })
                        .unwrap_err()
                        .code,
                    FailureCode::InvalidResponse
                );
                break;
            }
            Step::Request(request) => host.serve(&mut resumed, &request).unwrap(),
            Step::Progress | Step::ReleasePage(_) => (),
            _ => panic!("entry emitted before suffix authentication"),
        }
    }
}

fn hash_only_budget_outcome(pack: &[u8], mode: Option<u64>, resume: bool) -> FailureCode {
    let budget = VerifyLimits {
        acquisition_bytes: 64 << 10,
        work: u64::try_from(pack.len()).unwrap() * 3 + (256 << 10),
        ..limits()
    };
    let mut machine = VerifyDriver::new(source(pack), REPOSITORY, profile(), budget, 17).unwrap();
    if mode.is_some() {
        machine = machine
            .with_compute(ComputeConfig::new(3).with_min_job_bytes(0))
            .unwrap();
    }
    let mut host = Host::new(pack);
    let mut jobs = Vec::new();
    let mut random = mode.unwrap_or(0);
    let mut resumed = false;
    loop {
        match machine.step() {
            Err(error) => {
                assert!(!resume || resumed, "drain progress was not resumed");
                return error.code;
            }
            Ok(Step::Request(Request::Compute { job })) => {
                jobs.push(machine.take_compute(job).unwrap());
            }
            Ok(Step::Request(request)) => {
                if let Err(error) = host.serve(&mut machine, &request) {
                    assert!(!resume || resumed, "drain progress was not resumed");
                    return error.code;
                }
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
                while !jobs.is_empty() {
                    let index = match mode {
                        Some(0) => 0,
                        Some(1) => jobs.len() - 1,
                        _ => {
                            random = random
                                .wrapping_mul(6_364_136_223_846_793_005)
                                .wrapping_add(1);
                            usize::try_from(random % u64::try_from(jobs.len()).unwrap()).unwrap()
                        }
                    };
                    assert_eq!(
                        machine.supply_compute(jobs.remove(index).run()).unwrap(),
                        ComputeDisposition::Accepted
                    );
                }
            }
            Ok(Step::Complete(_)) => panic!("entry work exceeded the hash-only budget"),
        }
        if resume
            && !resumed
            && machine.phase == Phase::Drain
            && let Ok(checkpoint) = machine.checkpoint()
        {
            let checkpoint = Checkpoint::from_bytes(checkpoint.bytes(), budget).unwrap();
            machine =
                VerifyDriver::resume(source(pack), REPOSITORY, profile(), budget, 18, &checkpoint)
                    .unwrap();
            resumed = true;
        }
    }
}

#[test]
fn hashing_work_is_protected_from_entry_work_exhaustion() {
    let mut writer = PackWriter::new_raw_only();
    for byte in 1..=4 {
        let (id, bytes) = blob(&vec![byte; 512 << 10]);
        writer.push_raw(id, &bytes).unwrap();
    }
    let mut pack = writer.finish().unwrap();
    for corrupt in [true, false] {
        *pack.last_mut().unwrap() ^= 1;
        let expected = if corrupt {
            FailureCode::PackfileCorrupted
        } else {
            FailureCode::ResourceLimit
        };
        for mode in [None, Some(0), Some(1), Some(7)] {
            for resume in [false, true] {
                assert_eq!(
                    hash_only_budget_outcome(&pack, mode, resume),
                    expected,
                    "mode={mode:?}, resume={resume}, corrupt={corrupt}"
                );
            }
        }
    }
}

fn seal_budget_pack() -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for byte in 0..15 {
        let (id, bytes) = blob(&[byte; 20]);
        writer.push_raw(id, &bytes).unwrap();
    }
    let children: Vec<_> = (32..48).map(|byte| blob(&[byte; 20])).collect();
    let object = Object::Tree(Tree {
        entries: children
            .iter()
            .enumerate()
            .map(|(index, (id, _))| TreeEntry {
                name: format!("{index:02}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: *id,
            })
            .collect(),
    });
    let (id, bytes) = canonical(&object);
    writer.push_raw(id, &bytes).unwrap();
    for (id, bytes) in children {
        writer.push_raw(id, &bytes).unwrap();
    }
    writer.finish().unwrap()
}

const ALL_ENTRY_COMPUTE: ComputeConfig = ComputeConfig::new(3).with_min_job_bytes(0);

fn seal_budget_run(
    pack: &[u8],
    cap: u64,
    mode: Option<u64>,
    resume_last: bool,
    malformed_at: Option<u64>,
) -> (u64, bool) {
    // A one-page cache evicts constantly, so the seal still fetches pages.
    let budget = VerifyLimits {
        work: cap,
        page_bytes: 4096,
        resident_pages: 1,
        ..limits()
    };
    let mut machine = VerifyDriver::new(source(pack), REPOSITORY, profile(), budget, 17).unwrap();
    if mode.is_some() {
        machine = machine.with_compute(ALL_ENTRY_COMPUTE).unwrap();
    }
    let mut host = Host::new(pack);
    let mut jobs = Vec::new();
    let mut random = mode.unwrap_or(0);
    let mut resumed = false;
    let mut last_page_before = 0;
    loop {
        match machine
            .step()
            .expect("verification must reach the selected page supply")
        {
            Step::Request(Request::Compute { job }) => {
                jobs.push(machine.take_compute(job).unwrap());
            }
            Step::Request(request) => {
                if matches!(request, Request::EvidencePage { .. }) && machine.phase == Phase::Seal {
                    last_page_before = machine.usage().work;
                }
                let phase = machine.phase;
                let malformed = phase == Phase::Seal && malformed_at == Some(last_page_before);
                if malformed && let Request::EvidencePage { page, .. } = request {
                    host.pages
                        .iter_mut()
                        .find(|(commitment, _)| *commitment == page)
                        .unwrap()
                        .1[0] ^= 1;
                }
                if let Err(error) = host.serve(&mut machine, &request) {
                    assert_eq!(phase, Phase::Seal);
                    assert_eq!(
                        error.code,
                        if malformed {
                            FailureCode::InvalidEvidence
                        } else {
                            FailureCode::ResourceLimit
                        }
                    );
                    assert!(!resume_last || resumed);
                    if cap == last_page_before {
                        assert_eq!(
                            machine.step().unwrap_err().code,
                            FailureCode::InvalidResponse
                        );
                        assert_eq!(
                            host.serve(&mut machine, &request).unwrap_err().code,
                            FailureCode::InvalidResponse
                        );
                    } else {
                        assert!(malformed);
                        assert!(matches!(
                            machine.step().unwrap(),
                            Step::Request(Request::EvidencePage { .. })
                        ));
                    }
                    return (last_page_before, false);
                }
            }
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
            Step::Progress => complete_selected_jobs(&mut machine, &mut jobs, mode, &mut random),
            Step::ReleasePage(_) => (),
            Step::Complete(verified) => {
                assert_eq!(verified.counts().entries, 32);
                assert!(!resume_last || resumed);
                return (last_page_before, true);
            }
        }
        if resume_last
            && !resumed
            && machine.ordinal == 32
            && machine.work.is_none()
            && let Ok(checkpoint) = machine.checkpoint()
        {
            let checkpoint = Checkpoint::from_bytes(checkpoint.bytes(), budget).unwrap();
            machine =
                VerifyDriver::resume(source(pack), REPOSITORY, profile(), budget, 18, &checkpoint)
                    .unwrap();
            if mode.is_some() {
                machine = machine.with_compute(ALL_ENTRY_COMPUTE).unwrap();
            }
            resumed = true;
        }
    }
}

fn complete_selected_jobs(
    machine: &mut VerifyDriver,
    jobs: &mut Vec<ComputeJob>,
    mode: Option<u64>,
    random: &mut u64,
) {
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
        assert_eq!(
            machine.supply_compute(jobs.remove(index).run()).unwrap(),
            ComputeDisposition::Accepted
        );
    }
}

#[test]
fn sealing_page_work_exhaustion_is_terminal() {
    let pack = seal_budget_pack();
    for mode in [None, Some(0), Some(1), Some(7)] {
        for resume_last in [false, true] {
            let (cap, complete) = seal_budget_run(&pack, limits().work, mode, resume_last, None);
            assert!(complete);
            assert!(cap > 0);
            assert!(!seal_budget_run(&pack, cap, mode, resume_last, None).1);
        }
    }
}

#[test]
fn malformed_sealing_page_keeps_precedence_over_work_exhaustion() {
    let pack = seal_budget_pack();
    for mode in [None, Some(0), Some(1), Some(7)] {
        for resume_last in [false, true] {
            let (cap, complete) = seal_budget_run(&pack, limits().work, mode, resume_last, None);
            assert!(complete);
            assert!(!seal_budget_run(&pack, cap, mode, resume_last, Some(cap)).1);
            assert!(!seal_budget_run(&pack, limits().work, mode, resume_last, Some(cap)).1);
        }
    }
}
