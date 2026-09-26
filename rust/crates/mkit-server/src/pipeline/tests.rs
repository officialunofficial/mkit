//! Pipeline tests: the pure planners and the default hooks.

use futures_executor::block_on;
use mkit_core::hash::Hash;
use mkit_core::protocol::{AdvanceOutcome, PackKey};
use mkit_core::refs::RefWriteCondition::{self, Any, Match, Missing};
use proptest::prelude::*;

use super::*;
use crate::error::Code;
use crate::op::{RefUpdate, VerifiedAuth};
use crate::principal::Principal;
use crate::quota::{QuotaCharge, QuotaLimits, QuotaScope, QuotaState};
use crate::replay::{StoredResult, UpdateRefResult};
use crate::repo::{NamespaceKey, RepoId, RepoName};
use crate::store::keys::{self, LAYOUT_VERSION};
use crate::store::{Key, Partition, Precondition, StoreCapabilities, Value, Write, codec};

const REPO: &str = "room-a";
const T0: i64 = 1_700_000_000_000;
const WINDOW: u64 = 10_000;
const HEAD: &str = "refs/heads/main";
const PACKMAP: &str = "refs/mkit/packmap/main";
const A: Hash = [0xaa; 32];
const B: Hash = [0xbb; 32];
const C: Hash = [0xcc; 32];

fn upd(name: &str, condition: RefWriteCondition, new: Hash) -> RefUpdate {
    RefUpdate {
        name: name.to_owned(),
        condition,
        new,
    }
}

fn ms(t: i64) -> u64 {
    u64::try_from(t).unwrap()
}

// ------------------------------------------------------ pure planners

fn repo_name() -> RepoName {
    RepoName::new(REPO).unwrap()
}

fn clock_at(plan_time_ms: u64, deadline_cap: Option<u64>) -> PlanClock {
    PlanClock {
        plan_time_ms,
        business_now_ms: i64::try_from(plan_time_ms).unwrap(),
        max_apply_window_ms: WINDOW,
        deadline_cap,
    }
}

fn snapshot(req: &WriteRequest<'_>, values: &[(Key, Value)]) -> Snapshot {
    let mut snap = Snapshot::default();
    for key in req.read_keys() {
        let value = values
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone());
        snap.insert(key, value);
    }
    snap
}

fn ref_value(name: &str, id: Hash) -> (Key, Value) {
    (keys::ref_key(&repo_name(), name), codec::encode_ref_id(&id))
}

#[test]
fn plan_cas_any_missing_match_on_snapshot() {
    let name = repo_name();
    let cases = [
        (Any, None, true),
        (Any, Some(A), true),
        (Missing, None, true),
        (Missing, Some(A), false),
        (Match(A), Some(A), true),
        (Match(A), Some(B), false),
        (Match(A), None, false),
    ];
    for (condition, current, commits) in cases {
        let refs = [upd(HEAD, condition, C)];
        let req = WriteRequest {
            repo: &name,
            kind: WriteKind::UpdateRef,
            refs: &refs,
            replay: None,
            charges: &[],
            grant: None,
            layout_version: false,
        };
        let values: Vec<_> = current.map(|id| ref_value(HEAD, id)).into_iter().collect();
        let planned = plan_write(&req, &snapshot(&req, &values), &clock_at(5, None)).unwrap();
        match planned {
            Planned::Apply(plan) => {
                assert!(commits, "{condition:?} {current:?}");
                assert_eq!(
                    plan.on_commit,
                    StoredResult::UpdateRef(UpdateRefResult::Committed)
                );
                assert_eq!(
                    plan.batch.writes,
                    vec![Write::Put(ref_value(HEAD, C).0, ref_value(HEAD, C).1)]
                );
                let guarded = plan.batch.preconditions.len() == 2;
                assert_eq!(guarded, condition != Any, "Any is never guarded");
            }
            Planned::Done(result) => {
                assert!(!commits, "{condition:?} {current:?}");
                assert_eq!(
                    result,
                    StoredResult::UpdateRef(UpdateRefResult::Conflict { current })
                );
            }
        }
    }
}

fn replay() -> ReplayGuard {
    ReplayGuard {
        scope: [1; 32],
        fingerprint: [2; 32],
        expires_at_ms: T0,
    }
}

#[test]
fn plan_conflict_writes_only_the_replay_record() {
    let name = repo_name();
    let refs = [upd(PACKMAP, Match(A), C), upd(HEAD, Match(A), C)];
    let req = WriteRequest {
        repo: &name,
        kind: WriteKind::AdvanceRefs,
        refs: &refs,
        replay: Some(replay()),
        charges: &[],
        grant: None,
        layout_version: false,
    };
    let values = [ref_value(PACKMAP, A), ref_value(HEAD, B)];
    let Planned::Apply(plan) =
        plan_write(&req, &snapshot(&req, &values), &clock_at(5, None)).unwrap()
    else {
        panic!("a signed conflict is stored");
    };
    assert_eq!(
        plan.on_commit,
        StoredResult::AdvanceRefs(AdvanceOutcome::HeadConflict)
    );
    let written: Vec<_> = plan
        .batch
        .writes
        .iter()
        .map(|w| match w {
            Write::Put(k, _) | Write::Delete(k) => keys::parse(k),
        })
        .collect();
    assert!(matches!(
        written[..],
        [
            Some(keys::ParsedKey::Replay(_)),
            Some(keys::ParsedKey::ReplayExpiry { .. })
        ]
    ));
    // Both refs that decided the conflict are guarded with what was read.
    assert_eq!(
        plan.batch.preconditions[1..],
        [
            Precondition::Equals(values[0].0.clone(), values[0].1.clone()),
            Precondition::Equals(values[1].0.clone(), values[1].1.clone()),
            Precondition::Absent(keys::replay(&[1; 32])),
        ]
    );
    assert_eq!(plan.replay_index, Some(3));
}

fn charge(max_ops: u32) -> QuotaCharge {
    QuotaCharge {
        scope: QuotaScope::for_signer(&NamespaceKey::deployment_default(), &[3; 32]),
        bytes: 0,
        limits: QuotaLimits {
            window_ms: 60_000,
            max_ops,
            max_bytes: 0,
        },
    }
}

#[test]
fn plan_quota_exhaustion_yields_no_batch() {
    let name = repo_name();
    let refs = [upd(HEAD, Any, C)];
    let charges = [charge(1)];
    let req = WriteRequest {
        repo: &name,
        kind: WriteKind::UpdateRef,
        refs: &refs,
        replay: Some(replay()),
        charges: &charges,
        grant: None,
        layout_version: true,
    };
    let used = QuotaState {
        window_start: T0,
        ops: 1,
        bytes: 0,
    };
    let values = [(
        keys::quota(&charges[0].scope),
        codec::encode_quota_state(&used),
    )];
    let err = plan_write(&req, &snapshot(&req, &values), &clock_at(ms(T0) + 1, None)).unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
}

fn condition() -> impl Strategy<Value = RefWriteCondition> {
    prop_oneof![Just(Any), Just(Missing), Just(Match(A)), Just(Match(B))]
}

fn maybe_id() -> impl Strategy<Value = Option<Hash>> {
    prop_oneof![Just(None), Just(Some(A)), Just(Some(B))]
}

proptest! {
    #[test]
    fn plan_guards_every_read_and_starts_with_not_after(
        advance in any::<bool>(),
        conditions in (condition(), condition()),
        currents in (maybe_id(), maybe_id()),
        signed in any::<bool>(),
        quota in prop::option::of(0u32..3),
        layout in prop_oneof![Just(None), Just(Some(false)), Just(Some(true))],
        plan_time in 0u64..1_000_000,
        cap in prop::option::of(0u64..1_100_000),
    ) {
        let name = repo_name();
        let refs = [upd(PACKMAP, conditions.0, C), upd(HEAD, conditions.1, C)];
        let refs = if advance { &refs[..] } else { &refs[1..] };
        let charges: Vec<_> = quota.map(|_| charge(2)).into_iter().collect();
        let req = WriteRequest {
            repo: &name,
            kind: if advance { WriteKind::AdvanceRefs } else { WriteKind::UpdateRef },
            refs,
            replay: signed.then(replay),
            charges: &charges,
            grant: None,
            layout_version: layout.is_some(),
        };
        let mut values = Vec::new();
        for (name, current) in [(PACKMAP, currents.0), (HEAD, currents.1)] {
            values.extend(current.map(|id| ref_value(name, id)));
        }
        if let Some(ops) = quota.filter(|ops| *ops > 0) {
            let state = QuotaState { window_start: 0, ops, bytes: 0 };
            values.push((keys::quota(&charges[0].scope), codec::encode_quota_state(&state)));
        }
        if layout == Some(true) {
            values.push((keys::layout_version(), codec::encode_u32(LAYOUT_VERSION)));
        }
        let snap = snapshot(&req, &values);
        let clock = clock_at(plan_time, cap);
        let planned = plan_write(&req, &snap, &clock);
        let plan = match planned {
            Err(e) => { prop_assert_eq!(e.code(), Code::ResourceExhausted); return Ok(()); }
            Ok(Planned::Done(_)) => { prop_assert!(!signed && charges.is_empty()); return Ok(()); }
            Ok(Planned::Apply(plan)) => plan,
        };
        let expected = cap.map_or(plan_time + WINDOW, |c| c.min(plan_time + WINDOW));
        prop_assert_eq!(&plan.batch.preconditions[0], &Precondition::NotAfter(expected));
        prop_assert_eq!(plan.batch.preconditions.iter().filter(|p| matches!(p, Precondition::NotAfter(_))).count(), 1);
        let replay_key = keys::replay(&[1; 32]);
        for pre in &plan.batch.preconditions[1..] {
            match pre {
                Precondition::Equals(k, v) => prop_assert_eq!(snap.get(k), Some(v)),
                Precondition::Absent(k) if *k == replay_key => {}
                Precondition::Absent(k) => prop_assert_eq!(snap.get(k), None),
                other => prop_assert!(false, "unexpected {:?}", other),
            }
        }
        let guarded = |k: &Key| plan.batch.preconditions.iter().any(|p| matches!(p,
            Precondition::Equals(g, _) | Precondition::Absent(g) if g == k));
        for k in req.read_keys().iter().filter(|k| !keys::is_ref_key(k)) {
            prop_assert!(guarded(k), "{:?} unguarded", k);
        }
        for update in refs.iter().filter(|u| u.condition != Any) {
            let k = keys::ref_key(&name, &update.name);
            let decided = plan.batch.writes.iter().any(|w| matches!(w, Write::Put(p, _) if *p == k));
            prop_assert!(!decided || guarded(&k), "{} written unguarded", update.name);
        }
        prop_assert!(plan.batch.validate(&StoreCapabilities::full()).is_ok());
    }
}

fn verified(expires_at: i64) -> VerifiedAuth {
    let authorized = mkit_core::write_auth::Authorized {
        scope: "11".repeat(32),
        public_key: "22".repeat(32),
        nonce: "ab".repeat(32),
        fingerprint: "33".repeat(32),
        commitment: format!("body:{}", "cd".repeat(32)),
        expires_at,
    };
    VerifiedAuth::try_from(&authorized).unwrap()
}

fn charges_for(input: &AdmissionInput<'_>) -> Vec<QuotaCharge> {
    match block_on(DefaultAdmission.admit(input)).unwrap() {
        AdmissionDecision::Allow { charges, .. } => charges,
        other => panic!("{other:?}"),
    }
}

#[test]
fn default_admission_charges_signed_writes_only() {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: repo_name(),
    };
    let auth = verified(T0);
    let op = |kind, auth: Option<VerifiedAuth>| {
        let principal = auth
            .as_ref()
            .map_or(Principal::Anonymous, |a| Principal::Signer {
                ed25519: a.signer,
            });
        crate::op::Operation::new(repo.clone(), principal, auth, kind)
    };
    let write = crate::op::OpKind::UpdateRef(upd(HEAD, Missing, A));
    let signed = op(write.clone(), Some(auth.clone()));
    let mut input = AdmissionInput::new(&signed);
    assert_eq!(input.idempotency_key, Some(auth.nonce.as_str()));
    assert_eq!((input.declared_bytes, input.pack_id), (0, None));
    assert!(charges_for(&input).is_empty(), "no configured quota");
    input.write_quota = Some(crate::quota::DEFAULT_WRITE_QUOTA);
    let scope = QuotaScope::for_signer(&repo.namespace, &auth.signer);
    let expected = QuotaCharge {
        scope,
        bytes: 0,
        limits: crate::quota::DEFAULT_WRITE_QUOTA,
    };
    assert_eq!(charges_for(&input), vec![expected]);
    let read = crate::op::OpKind::ReadRef { name: HEAD.into() };
    for other in [op(write, None), op(read, Some(auth))] {
        let mut input = AdmissionInput::new(&other);
        input.write_quota = Some(crate::quota::DEFAULT_WRITE_QUOTA);
        assert!(charges_for(&input).is_empty());
    }
}

#[test]
fn single_partition_maps_everything_to_the_namespace() {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: repo_name(),
    };
    let expected = Partition::Namespace(NamespaceKey::deployment_default());
    let shards = SinglePartition;
    assert_eq!(shards.ref_shard(&repo, HEAD), expected);
    assert_eq!(shards.ref_shard(&repo, PACKMAP), expected);
    assert_eq!(shards.coordinator(&repo.namespace), expected);
    assert_eq!(shards.ref_index(&repo), expected);
    assert_eq!(shards.membership(&repo, &PackKey::new(A)), expected);
}
