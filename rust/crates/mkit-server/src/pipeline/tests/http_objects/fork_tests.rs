//! A forked manifest is served once the remix publishes: the fork copied its
//! holder row, so the extracted copy is the destination's own.
use super::*;
use crate::fork::{ForkEnv, ForkLimits, ForkSpec, Phase, StartOutcome};

#[test]
fn a_forked_manifest_is_served_after_the_remix_publishes() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.takedown_denial = true;
        cfg.sharding = Sharding::D34;
    });
    let d = data();
    let pack = fx.push("room", &d.refs(), d.head(), None);
    drain_relays(&fx, "room");
    let packmap = hash(&mkit_core::transfer::encode_packlist(None, &[pack]).unwrap());
    let dest = fx.repo_id("forked");
    let env = ForkEnv {
        store: &fx.pipe.meta,
        shards: fx.pipe.shards.as_ref(),
        clock: fx.pipe.clock.as_ref(),
        takedown_denial: true,
        extract_min_bytes: Some(EXTRACT_MIN),
        limits: ForkLimits::default(),
    };
    let spec = ForkSpec {
        source: fx.repo_id("room"),
        source_ref: HEAD.into(),
        expected_tip: d.head(),
        dest: dest.clone(),
        dest_visibility: mkit_attest::grant::Visibility::Public,
    };
    let started = block_on(crate::fork::start(&env, &spec, None)).unwrap();
    assert!(matches!(started, StartOutcome::Started(_)));
    let budget = crate::budget::SliceBudget::new(600);
    let job = loop {
        let report = block_on(crate::fork::step(&env, &dest, &budget)).unwrap();
        if report.job.finished() {
            break report.job;
        }
    };
    assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
    // Holders are written before completion; the objects are not readable
    // until a ref publishes them.
    assert!(fx.holder("forked", &id(&d.manifest)).is_some());
    assert!(fx.holder("forked", &id(&d.big)).is_some());
    assert_eq!(
        fx.get(&fx.object_url("forked", &id(&d.manifest))).status,
        404
    );
    // The remix: one commit on the inherited root tree, chained to the
    // inherited packmap.
    let remix = commit(&d.root, &[], "remix");
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(remix.id().unwrap(), &serialize(&remix).unwrap())
        .unwrap();
    let (outcome, _) = fx.push_pack_on(
        "forked",
        &writer.finish().unwrap(),
        (HEAD, PACKMAP),
        id(&remix),
        (Missing, Missing),
        Some(packmap),
    );
    assert_eq!(outcome, AdvanceOutcome::Committed);
    drain_relays(&fx, "forked");
    // A manifest Cat: the reassembled content, byte for byte, from the
    // destination's own holder.
    let got = fx.get(&fx.object_url("forked", &id(&d.manifest)));
    assert_eq!(got.status, 200);
    assert_eq!(got.body, d.whole());
    assert_eq!(got.header("X-Mkit-Object-Type"), Some("chunked_blob"));
    let by_path = fx.get(&fx.ref_url("forked", "main", "chunked.bin"));
    assert_eq!(by_path.status, 200);
    assert_eq!(by_path.body, d.whole());
    // The extracted file blob and an inherited tree serve too.
    assert_eq!(
        fx.get(&fx.object_url("forked", &id(&d.big))).body,
        d.big_bytes
    );
    assert_eq!(fx.get(&fx.object_url("forked", &id(&d.root))).status, 200);
}

/// Deliver the relayed membership rows of `name`'s ref shard.
fn drain_relays<H: HookSet>(fx: &Fx<H>, name: &str) {
    let repo = fx.repo_id(name);
    let registry = crate::timers::TimerRegistry::new().register(crate::relay::RelayHandler {
        target: crate::store::BorrowedStore(&fx.pipe.meta),
        hook: crate::relay::NoHook,
        budget: crate::relay::RelayBudget::default(),
    });
    let source = fx.pipe.shards.ref_shard(&repo, HEAD);
    for _ in 0..8 {
        block_on(crate::timers::run_due(
            &fx.pipe.meta,
            &source,
            &registry,
            fx.clock.as_ref(),
            u64::try_from(fx.clock.now_ms()).unwrap(),
            &crate::timers::TickBudget::default(),
        ))
        .unwrap();
        fx.clock.advance(1000);
    }
}

/// A start carrying a replay record, as the request pipeline hands it:
/// `expires_at_ms` is the signed envelope's expiry. The timer still arms at
/// job creation — the request's bounded lifetime does not defer it.
fn replay_settle(dest: &RepoId, expires_at_ms: i64) -> crate::fork::SettleV1 {
    crate::fork::SettleV1 {
        rid: String::new(),
        pending: Vec::new(),
        repository: format!("{}/{}", dest.namespace.as_str(), dest.name.as_str()),
        replay: Some(crate::fork::ReplayV1 {
            scope: hash(b"replay scope"),
            fingerprint: hash(b"request fingerprint"),
            expires_at_ms,
        }),
        charges: Vec::new(),
        namespace_cap: None,
        declared_bytes: u64::MAX,
    }
}

/// One tick of the destination coordinator's timers through the real kind-16
/// handler; returns the report so callers can assert on `fired`.
fn fork_tick<H: HookSet>(fx: &Fx<H>, dest: &RepoId) -> crate::timers::RunReport {
    let registry = crate::timers::TimerRegistry::new().register(crate::fork::ForkTimer {
        store: crate::store::BorrowedStore(&fx.pipe.meta),
        shards: fx.pipe.shards.clone(),
        clock: fx.clock.clone(),
        takedown_denial: true,
        extract_min_bytes: Some(EXTRACT_MIN),
    });
    block_on(crate::timers::run_due(
        &fx.pipe.meta,
        &fx.pipe.shards.coordinator(&dest.namespace),
        &registry,
        fx.clock.as_ref(),
        u64::try_from(fx.clock.now_ms()).unwrap(),
        &crate::timers::TickBudget::default(),
    ))
    .unwrap()
}

/// The job row of `dest`, decoded.
fn fork_job<H: HookSet>(fx: &Fx<H>, dest: &RepoId) -> crate::fork::ForkJobV1 {
    let p = fx.pipe.shards.coordinator(&dest.namespace);
    let raw = block_on(fx.pipe.meta.get(&p, &keys::fork_job(&dest.name)))
        .unwrap()
        .unwrap();
    crate::fork::decode_job(&raw).unwrap()
}

/// The due time of the destination's fork timer row, if it still has one.
fn fork_timer_due<H: HookSet>(fx: &Fx<H>, dest: &RepoId) -> Option<u64> {
    let p = fx.pipe.shards.coordinator(&dest.namespace);
    let (start, end) = keys::class_range(keys::TAG_TIMER);
    let page = block_on(fx.pipe.meta.scan(&p, &start, &end, None, 100)).unwrap();
    page.entries
        .iter()
        .find_map(|(key, _)| match keys::parse(key) {
            Some(keys::ParsedKey::Timer {
                due_at_ms, kind, ..
            }) if kind == crate::timers::registry::kinds::FORK.get() => Some(due_at_ms),
            _ => None,
        })
}

/// A fork's kind-16 timer row arms at job creation — the alarm is a second
/// driver from t=0, the behavior `fork_step` events measure — whether or
/// not the start carries a replay record.
#[test]
fn fork_timer_arms_at_job_creation() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.takedown_denial = true;
        cfg.sharding = Sharding::D34;
    });
    let d = data();
    let _ = fx.push("room", &d.refs(), d.head(), None);
    drain_relays(&fx, "room");
    let env = ForkEnv {
        store: &fx.pipe.meta,
        shards: fx.pipe.shards.as_ref(),
        clock: fx.clock.as_ref(),
        takedown_denial: true,
        extract_min_bytes: Some(EXTRACT_MIN),
        limits: ForkLimits::default(),
    };
    let now = u64::try_from(fx.clock.now_ms()).unwrap();
    let expiry = now + 240_000;
    let dest = fx.repo_id("armed");
    let spec = ForkSpec {
        source: fx.repo_id("room"),
        source_ref: HEAD.into(),
        expected_tip: d.head(),
        dest: dest.clone(),
        dest_visibility: mkit_attest::grant::Visibility::Public,
    };
    let settle = replay_settle(&dest, i64::try_from(expiry).unwrap());
    let started = block_on(crate::fork::start(&env, &spec, Some(settle))).unwrap();
    assert!(matches!(started, StartOutcome::Started(_)));
    // The envelope expiry does not defer the timer: due is creation time.
    assert_eq!(fork_timer_due(&fx, &dest), Some(now));

    let plain = fx.repo_id("plain");
    let started = block_on(crate::fork::start(
        &env,
        &ForkSpec {
            dest: plain.clone(),
            ..spec
        },
        None,
    ))
    .unwrap();
    assert!(matches!(started, StartOutcome::Started(_)));
    assert_eq!(fork_timer_due(&fx, &plain), Some(now));
}

/// A request that finishes the job leaves the timer row behind; its one
/// fire is a no-op `Done` that deletes the row, never a double commit.
#[test]
fn a_finished_fork_leaves_one_stale_timer_fire() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.takedown_denial = true;
        cfg.sharding = Sharding::D34;
    });
    let d = data();
    let _ = fx.push("room", &d.refs(), d.head(), None);
    drain_relays(&fx, "room");
    let env = ForkEnv {
        store: &fx.pipe.meta,
        shards: fx.pipe.shards.as_ref(),
        clock: fx.clock.as_ref(),
        takedown_denial: true,
        extract_min_bytes: Some(EXTRACT_MIN),
        limits: ForkLimits::default(),
    };
    let now = u64::try_from(fx.clock.now_ms()).unwrap();
    let dest = fx.repo_id("stale");
    let spec = ForkSpec {
        source: fx.repo_id("room"),
        source_ref: HEAD.into(),
        expected_tip: d.head(),
        dest: dest.clone(),
        dest_visibility: mkit_attest::grant::Visibility::Public,
    };
    block_on(crate::fork::start(&env, &spec, None)).unwrap();
    // The request driver takes the job to Done before the timer ticks.
    let budget = crate::budget::SliceBudget::new(600);
    loop {
        let report = block_on(crate::fork::step(&env, &dest, &budget)).unwrap();
        if report.job.finished() {
            break;
        }
    }
    assert_eq!(fork_job(&fx, &dest).phase, Phase::Done);
    // The timer is still armed: nothing deleted it at completion.
    assert_eq!(fork_timer_due(&fx, &dest), Some(now));
    // Its one fire sees Done and consumes the row.
    let _ = fork_tick(&fx, &dest);
    assert!(
        fork_timer_due(&fx, &dest).is_none(),
        "fire consumed the row"
    );
    let _ = fork_tick(&fx, &dest);
    assert!(
        fork_timer_due(&fx, &dest).is_none(),
        "at most one stale fire"
    );
    assert_eq!(fork_job(&fx, &dest).phase, Phase::Done);
}

/// A request that dies leaves the job to the timer, whose slices resume it
/// mid-flight and drive it over more than one slice to `Done`.
#[test]
fn a_dead_request_is_resumed_by_the_alarm() {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| {
        cfg.takedown_denial = true;
        cfg.sharding = Sharding::D34;
    });
    let d = data();
    let _ = fx.push("room", &d.refs(), d.head(), None);
    drain_relays(&fx, "room");
    let env = ForkEnv {
        store: &fx.pipe.meta,
        shards: fx.pipe.shards.as_ref(),
        clock: fx.clock.as_ref(),
        takedown_denial: true,
        extract_min_bytes: Some(EXTRACT_MIN),
        limits: ForkLimits::default(),
    };
    let dest = fx.repo_id("orphaned");
    let spec = ForkSpec {
        source: fx.repo_id("room"),
        source_ref: HEAD.into(),
        expected_tip: d.head(),
        dest: dest.clone(),
        dest_visibility: mkit_attest::grant::Visibility::Public,
    };
    block_on(crate::fork::start(&env, &spec, None)).unwrap();
    // The request ran one short slice before dying, leaving the job
    // mid-flight: the resume covers a fork over more than one slice.
    let partial = crate::budget::SliceBudget::new(60);
    let report = block_on(crate::fork::step(&env, &dest, &partial)).unwrap();
    assert!(!report.job.finished());
    // The timer was due at creation: alarm ticks drive the job to Done.
    for _ in 0..8 {
        let _ = fork_tick(&fx, &dest);
        if fork_job(&fx, &dest).phase == Phase::Done {
            break;
        }
        fx.clock.advance(1_000);
    }
    assert_eq!(fork_job(&fx, &dest).phase, Phase::Done);
    assert!(fork_timer_due(&fx, &dest).is_none());
}
