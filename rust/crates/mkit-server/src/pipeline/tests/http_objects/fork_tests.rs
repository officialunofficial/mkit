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
