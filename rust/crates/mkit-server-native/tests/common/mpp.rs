//! Shared native M3 lane: production hook configuration and real timer driver.
use mkit_server::hooks::HookSigner;
use mkit_server_conformance::stubs::{hook::HookKey, mpp::MppStub};
use mkit_server_conformance::wire::{Feature, Milestone, Profile, WireAuth, WireTarget, run};
use mkit_server_native::{Shutdown, server};

pub(crate) async fn suite(extra: &[String], filters: &[&str]) {
    let root = super::repo_root();
    let aux = tempfile::tempdir().unwrap();
    let (listener, origin) = super::listener().await;
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).unwrap();
    let signer = HookSigner::new("m3", seed.into()).unwrap();
    let stub = MppStub::start(vec![HookKey::new("m3", signer.public_key())]);
    let hook_key = aux.path().join("hook.key");
    super::secret_file(
        &hook_key,
        format!("m3 {}\n", mkit_core::hash::to_hex(&seed)).as_bytes(),
    );
    let ticket_key = aux.path().join("ticket.key");
    getrandom::fill(&mut seed).unwrap();
    super::secret_file(
        &ticket_key,
        format!("ticket {}\n", mkit_core::hash::to_hex(&seed)).as_bytes(),
    );
    let mut flags: Vec<String> = [
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        super::s(root.path()),
        "--meta",
        &format!("sqlite:{}", root.path().join("meta.db").display()),
        "--sharding",
        "single",
        "--auth",
        "auth-v2",
        "--audience",
        &origin,
        "--repository",
        "default",
        "--hook-admit-url",
        &stub.origin(),
        "--hook-outcome-url",
        &stub.origin(),
        "--hook-key-file",
        super::s(&hook_key),
        "--ticket-key-file",
        super::s(&ticket_key),
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    flags.extend_from_slice(extra);
    let cfg =
        super::resolve_with(&flags.iter().map(String::as_str).collect::<Vec<_>>(), &[]).unwrap();
    let mut opened = server::open(&cfg).unwrap();
    let shutdown = Shutdown::new();
    let timer = opened
        .timers
        .take()
        .unwrap()
        .start(shutdown.clone())
        .await
        .unwrap();
    let task = super::spawn_serve(listener, opened.router.clone(), &shutdown);
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: origin.clone(),
        repository: "default".into(),
        seed: [0x5e; 32],
    });
    profile.milestone = Milestone::M3;
    profile.atomic_advance = true;
    profile.hook_stub = Some(stub.origin().parse().unwrap());
    profile.derive_features();
    profile.features.extend([
        Feature::Admission,
        Feature::HookStub,
        Feature::Tickets,
        Feature::Timers,
    ]);
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    for filter in filters {
        let report = run(&target, Some(filter)).await;
        super::judge(&report, &[]);
        assert!(report.skips().is_empty(), "M3 case unexpectedly skipped");
        assert!(
            !report.tap().contains("Payment "),
            "credentials entered the case report"
        );
    }
    shutdown.trigger();
    task.await.unwrap().unwrap();
    timer.await.unwrap();
}
