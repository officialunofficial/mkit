//! Shared native M3 lane: production hook configuration and real timer driver.
use mkit_server::hooks::HookSigner;
use mkit_server_conformance::stubs::{hook::HookKey, mpp::MppStub};
use mkit_server_conformance::wire::{Feature, Milestone, Profile, WireAuth, WireTarget, run};
use mkit_server_native::{Shutdown, server};

pub(crate) async fn suite(extra: &[String], filters: &[&str]) {
    suite_with(extra, filters, &[], false).await;
}
#[allow(clippy::too_many_lines)] // Shared real-adapter setup and owned teardown.
pub(crate) async fn suite_with(
    extra: &[String],
    filters: &[&str],
    vars: &[(&str, &str)],
    binary: bool,
) {
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
        "--cors-allow-origin",
        "*",
        "--auth",
        "auth-v2",
        "--audience",
        &origin,
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
    if !extra.iter().any(|s| s == "multi") {
        flags.extend(["--repository".into(), "default".into()]);
    }
    flags.extend_from_slice(extra);
    let mut cfg =
        super::resolve_with(&flags.iter().map(String::as_str).collect::<Vec<_>>(), vars).unwrap();
    if !binary {
        cfg.pipeline.ticket_ttl_ms = 10_000;
        cfg.pipeline.outbox_backlog_cap = Some(mkit_server::pipeline::OutboxBacklogCap {
            rows: 16,
            bytes: u64::MAX,
        });
    }
    let shutdown = Shutdown::new();
    let mut opened = (!binary).then(|| server::open(&cfg).unwrap());
    let timer = if let Some(opened) = opened.as_mut() {
        Some(
            opened
                .timers
                .take()
                .unwrap()
                .start(shutdown.clone())
                .await
                .unwrap(),
        )
    } else {
        None
    };
    let mut child = None;
    let task = if binary {
        drop(listener);
        origin
            .trim_start_matches("http://")
            .clone_into(&mut flags[1]);
        child = Some(OwnedChild(
            std::process::Command::new(env!("CARGO_BIN_EXE_mkit-server"))
                .arg("serve")
                .args(&flags)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        ));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::net::TcpStream::connect(&flags[1]).is_err() {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        None
    } else {
        Some(super::spawn_serve(
            listener,
            opened.as_ref().unwrap().router.clone(),
            &shutdown,
        ))
    };
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: origin.clone(),
        repository: "default".into(),
        seed: [0x5e; 32],
    });
    if extra.iter().any(|s| s == "multi") {
        profile.features.insert(Feature::MultiRepo);
    }
    if !binary {
        profile.backlog_cap = Some(16);
        profile
            .features
            .extend([Feature::ShortTickets, Feature::BacklogCap]);
    }
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
        assert!(
            report.skips().is_empty(),
            "M3 case unexpectedly skipped\n{}",
            report.tap()
        );
        assert!(
            !report.tap().contains("Payment "),
            "credentials entered the case report"
        );
    }
    shutdown.trigger();
    if let Some(task) = task {
        task.await.unwrap().unwrap();
    }
    if let Some(mut child) = child {
        child.0.kill().unwrap();
        child.0.wait().unwrap();
    }
    if let Some(timer) = timer {
        timer.await.unwrap();
    }
}

struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
