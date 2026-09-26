//! Shared by the wire baselines: judge a report against a list of known
//! divergences, and bind a loopback listener.

use mkit_server_conformance::wire::{CASES, Report, Verdict};

/// Pass iff every failed case is listed in `divergences`, and every listed
/// case names a real case and does not pass: a divergence that starts
/// passing must leave the list (it is then fixed, and the suite guards it).
///
/// # Panics
/// With the TAP report, on any violation.
pub(crate) fn judge(report: &Report, divergences: &[(&str, &str)]) {
    let tap = report.tap();
    eprintln!("{tap}");
    for (name, why) in divergences {
        assert!(
            CASES.iter().any(|c| c.name == *name),
            "divergence `{name}` names no case"
        );
        assert!(!why.is_empty(), "divergence `{name}` has no justification");
        // A filtered run need not include it.
        assert!(
            !matches!(report.verdict(name), Some(Verdict::Pass(_))),
            "divergence `{name}` passes now: remove it from the list\n{tap}"
        );
    }
    let unexpected: Vec<_> = report
        .failures()
        .into_iter()
        .filter(|f| !divergences.iter().any(|(n, _)| n == f))
        .collect();
    assert!(
        unexpected.is_empty(),
        "unexpected failures {unexpected:?}\n{tap}"
    );
}

/// `127.0.0.1:0` and its `http://` origin.
pub(crate) async fn listener() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    (listener, origin)
}
