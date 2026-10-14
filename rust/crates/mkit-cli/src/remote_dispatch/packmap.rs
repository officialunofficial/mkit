//! CLI configuration of the packmap rollover policy.
/// Default chain depth at which a push re-baselines: resets the packlist
/// chain to a single fresh self-contained node instead of appending to it
/// (#406). Bounds clone cost, which otherwise grows with the chain length
/// (one node walked/downloaded per push since the last re-baseline).
/// Overridable via `MKIT_PACK_REBASELINE_DEPTH` for tests; `0` disables
/// re-baselining entirely.
const DEFAULT_REBASELINE_DEPTH: usize = 64;

/// Resolve the configured re-baseline threshold: the `MKIT_PACK_REBASELINE_DEPTH`
/// environment variable if present and parsable, else [`DEFAULT_REBASELINE_DEPTH`].
/// A value of `0` disables re-baselining (the push path never forces a
/// full-closure reset on depth alone).
pub(crate) fn rebaseline_depth() -> usize {
    let (depth, warning) = configured_depth();
    if let Some(warning) = warning {
        eprintln!("{warning}");
    }
    depth
}

pub(crate) fn configured_depth() -> (usize, Option<String>) {
    match std::env::var("MKIT_PACK_REBASELINE_DEPTH") {
        Err(_) => (DEFAULT_REBASELINE_DEPTH, None),
        Ok(s) => match s.parse::<usize>() {
            Ok(depth) => (depth, None),
            Err(_) => (
                DEFAULT_REBASELINE_DEPTH,
                Some(format!(
                    "warning: MKIT_PACK_REBASELINE_DEPTH='{s}' is not a valid non-negative integer; using the default {DEFAULT_REBASELINE_DEPTH} (set it to 0 to disable re-baselining)"
                )),
            ),
        },
    }
}
