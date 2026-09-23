use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use clap::Args;
use mkit_core::hash::to_hex;
use mkit_core::layout::check_scoped_boundary;
use mkit_core::partial::{
    PartialExchangeContext, PendingOutcomeV1, PendingStatusV1, PublicationOutcome,
    RemotePublicationTargetV1, publish_explicit_update,
};
use mkit_core::protocol::Transport;
use mkit_transport_file::FileTransport;
use serde_json::json;

use super::{OutputFormat, envelope, err, header, open_here, print_json, read_state};
use crate::exit;

#[derive(Debug, Args)]
pub(super) struct PushArgs {
    #[arg(long, value_name = "URL")]
    endpoint: Option<String>,
    #[arg(long, value_name = "NAME")]
    repository: Option<String>,
    #[arg(long = "ref", value_name = "REF")]
    exact_ref: Option<String>,
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,
}

fn parse_file_endpoint(endpoint: &str) -> Result<PathBuf, &'static str> {
    let path = endpoint
        .strip_prefix("mkit+file:///")
        .ok_or("initial scoped publication supports only local mkit+file:/// endpoints")?;
    if path.contains(['?', '#']) {
        return Err("file endpoint cannot have query or fragment");
    }
    let raw = path.as_bytes();
    let mut decoded = Vec::with_capacity(raw.len() + 1);
    decoded.push(b'/');
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            if i + 2 >= raw.len() {
                return Err("invalid file endpoint escape");
            }
            let digit = |b: u8| (b as char).to_digit(16).and_then(|v| u8::try_from(v).ok());
            let (Some(a), Some(b)) = (digit(raw[i + 1]), digit(raw[i + 2])) else {
                return Err("invalid file endpoint escape");
            };
            decoded.push(a << 4 | b);
            i += 3;
        } else {
            decoded.push(raw[i]);
            i += 1;
        }
    }
    if decoded.contains(&0) {
        return Err("file endpoint contains NUL");
    }
    let parsed = PathBuf::from(std::ffi::OsString::from_vec(decoded));
    if parsed
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("file endpoint contains parent traversal");
    }
    Ok(parsed)
}

fn recipient_path(endpoint: &str) -> Result<PathBuf, String> {
    let path = parse_file_endpoint(endpoint).map_err(str::to_owned)?;
    check_scoped_boundary(&path).map_err(|e| format!("recipient scoped boundary: {e}"))?;
    let real = path
        .canonicalize()
        .map_err(|e| format!("recipient path: {e}"))?;
    if !real.is_dir() {
        return Err("file recipient must be an existing directory".to_owned());
    }
    Ok(real)
}

fn selected_target(
    args: &PushArgs,
    pinned: Option<&RemotePublicationTargetV1>,
) -> Result<RemotePublicationTargetV1, String> {
    let count = [
        args.endpoint.is_some(),
        args.repository.is_some(),
        args.exact_ref.is_some(),
    ]
    .into_iter()
    .filter(|v| *v)
    .count();
    if count != 0 && count != 3 {
        return Err("supply --endpoint, --repository and --ref together".to_owned());
    }
    let target = if count == 0 {
        pinned
            .cloned()
            .ok_or_else(|| "first push requires --endpoint, --repository and --ref".to_owned())?
    } else {
        RemotePublicationTargetV1::new(
            args.endpoint.as_deref().unwrap_or_default(),
            args.repository.as_deref().unwrap_or_default(),
            args.exact_ref.as_deref().unwrap_or_default(),
        )
        .map_err(|e| e.to_string())?
    };
    if !target.exact_ref().starts_with("refs/heads/") {
        return Err("scoped publication requires a refs/heads/ branch".to_owned());
    }
    if pinned.is_some_and(|old| old != &target) {
        return Err("publication target differs from the pinned target".to_owned());
    }
    Ok(target)
}

#[allow(
    clippy::too_many_lines,
    reason = "keep the single-attempt publication state sequence visible in one place"
)]
pub(super) fn run(args: &PushArgs) -> u8 {
    let layout = match open_here() {
        Ok(v) => v,
        Err(c) => return c,
    };
    let mut state = match read_state(&layout) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let target = match selected_target(args, state.workspace().target()) {
        Ok(v) => v,
        Err(e) => return err(&e, exit::USAGE),
    };
    let recipient = match recipient_path(target.endpoint()) {
        Ok(v) => v,
        Err(e) => return err(&e, exit::UNAVAILABLE),
    };
    let Some(pending) = state.pending() else {
        return err("no pending candidate to publish", exit::USAGE);
    };
    if !matches!(
        pending.status(),
        PendingStatusV1::Prepared | PendingStatusV1::Exported
    ) {
        return err(
            "pending publication is conflicted or unknown; inspect or explicitly abandon it",
            exit::DATAERR,
        );
    }
    // Cheap read-only eligibility checks keep an obviously missing branch or
    // packmap from consuming the one pending attempt. The publisher repeats
    // both reads and still performs strict Match(base) CAS against races.
    let transport = FileTransport::new(&recipient);
    let branch = target
        .exact_ref()
        .strip_prefix("refs/heads/")
        .expect("target validated");
    let packmap_ref = format!("refs/mkit/packmap/{branch}");
    match transport.read_ref(target.exact_ref()) {
        Ok(Some(head)) if head == *pending.base_id() => {}
        Ok(None) => return err("recipient branch is missing", exit::UNAVAILABLE),
        Ok(Some(_)) => {
            let candidate = *pending.candidate_id();
            let next = match layout.record_outcome(
                state.workspace().transaction_generation(),
                &pending.identity(),
                PendingOutcomeV1::Conflict,
            ) {
                Ok(v) => v,
                Err(e) => {
                    return err(
                        &format!("record definite head conflict: {e}"),
                        exit::DATAERR,
                    );
                }
            };
            match args.format {
                OutputFormat::Human => {
                    header(&next);
                    println!(
                        "Candidate {}: recipient head conflict; draft retained.",
                        to_hex(&candidate)
                    );
                }
                OutputFormat::Json => {
                    let mut output = envelope(&next, "push");
                    output["candidate"] = json!(to_hex(&candidate));
                    output["publication"] = json!("conflict");
                    output["transport_guarantee"] = json!("single-attempt-file-no-durable-results");
                    print_json(&output);
                }
            }
            return exit::GENERAL_ERROR;
        }
        Err(e) => {
            return err(
                &format!("recipient branch preflight: {e}"),
                exit::UNAVAILABLE,
            );
        }
    }
    match transport.read_ref(&packmap_ref) {
        Ok(Some(_)) => {}
        Ok(None) => return err("recipient packmap is missing", exit::UNAVAILABLE),
        Err(e) => {
            return err(
                &format!("recipient packmap preflight: {e}"),
                exit::UNAVAILABLE,
            );
        }
    }
    if pending.operation().is_none() {
        let mut operation_id = [0u8; 32];
        if getrandom::fill(&mut operation_id).is_err() {
            return err("operation ID generation failed", exit::GENERAL_ERROR);
        }
        state = match layout.bind_pending_publication(
            state.workspace().transaction_generation(),
            &pending.identity(),
            target.clone(),
            operation_id,
        ) {
            Ok(v) => v,
            Err(e) => return err(&format!("bind publication: {e}"), exit::DATAERR),
        };
    }
    let pending = state.pending().expect("binding retained pending");
    let identity = pending.identity();
    let bytes = state
        .pending_update_bytes()
        .expect("verified pending bytes")
        .to_vec();
    let operation = pending.operation().expect("binding pinned operation");
    let context = PartialExchangeContext::bind(
        target.repository(),
        target.exact_ref(),
        operation.operation_id,
        *pending.base_id(),
        &bytes,
    );
    if context.update_digest != *pending.update_digest()
        || context.update_length != pending.update_length()
    {
        return err("pending publication context mismatch", exit::DATAERR);
    }
    state = match layout.begin_publication(state.workspace().transaction_generation(), &identity) {
        Ok(v) => v,
        Err(e) => return err(&format!("begin publication: {e}"), exit::DATAERR),
    };
    let result = publish_explicit_update(&transport, &bytes, state.workspace().limits(), &context);
    let outcome = match result {
        Ok(PublicationOutcome::Published) => PendingOutcomeV1::Accepted,
        Ok(PublicationOutcome::HeadConflict) => PendingOutcomeV1::Conflict,
        Ok(other) => {
            return err(
                &format!("publication outcome {other:?}; pending result remains unknown"),
                exit::UNAVAILABLE,
            );
        }
        Err(e) => {
            return err(
                &format!("publication failed: {e}; pending result remains unknown"),
                exit::DATAERR,
            );
        }
    };
    let next = match layout.record_outcome(
        state.workspace().transaction_generation(),
        &identity,
        outcome,
    ) {
        Ok(v) => v,
        Err(e) => {
            return err(
                &format!(
                    "remote result was {outcome:?}, but local outcome persistence failed: {e}; inspect pending state"
                ),
                exit::GENERAL_ERROR,
            );
        }
    };
    match args.format {
        OutputFormat::Human => {
            header(&next);
            println!(
                "Candidate {}: {}. File transport has no durable result ledger.",
                to_hex(identity.candidate_id()),
                if outcome == PendingOutcomeV1::Accepted {
                    "published"
                } else {
                    "head conflict"
                }
            );
        }
        OutputFormat::Json => {
            let mut output = envelope(&next, "push");
            output["candidate"] = json!(to_hex(identity.candidate_id()));
            output["publication"] = json!(if outcome == PendingOutcomeV1::Accepted {
                "accepted"
            } else {
                "conflict"
            });
            output["transport_guarantee"] = json!("single-attempt-file-no-durable-results");
            output["target"] = json!({"endpoint":target.endpoint(), "repository":target.repository(), "ref":target.exact_ref()});
            print_json(&output);
        }
    }
    if outcome == PendingOutcomeV1::Accepted {
        exit::OK
    } else {
        exit::GENERAL_ERROR
    }
}

#[cfg(test)]
mod tests {
    use super::parse_file_endpoint;

    #[test]
    fn file_endpoint_requires_local_absolute_path_without_traversal() {
        assert_eq!(
            parse_file_endpoint("mkit+file:///tmp/with%20space")
                .unwrap()
                .to_str(),
            Some("/tmp/with space")
        );
        for invalid in [
            "https://example.test/repo",
            "mkit+file://example.test/repo",
            "mkit+file:///tmp/../repo",
            "mkit+file:///tmp/%2e%2e/repo",
            "mkit+file:///tmp/repo?branch=main",
            "mkit+file:///tmp/repo#fragment",
            "mkit+file:///tmp/%00repo",
            "mkit+file:///tmp/%xx",
        ] {
            assert!(parse_file_endpoint(invalid).is_err(), "{invalid}");
        }
    }
}
