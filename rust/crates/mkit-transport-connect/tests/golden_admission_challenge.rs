//! The native client's vendored proto must decode the server's STC §5.1 golden.

use std::fs;
use std::path::Path;

use buffa::Message;
use mkit_transport_connect::generated::AdmissionChallenge;

#[test]
fn client_decodes_admission_challenge_golden() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/transport/admission-challenge.bin");
    let message = AdmissionChallenge::decode_from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(message.challenges.len(), 2);
    assert_eq!(message.challenges[0].scheme.as_deref(), Some("mpp"));
    assert_eq!(
        message.challenges[0].value.as_deref(),
        Some(
            "Payment id=\"fake-example-not-valid\", method=\"tempo\", intent=\"charge\", request=\"fake-example-request-not-valid\""
        )
    );
    assert_eq!(message.challenges[1].scheme.as_deref(), Some("x402"));
    assert_eq!(
        message.challenges[1].value.as_deref(),
        Some("fake-example-payment-required-not-valid")
    );
    assert_eq!(
        message.description.as_deref(),
        Some("Example upload payment required.")
    );
}
