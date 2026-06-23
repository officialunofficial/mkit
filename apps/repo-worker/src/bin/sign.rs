// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Dev-only signing helper + conformance client. Given a procedure and a raw
// request body (the exact bytes that will be sent on the wire — JSON for a
// Connect-JSON call), it prints the write-envelope headers a client must
// attach. Run on the host (NOT compiled into the wasm worker).
//
//   cargo run --bin sign -- <procedure> <body-json> [idempotency-key] [seed-hex]
//
// e.g.
//   cargo run --bin sign -- /mkit.repo.v1.RepoService/UpdateRef \
//       '{"room":"demo","name":"refs/heads/main","newId":"...","expectation":"REF_EXPECTATION_ANY"}'
//
// Emits `-H 'X-...: ...'` curl flags on stdout. The seed defaults to 32 bytes
// of 0x07 (the deterministic test signer) so output is reproducible.

use ed25519_dalek::{Signer, SigningKey};
use mkit_repo_worker::envelope::envelope_signing_digest;
use mkit_repo_worker::hashing::blake3_hex;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // `sign b3 <utf8>` prints the lowercase-hex BLAKE3 of the given string —
    // handy for deriving a PutObject object_id in conformance scripts.
    if args.get(1).map(String::as_str) == Some("b3") {
        let data = args.get(2).cloned().unwrap_or_default();
        println!("{}", blake3_hex(data.as_bytes()));
        return;
    }
    if args.len() < 3 {
        eprintln!(
            "usage: sign <procedure> <body> [idempotency-key] [seed-hex]\n\
             prints the X-* envelope headers as curl -H flags"
        );
        std::process::exit(2);
    }
    let procedure = &args[1];
    let body = &args[2];
    let idem = args.get(3).cloned().unwrap_or_default();
    let seed_hex = args.get(4).cloned().unwrap_or_else(|| "07".repeat(32));

    let seed: [u8; 32] = {
        let mut s = [0u8; 32];
        hex::decode_to_slice(&seed_hex, &mut s).expect("seed must be 64-hex");
        s
    };
    let sk = SigningKey::from_bytes(&seed);
    let pubkey = hex::encode(sk.verifying_key().to_bytes());

    // X-Digest = BLAKE3(raw body bytes) — the bytes that go on the wire.
    let body_digest = blake3_hex(body.as_bytes());
    let created_at: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let digest = envelope_signing_digest(procedure, &body_digest, created_at, &idem);
    let signature = hex::encode(sk.sign(&digest).to_bytes());

    // Emit curl -H flags.
    print!(
        "-H 'X-Public-Key: {pubkey}' \
-H 'X-Signature: {signature}' \
-H 'X-Digest: {body_digest}' \
-H 'X-Created-At: {created_at}'"
    );
    if !idem.is_empty() {
        print!(" -H 'Idempotency-Key: {idem}'");
    }
    println!();
}
