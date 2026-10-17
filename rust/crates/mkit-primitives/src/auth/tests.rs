use super::*;
use ed25519_dalek::{Signer, SigningKey};
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use mkit_core::write_auth::Operation;
use serde_json::Value;

fn headers(f: &Value) -> Headers {
    let text = |key: &str| f[key].as_str().map(str::to_owned);
    Headers {
        version: Some("2".into()),
        audience: text("audience"),
        repository: text("repository"),
        public_key: text("public_key"),
        signature: text("signature"),
        digest: text("body_digest"),
        commitment: text("commitment"),
        created_at: Some(f["created_at"].as_i64().unwrap().to_string()),
        expires_at: Some(f["expires_at"].as_i64().unwrap().to_string()),
        idempotency_key: text("nonce"),
    }
}

fn parity(h: &Headers, ctx: Context<'_>, path: &str, expected: ExpectedCommitment<'_>, now: i64) {
    let old = write_auth::verify_headers_with(ctx, path, expected, now, h);
    let new = validate_envelope(h, ctx, path, expected, now);
    match (old, new) {
        (Ok(old), Ok(new)) => {
            assert_eq!(new.authorized(), &old);
            assert_eq!(to_hex(new.signer()), old.public_key);
            assert_eq!(to_hex(new.replay_scope()), old.scope);
            assert_eq!(to_hex(new.fingerprint()), old.fingerprint);
            assert_eq!(new.commitment(), old.content_commitment().unwrap());
            assert_eq!(
                new.created_at_ms().to_string(),
                h.created_at.as_deref().unwrap()
            );
            assert_eq!(new.expires_at_ms(), old.expires_at);
        }
        (Err(old), Err(new)) => {
            assert_eq!(old.0, new.reason());
            assert_eq!(new.code(), FailureCode::InvalidEnvelope);
        }
        (old, new) => panic!("validator parity failed: {old:?} vs {new:?}"),
    }
}

#[test]
fn canonical_shared_read_write_and_part_vectors() {
    let mut fixtures = vec![
        serde_json::from_str::<Value>(include_str!("../../fixtures/auth/unary.json")).unwrap(),
    ];
    fixtures.extend(
        serde_json::from_str::<Vec<Value>>(include_str!("../../fixtures/auth/read.json")).unwrap(),
    );
    fixtures.push(serde_json::from_str(include_str!("../../fixtures/auth/part.json")).unwrap());
    for f in fixtures {
        let h = headers(&f);
        let ctx = Context {
            audience: f["audience"].as_str().unwrap(),
            repository: f["repository"].as_str().unwrap(),
        };
        let path = f["procedure"].as_str().unwrap();
        let commitment = f["commitment"].as_str().unwrap();
        let expected = if commitment.starts_with("part:") {
            ExpectedCommitment::PartStream
        } else {
            ExpectedCommitment::Exact(commitment)
        };
        let created = f["created_at"].as_i64().unwrap();
        let expires = f["expires_at"].as_i64().unwrap();
        let operation = Operation {
            context: ctx,
            procedure: path,
            commitment,
            created_at: created,
            expires_at: expires,
            nonce: f["nonce"].as_str().unwrap(),
        };
        assert_eq!(
            operation.canonical().unwrap(),
            f["canonical"].as_str().unwrap()
        );
        assert_eq!(
            to_hex(&operation.digest().unwrap()),
            f["signing_digest"].as_str().unwrap()
        );
        assert_eq!(
            operation
                .canonical()
                .unwrap()
                .bytes()
                .filter(|b| *b == b'\n')
                .count(),
            7
        );
        assert!(!operation.canonical().unwrap().ends_with('\n'));
        for (now, accepted) in [
            (created - 30_001, false),
            (created - 30_000, true),
            (created, true),
            (expires, true),
            (expires + 1, false),
            (-1, false),
        ] {
            assert_eq!(
                validate_envelope(&h, ctx, path, expected, now).is_ok(),
                accepted,
                "{path} at {now}"
            );
            parity(&h, ctx, path, expected, now);
        }
    }
}

#[test]
fn raw_input_mutations_preserve_reference_failure_precedence() {
    let f: Value = serde_json::from_str(include_str!("../../fixtures/auth/unary.json")).unwrap();
    let good = headers(&f);
    let ctx = Context {
        audience: f["audience"].as_str().unwrap(),
        repository: f["repository"].as_str().unwrap(),
    };
    let path = f["procedure"].as_str().unwrap();
    let expected = ExpectedCommitment::Exact(f["commitment"].as_str().unwrap());
    let now = f["created_at"].as_i64().unwrap();
    for index in 0..10 {
        for value in [
            None,
            Some(String::new()),
            Some(" ".into()),
            Some("\n".into()),
            Some("+1".into()),
            Some("01".into()),
            Some("18446744073709551616".into()),
        ] {
            let mut h = good.clone();
            let fields = [
                &mut h.version,
                &mut h.audience,
                &mut h.repository,
                &mut h.public_key,
                &mut h.signature,
                &mut h.digest,
                &mut h.commitment,
                &mut h.created_at,
                &mut h.expires_at,
                &mut h.idempotency_key,
            ];
            *fields.into_iter().nth(index).unwrap() = value;
            assert!(validate_envelope(&h, ctx, path, expected, now).is_err());
            parity(&h, ctx, path, expected, now);
        }
    }
    for (audience, repository, procedure) in [
        ("https://other.test", ctx.repository, path),
        (ctx.audience, "other", path),
        (ctx.audience, ctx.repository, "/other/Read"),
    ] {
        assert!(
            validate_envelope(
                &good,
                Context {
                    audience,
                    repository
                },
                procedure,
                expected,
                now
            )
            .is_err()
        );
        parity(
            &good,
            Context {
                audience,
                repository,
            },
            procedure,
            expected,
            now,
        );
    }
    for path in ["", "not/a/path", "/with space", "/with\nnewline"] {
        assert!(validate_envelope(&good, ctx, path, expected, now).is_err());
        parity(&good, ctx, path, expected, now);
    }
}

fn signed(operation: Operation<'_>) -> Headers {
    let key = SigningKey::from_bytes(&[7; 32]);
    let digest = operation.digest().unwrap();
    Headers {
        version: Some("2".into()),
        audience: Some(operation.context.audience.into()),
        repository: Some(operation.context.repository.into()),
        public_key: Some(to_hex_bytes(&key.verifying_key().to_bytes())),
        signature: Some(to_hex_bytes(&key.sign(&digest).to_bytes())),
        digest: operation
            .commitment
            .strip_prefix("body:")
            .map(str::to_owned),
        commitment: Some(operation.commitment.into()),
        created_at: Some(operation.created_at.to_string()),
        expires_at: Some(operation.expires_at.to_string()),
        idempotency_key: Some(operation.nonce.into()),
    }
}

#[test]
fn stream_digest_values_preserve_core_acceptance() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../fixtures/auth/part.json")).unwrap();
    let pack = format!("pack:{}:12", "cd".repeat(32));
    for (commitment, path, expected) in [
        (
            pack.as_str(),
            "/mkit.transport.v1.TransportService/UploadPack",
            ExpectedCommitment::PackStream,
        ),
        (
            fixture["commitment"].as_str().unwrap(),
            fixture["procedure"].as_str().unwrap(),
            ExpectedCommitment::PartStream,
        ),
    ] {
        let operation = Operation {
            context: Context {
                audience: fixture["audience"].as_str().unwrap(),
                repository: fixture["repository"].as_str().unwrap(),
            },
            procedure: path,
            commitment,
            created_at: fixture["created_at"].as_i64().unwrap(),
            expires_at: fixture["expires_at"].as_i64().unwrap(),
            nonce: fixture["nonce"].as_str().unwrap(),
        };
        let mut h = signed(operation);
        let baseline = validate_envelope(
            &h,
            operation.context,
            path,
            expected,
            operation.created_at,
        )
        .unwrap();
        for digest in [None, Some(""), Some("garbage"), Some("AA")] {
            h.digest = digest.map(str::to_owned);
            let mut counts = [1; 10];
            counts[5] = usize::from(digest.is_some());
            assert_eq!(
                inspect_headers(&counts, false).unwrap(),
                EnvelopePresence::Present
            );
            assert_eq!(
                validate_envelope(&h, operation.context, path, expected, operation.created_at)
                    .unwrap(),
                baseline
            );
            parity(&h, operation.context, path, expected, operation.created_at);
        }
    }
}

#[test]
fn component_and_validity_boundaries_use_core_rules() {
    let nonce = "ab".repeat(32);
    let repo = "r".repeat(255);
    let path = format!("/{}", "p".repeat(511));
    // Core's canonical-origin grammar accepts a nonempty lowercase host with
    // no DNS-label length rule; preserve that exact component ceiling.
    let audience = format!("https://{}", "a".repeat(504));
    let body = format!("body:{}", to_hex(&hash(b"body")));
    let operation = Operation {
        context: Context {
            audience: &audience,
            repository: &repo,
        },
        procedure: &path,
        commitment: &body,
        created_at: i64::MAX - 300_000,
        expires_at: i64::MAX,
        nonce: &nonce,
    };
    let h = signed(operation);
    assert!(
        validate_envelope(
            &h,
            operation.context,
            &path,
            ExpectedCommitment::Exact(&body),
            i64::MAX
        )
        .is_ok()
    );
    for field in ["audience", "repository", "procedure"] {
        let mut h = h.clone();
        let longer_path = format!("{path}p");
        let (ctx, p) = match field {
            "audience" => {
                h.audience.as_mut().unwrap().push('a');
                (operation.context, path.as_str())
            }
            "repository" => {
                h.repository.as_mut().unwrap().push('r');
                (operation.context, path.as_str())
            }
            _ => (operation.context, longer_path.as_str()),
        };
        parity(&h, ctx, p, ExpectedCommitment::Exact(&body), i64::MAX);
        assert!(validate_envelope(&h, ctx, p, ExpectedCommitment::Exact(&body), i64::MAX).is_err());
    }
    for (created, expires, accepted) in [
        (0, 1, true),
        (0, 300_000, true),
        (0, 300_001, false),
        (-1, 1, false),
        (1, 1, false),
        (2, 1, false),
    ] {
        let op = Operation {
            created_at: created,
            expires_at: expires,
            ..operation
        };
        assert_eq!(op.canonical().is_ok(), accepted);
        if accepted {
            let h = signed(op);
            assert!(
                validate_envelope(
                    &h,
                    op.context,
                    &path,
                    ExpectedCommitment::Exact(&body),
                    created
                )
                .is_ok()
            );
        }
    }
}

#[test]
fn stream_decimal_boundaries_use_core_rules() {
    let nonce = "ab".repeat(32);
    let path = "/service/Upload".to_owned();
    let body = format!("body:{}", to_hex(&hash(b"body")));
    let operation = Operation {
        context: Context {
            audience: "https://example.test",
            repository: "repo",
        },
        procedure: &path,
        commitment: &body,
        created_at: i64::MAX - 300_000,
        expires_at: i64::MAX,
        nonce: &nonce,
    };
    for commitment in [
        format!("pack:{}:{}", "ab".repeat(32), u64::MAX),
        format!(
            "part:{}:{}:{}:{}",
            "ab".repeat(32),
            u32::MAX,
            "cd".repeat(32),
            u64::MAX
        ),
    ] {
        let op = Operation {
            commitment: &commitment,
            ..operation
        };
        let h = signed(op);
        let expected = if commitment.starts_with("part:") {
            ExpectedCommitment::PartStream
        } else {
            ExpectedCommitment::PackStream
        };
        assert!(validate_envelope(&h, op.context, &path, expected, i64::MAX).is_ok());
        parity(&h, op.context, &path, expected, i64::MAX);
    }
    for commitment in [
        format!("pack:{}:01", "ab".repeat(32)),
        format!("pack:{}:18446744073709551616", "ab".repeat(32)),
        format!("part:{}:4294967296:{}:1", "ab".repeat(32), "cd".repeat(32)),
        format!("part:{}:0:{}:0", "ab".repeat(32), "cd".repeat(32)),
    ] {
        assert!(ContentCommitment::parse(&commitment).is_err());
        let mut h = signed(operation);
        h.commitment = Some(commitment.clone());
        let expected = if commitment.starts_with("part:") {
            ExpectedCommitment::PartStream
        } else {
            ExpectedCommitment::PackStream
        };
        parity(&h, operation.context, &path, expected, i64::MAX);
        assert_eq!(
            validate_envelope(&h, operation.context, &path, expected, i64::MAX)
                .unwrap_err()
                .code(),
            FailureCode::InvalidEnvelope
        );
    }
}

#[test]
fn seeded_claims_binding_matches_independent_reference_predicate() {
    // Fixed-seed bounded fuzz body: no host token format or secret enters it.
    let mut seed = 0x6a09_e667_f3bc_c909_u64;
    for case in 0..4096 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let bits = seed.to_le_bytes();
        let signer = [bits[0]; 32];
        let other_signer = [bits[0] ^ 1; 32];
        let pack = [bits[1]; 32];
        let other_pack = [bits[1] ^ 1; 32];
        let claims = ClaimsPrincipal {
            audience: "https://example.test",
            repository: "repo",
            signer: &signer,
        };
        let request = ClaimsPrincipal {
            audience: if bits[2] & 1 == 0 {
                claims.audience
            } else {
                "https://other.test"
            },
            repository: if bits[2] & 2 == 0 {
                claims.repository
            } else {
                "other"
            },
            signer: if bits[2] & 4 == 0 {
                &signer
            } else {
                &other_signer
            },
        };
        let requested_pack = if bits[2] & 8 == 0 { &pack } else { &other_pack };
        let bytes = seed;
        let requested_bytes = if bits[2] & 16 == 0 { bytes } else { bytes ^ 1 };
        let reference = claims.audience == request.audience
            && claims.repository == request.repository
            && claims.signer == request.signer
            && pack == *requested_pack
            && bytes == requested_bytes;
        let result = validate_claims_binding(
            claims,
            request,
            &pack,
            bytes,
            requested_pack,
            requested_bytes,
        );
        assert_eq!(result.is_ok(), reference, "case {case}, seed {seed}");
        if let Err(error) = result {
            assert_eq!(error.code(), FailureCode::ClaimsBindingMismatch);
        }
    }
}

#[test]
fn fixture_auth_failure_codes_map_explicitly() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("../../fixtures/auth/codes.json")).unwrap();
    assert_eq!(cases.len(), 2);
    let failure = validate_envelope(
        &Headers::default(),
        Context {
            audience: "https://example.test",
            repository: "repo",
        },
        "/service/Read",
        ExpectedCommitment::Exact("body:invalid"),
        0,
    )
    .unwrap_err();
    assert_eq!(failure.code(), FailureCode::InvalidEnvelope);
    assert_eq!(
        failure.code().as_str(),
        cases[0]["failure_code"].as_str().unwrap()
    );
    assert_eq!(cases[0]["connect_code"], "unauthenticated");
    assert_eq!(
        ClaimsMismatch.code().as_str(),
        cases[1]["failure_code"].as_str().unwrap()
    );
    assert_eq!(cases[1]["connect_code"], "permission_denied");
}

#[test]
fn competing_faults_preserve_reference_precedence() {
    let f: Value = serde_json::from_str(include_str!("../../fixtures/auth/unary.json")).unwrap();
    let good = headers(&f);
    let ctx = Context {
        audience: f["audience"].as_str().unwrap(),
        repository: f["repository"].as_str().unwrap(),
    };
    let path = f["procedure"].as_str().unwrap();
    let expected = ExpectedCommitment::Exact(f["commitment"].as_str().unwrap());
    let now = f["created_at"].as_i64().unwrap();
    let mut bad_signature = good.clone();
    bad_signature.signature = Some("bad".into());
    let mut wrong_destination = bad_signature.clone();
    wrong_destination.repository = Some("other".into());
    let mut bad_content_and_time = good.clone();
    bad_content_and_time.commitment = Some("unknown".into());
    bad_content_and_time.created_at = Some("01".into());
    let mut bad_version = bad_content_and_time.clone();
    bad_version.version = Some("3".into());
    for (headers, now, reason) in [
        (wrong_destination, now, "noncanonical signature header"),
        (bad_signature, i64::MAX, "noncanonical signature header"),
        (bad_content_and_time, now, "noncanonical validity header"),
        (bad_version, now, "auth v2 required"),
    ] {
        parity(&headers, ctx, path, expected, now);
        assert_eq!(
            validate_envelope(&headers, ctx, path, expected, now)
                .unwrap_err()
                .reason(),
            reason
        );
    }
}

#[test]
fn fixture_claims_binding_matrix() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("../../fixtures/auth/claims.json")).unwrap();
    assert_eq!(cases.len(), 32);
    let signer = [7; 32];
    let other_signer = [8; 32];
    let pack = [9; 32];
    let other_pack = [10; 32];
    let claims = ClaimsPrincipal {
        audience: "https://example.test",
        repository: "repo",
        signer: &signer,
    };
    for case in cases {
        let different = |name: &str| case[name].as_bool().unwrap();
        let request = ClaimsPrincipal {
            audience: if different("different_audience") {
                "https://other.test"
            } else {
                claims.audience
            },
            repository: if different("different_repository") {
                "other"
            } else {
                claims.repository
            },
            signer: if different("different_signer") {
                &other_signer
            } else {
                &signer
            },
        };
        let result = validate_claims_binding(
            claims,
            request,
            &pack,
            u64::MAX,
            if different("different_pack") {
                &other_pack
            } else {
                &pack
            },
            if different("different_bytes") {
                u64::MAX - 1
            } else {
                u64::MAX
            },
        );
        let actual = match result {
            Ok(()) => "verified".to_owned(),
            Err(error) => error.code().as_str().to_owned(),
        };
        assert_eq!(actual, case["expected"].as_str().unwrap(), "{case}");
    }
}

#[test]
fn trigger_headers_require_complete_unique_envelopes() {
    for requires_digest in [true, false] {
        assert_eq!(
            inspect_headers(&[0; 10], requires_digest).unwrap(),
            EnvelopePresence::Absent
        );
        let mut complete = [1; 10];
        if !requires_digest {
            complete[5] = 0;
        }
        assert_eq!(
            inspect_headers(&complete, requires_digest).unwrap(),
            EnvelopePresence::Present
        );
        for index in 0..HEADER_NAMES.len() {
            let mut single = [0; 10];
            single[index] = 1;
            if index == 2 || index == 9 {
                assert_eq!(
                    inspect_headers(&single, requires_digest).unwrap(),
                    EnvelopePresence::Absent,
                    "unsigned {}",
                    HEADER_NAMES[index]
                );
            } else {
                assert_eq!(
                    inspect_headers(&single, requires_digest)
                        .unwrap_err()
                        .code(),
                    FailureCode::InvalidEnvelope,
                    "single {}",
                    HEADER_NAMES[index]
                );
            }
            let mut missing = complete;
            missing[index] = 0;
            assert_eq!(
                inspect_headers(&missing, requires_digest).is_err(),
                index != 5 || requires_digest,
                "missing {}",
                HEADER_NAMES[index]
            );
            for count in [2, usize::MAX] {
                let mut duplicate = complete;
                duplicate[index] = count;
                assert_eq!(
                    inspect_headers(&duplicate, requires_digest)
                        .unwrap_err()
                        .code(),
                    FailureCode::InvalidEnvelope,
                    "duplicate {}",
                    HEADER_NAMES[index]
                );
            }
        }
    }
}

#[test]
fn fixture_header_presence_matrix() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("../../fixtures/auth/header-presence.json")).unwrap();
    assert_eq!(cases.len(), 66);
    for case in cases {
        let counts: [usize; 10] = std::array::from_fn(|index| {
            usize::try_from(case["counts"][index].as_u64().unwrap()).unwrap()
        });
        let actual = match inspect_headers(&counts, case["requires_digest"].as_bool().unwrap()) {
            Ok(EnvelopePresence::Absent) => "absent".to_owned(),
            Ok(EnvelopePresence::Present) => "present".to_owned(),
            Err(error) => error.code().as_str().to_owned(),
        };
        assert_eq!(actual, case["expected"].as_str().unwrap(), "{case}");
    }
}
