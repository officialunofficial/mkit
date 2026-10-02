use super::*;

fn claims() -> TicketClaims {
    TicketClaims {
        authority_generation: None,
        ticket_id: [0x11; 32],
        audience: "https://api.example.test".into(),
        repository: "ed25519-test/demo".into(),
        signer: [0x22; 32],
        pack_id: [0x33; 32],
        bytes: 16_777_217,
        part_size: 8_388_608,
        expires_at_ms: 1_700_086_400_000,
        upload_session: Vec::new(),
    }
}

fn keys(id: &str, secret: u8) -> TicketKeys {
    TicketKeys::new(vec![(id.into(), [secret; 32])]).unwrap()
}

#[test]
fn round_trip_including_binary_session() {
    let keys = keys("key-1", 7);
    let mut claims = claims();
    for session in [Vec::new(), vec![0, 0xff, 2, 3]] {
        claims.upload_session = session;
        assert_eq!(
            keys.verify(&keys.mint(&claims), 1_700_000_000_000).unwrap(),
            claims
        );
    }
}

#[test]
fn verification_failures_are_failed_precondition() {
    let keys = keys("key-1", 7);
    let token = keys.mint(&claims());
    let mut flipped = token.clone();
    *flipped.last_mut().unwrap() ^= 1;
    let wrong_key = super::tests::keys("key-1", 8);
    let unknown_key = super::tests::keys("other", 7);
    for failure in [
        wrong_key.verify(&token, 0),
        unknown_key.verify(&token, 0),
        keys.verify(&flipped, 0),
        keys.verify(&token[..token.len() - 1], 0),
        keys.verify(&[], 0),
        keys.verify(&token, claims().expires_at_ms),
        keys.verify(&token, claims().expires_at_ms + 1),
    ] {
        assert_eq!(failure.unwrap_err().code(), Code::FailedPrecondition);
    }
    for prefix in 0..token.len() {
        assert_eq!(
            keys.verify(&token[..prefix], 0).unwrap_err().code(),
            Code::FailedPrecondition
        );
    }
    assert!(keys.verify(&token, claims().expires_at_ms - 1).is_ok());
}

#[test]
fn authenticated_garbage_is_rejected_after_mac() {
    let keys = keys("key-1", 7);
    let token = keys.mint(&claims());
    let mut messages = Vec::new();
    let mut bad_version = token[..token.len() - 32].to_vec();
    bad_version[0] = 2;
    messages.push(bad_version);
    let mut trailing = token[..token.len() - 32].to_vec();
    trailing.push(0);
    messages.push(trailing);
    let mut bad_utf8 = token[..token.len() - 32].to_vec();
    bad_utf8[2 + "key-1".len() + 32 + 2] = 0xff;
    messages.push(bad_utf8);
    messages.push(token[..2 + "key-1".len() + 32].to_vec());
    for mut message in messages {
        let tag = blake3::keyed_hash(&keys.keys[0].mac_key(), &message);
        message.extend_from_slice(tag.as_bytes());
        assert_eq!(
            keys.verify(&message, 0).unwrap_err().code(),
            Code::FailedPrecondition
        );
    }
}

#[test]
fn rotation_accepts_old_and_signs_new() {
    let old = keys("old", 7);
    let new = keys("new", 8);
    let rotated = TicketKeys::new(vec![("new".into(), [8; 32]), ("old".into(), [7; 32])]).unwrap();
    let claims = claims();
    assert_eq!(rotated.verify(&old.mint(&claims), 0).unwrap(), claims);
    assert_eq!(rotated.mint(&claims), new.mint(&claims));
    assert_eq!(
        new.verify(&old.mint(&claims), 0).unwrap_err().code(),
        Code::FailedPrecondition
    );
}

#[test]
fn bindings_fail_with_permission_denied() {
    let claims = claims();
    assert!(
        claims
            .check_binding(
                &claims.audience,
                &claims.repository,
                &claims.signer,
                &claims.pack_id,
                claims.bytes
            )
            .is_ok()
    );
    for (audience, repository, signer, pack, bytes) in [
        (
            "https://wrong.test",
            claims.repository.as_str(),
            claims.signer,
            claims.pack_id,
            claims.bytes,
        ),
        (
            claims.audience.as_str(),
            "other/demo",
            claims.signer,
            claims.pack_id,
            claims.bytes,
        ),
        (
            claims.audience.as_str(),
            claims.repository.as_str(),
            [4; 32],
            claims.pack_id,
            claims.bytes,
        ),
        (
            claims.audience.as_str(),
            claims.repository.as_str(),
            claims.signer,
            [4; 32],
            claims.bytes,
        ),
        (
            claims.audience.as_str(),
            claims.repository.as_str(),
            claims.signer,
            claims.pack_id,
            claims.bytes + 1,
        ),
    ] {
        assert_eq!(
            claims
                .check_binding(audience, repository, &signer, &pack, bytes)
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
    }
}

#[test]
fn configuration_validation_and_redaction() {
    let text = format!(
        "# test secrets only\n\n current-key {}\nold_key {}\n",
        "07".repeat(32),
        "08".repeat(32)
    );
    let keys = TicketKeys::parse(&text).unwrap();
    assert_eq!(keys.keys[0].id, "current-key");
    assert_eq!(keys.keys.len(), 2);
    let debug = format!("{keys:?}");
    assert!(debug.contains("current-key"));
    assert!(!debug.contains(&"07".repeat(32)));
    assert!(!debug.contains("secret"));
    for invalid in [
        String::new(),
        "# no keys\n\n".into(),
        format!("bad/id {}", "07".repeat(32)),
        format!("{} {}", "a".repeat(33), "07".repeat(32)),
        "id 07".into(),
        format!("id {}", "gg".repeat(32)),
        format!("id {} extra", "07".repeat(32)),
        format!("id {}\nid {}", "07".repeat(32), "08".repeat(32)),
        format!("é {}", "07".repeat(32)),
    ] {
        let error = TicketKeys::parse(&invalid).unwrap_err();
        assert_eq!(error, TicketKeyError);
        assert!(!error.to_string().contains(&"07".repeat(32)));
    }
    assert!(TicketKeys::new(Vec::new()).is_err());
    assert!(TicketKeys::new(vec![(String::new(), [7; 32])]).is_err());
    assert!(TicketKeys::new(vec![("id".into(), [7; 32]), ("id".into(), [8; 32])]).is_err());
}

#[test]
fn authority_generation_is_authenticated_and_unfenced_tokens_stay_v1() {
    let keys = keys("key-1", 7);
    let mut claims = claims();
    assert_eq!(keys.mint(&claims)[0], 1);
    for generation in [0, 1, u64::MAX] {
        claims.authority_generation = Some(generation);
        let token = keys.mint(&claims);
        assert_eq!(token[0], 2);
        assert_eq!(keys.verify(&token, 0).unwrap(), claims);
        let mut changed = token.clone();
        let at = changed.len() - 33;
        changed[at] ^= 1;
        assert!(keys.verify(&changed, 0).is_err());
    }
}
