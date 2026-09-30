#![allow(clippy::unwrap_used)]

use super::*;
use core::time::Duration;
use ed25519_dalek::SigningKey;
use mkit_core::hash::to_hex;

fn scanner() -> String {
    to_hex(SigningKey::from_bytes(&[41; 32]).verifying_key().as_bytes())
}

fn config() -> RetrievalConfig {
    RetrievalConfig::parse(&format!("active current {}", to_hex(&[42; 32])), &scanner()).unwrap()
}

fn assignment() -> Assignment {
    Assignment {
        namespace: "test".into(),
        repo_name: "room".into(),
        repository: "test/room".into(),
        ref_name: "refs/heads/main".into(),
        signer: [43; 32],
        packs: vec![
            PackGrant {
                id: [44; 32],
                length: 200,
                tickets: vec![[45; 32]],
            },
            PackGrant {
                id: [46; 32],
                length: 300,
                tickets: vec![[47; 32]],
            },
        ],
    }
}

#[test]
fn each_attempt_has_fresh_capability_with_stable_id_and_ordered_lengths() {
    let config = config();
    let assignment = assignment();
    let first = config
        .mint(
            "https://scanner.test",
            "stable",
            &assignment,
            Duration::from_secs(10),
            1_000,
        )
        .unwrap();
    let second = config
        .mint(
            "https://scanner.test",
            "stable",
            &assignment,
            Duration::from_secs(10),
            1_000,
        )
        .unwrap();
    assert_eq!(first.endpoint_path.as_deref(), Some(PATH));
    assert_eq!(first.expires_at_ms, Some(12_000));
    assert_ne!(first.capability, second.capability);
    assert_eq!(first.packs, second.packs);
    for (wire, grant) in first.packs.iter().zip(&assignment.packs) {
        assert_eq!(wire.id.as_deref(), Some(grant.id.as_slice()));
        assert_eq!(wire.length, Some(grant.length));
    }
    let a = config
        .verify(
            first.capability.as_ref().unwrap(),
            "https://scanner.test",
            1_000,
        )
        .unwrap();
    let b = config
        .verify(
            second.capability.as_ref().unwrap(),
            "https://scanner.test",
            1_000,
        )
        .unwrap();
    assert_eq!(a.inspection_id, "stable");
    assert_eq!(b.inspection_id, "stable");
    assert_ne!(a.nonce, b.nonce);
    assert_eq!(a.assignment, assignment);
}

#[test]
fn capability_binds_origin_bytes_and_exclusive_validity_window() {
    let config = config();
    let wire = config
        .mint(
            "https://scanner.test",
            "stable",
            &assignment(),
            Duration::from_millis(1),
            1_000,
        )
        .unwrap();
    let token = wire.capability.unwrap();
    assert!(config.verify(&token, "https://scanner.test", 2_000).is_ok());
    for (candidate, audience, now) in [
        (token.clone(), "https://other.test", 1_000),
        (token.clone(), "https://scanner.test", 999),
        (token.clone(), "https://scanner.test", 2_001),
        (token.to_uppercase(), "https://scanner.test", 1_000),
        (
            token.replacen("r1.", "r2.", 1),
            "https://scanner.test",
            1_000,
        ),
        (
            token.replace("current", "unknown"),
            "https://scanner.test",
            1_000,
        ),
        (format!("{token}0"), "https://scanner.test", 1_000),
        (String::new(), "https://scanner.test", 1_000),
    ] {
        let error = config.verify(&candidate, audience, now).err().unwrap();
        assert_eq!(error.code(), crate::Code::NotFound);
        assert_eq!(error.public_message(), "pack not found");
    }
    let mut fields: Vec<_> = token.split('.').map(str::to_owned).collect();
    fields[2].replace_range(0..2, "00");
    assert!(
        config
            .verify(&fields.join("."), "https://scanner.test", 1_000)
            .is_err()
    );
}

#[test]
fn capability_claim_substitutions_cannot_reuse_the_original_mac() {
    let config = config();
    let token = config
        .mint(
            "https://scanner.test",
            "stable",
            &assignment(),
            Duration::from_secs(10),
            1_000,
        )
        .unwrap()
        .capability
        .unwrap();
    let claims = config
        .verify(&token, "https://scanner.test", 1_000)
        .unwrap();
    let original = serde_json::to_vec(&claims).unwrap();
    assert_eq!(
        token.split('.').nth(2).unwrap(),
        mkit_core::hash::to_hex_bytes(&original)
    );
    for case in 0..5 {
        let mut changed: super::Claims = serde_json::from_slice(&original).unwrap();
        match case {
            0 => changed.assignment.packs[0].id = [99; 32],
            1 => changed.assignment.repository = "test/other".into(),
            2 => changed.audience = "https://other.test".into(),
            3 => changed.expires_at_ms += 1,
            _ => changed.inspection_id = "another-inspection".into(),
        }
        let mut fields: Vec<_> = token.split('.').map(str::to_owned).collect();
        fields[2] = mkit_core::hash::to_hex_bytes(&serde_json::to_vec(&changed).unwrap());
        let error = config
            .verify(&fields.join("."), "https://scanner.test", 1_000)
            .err()
            .unwrap();
        assert_eq!(error.code(), crate::Code::NotFound, "substitution {case}");
        assert_eq!(error.public_message(), "pack not found");
    }
}

#[test]
fn retained_key_rotation_is_bounded_and_mint_uses_active_key() {
    let old = config();
    let token = old
        .mint(
            "https://scanner.test",
            "stable",
            &assignment(),
            Duration::from_mins(5),
            1_100,
        )
        .unwrap()
        .capability
        .unwrap();
    let rotated = RetrievalConfig::parse(
        &format!(
            "active next {}\nretained current {} 1000",
            to_hex(&[48; 32]),
            to_hex(&[42; 32])
        ),
        &scanner(),
    )
    .unwrap();
    assert!(
        rotated
            .verify(&token, "https://scanner.test", 1_100)
            .is_ok()
    );
    assert!(
        rotated
            .verify(&token, "https://scanner.test", 301_999)
            .is_ok()
    );
    assert!(
        rotated
            .verify(&token, "https://scanner.test", 302_000)
            .is_err()
    );
    let fresh = rotated
        .mint(
            "https://scanner.test",
            "stable",
            &assignment(),
            Duration::from_secs(1),
            1_000,
        )
        .unwrap()
        .capability
        .unwrap();
    assert!(fresh.starts_with("r1.next."));
    assert!(old.verify(&fresh, "https://scanner.test", 1_000).is_err());
    let removed =
        RetrievalConfig::parse(&format!("active next {}", to_hex(&[48; 32])), &scanner()).unwrap();
    assert!(
        removed
            .verify(&token, "https://scanner.test", 1_100)
            .is_err()
    );
}

#[test]
fn all_retained_and_active_keys_are_checked_for_role_reuse() {
    let config = RetrievalConfig::parse(
        &format!(
            "active current {}\nretained old {} 1000",
            to_hex(&[42; 32]),
            to_hex(&[48; 32])
        ),
        &scanner(),
    )
    .unwrap();
    for secret in [[42; 32], [48; 32], [41; 32]] {
        assert!(config.check_role_keys(&[], &[secret]).is_err());
        let public = SigningKey::from_bytes(&secret).verifying_key().to_bytes();
        assert!(config.check_role_keys(&[public], &[]).is_err());
        assert!(config.check_role_keys(&[], &[public]).is_err());
    }
    assert!(config.check_role_keys(&[], &[[49; 32]]).is_ok());
    let scanner_seed = format!("active current {}", to_hex(&[41; 32]));
    assert!(RetrievalConfig::parse(&scanner_seed, &scanner()).is_err());
}

#[test]
fn configuration_and_capability_limits_fail_closed() {
    let secret = to_hex(&[42; 32]);
    for grammar in [
        String::new(),
        format!("retained old {secret} 1"),
        format!("active a {secret}\nactive b {}", to_hex(&[48; 32])),
        format!("active a {secret}\nretained b {secret} 1"),
        format!("active a {secret}\nretained a {} 1", to_hex(&[48; 32])),
        format!("active a {secret}\nretained b {} 01", to_hex(&[48; 32])),
        format!("active bad/id {secret}"),
        format!("active a {secret} extra"),
    ] {
        assert!(
            RetrievalConfig::parse(&grammar, &scanner()).is_err(),
            "{grammar}"
        );
    }
    let valid = format!("active current {secret}");
    assert!(RetrievalConfig::parse(&valid, "").is_err());
    assert!(RetrievalConfig::parse(&valid, &format!("{}\n{}", scanner(), scanner())).is_err());
    assert!(RetrievalConfig::parse(&valid, &to_hex(&[0; 32])).is_err());
    let config = config();
    for timeout in [
        Duration::ZERO,
        Duration::from_millis(300_001),
        Duration::MAX,
    ] {
        assert!(
            config
                .mint(
                    "https://scanner.test",
                    "stable",
                    &assignment(),
                    timeout,
                    1_000
                )
                .is_err()
        );
    }
    assert!(
        config
            .mint(
                "https://scanner.test",
                "stable",
                &assignment(),
                Duration::from_secs(1),
                u64::MAX
            )
            .is_err()
    );
    let mut duplicate = assignment();
    duplicate.packs.push(duplicate.packs[0].clone());
    assert!(
        config
            .mint(
                "https://scanner.test",
                "stable",
                &duplicate,
                Duration::from_secs(1),
                1_000
            )
            .is_err()
    );
    let mut unbound = assignment();
    unbound.packs[0].tickets.clear();
    assert!(
        config
            .mint(
                "https://scanner.test",
                "stable",
                &unbound,
                Duration::from_secs(1),
                1_000
            )
            .is_err()
    );
}
