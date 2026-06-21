//! Sign + verify throughput across the three algorithms mkit ships:
//! Ed25519 (RFC 8032), secp256k1 (Bitcoin curve), P-256 (NIST). Two
//! charts per category — one for sign ops/s, one for verify ops/s —
//! mirroring the buffa "encode vs decode" split.
//!
//! The signed payload is a fixed 200-byte blob (representative of a
//! DSSE PAE wrapping an in-toto v1 statement; see SPEC-ATTESTATIONS).

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};

const PAYLOAD_SIZE: usize = 200;

fn random_payload() -> Vec<u8> {
    let mut state: u64 = 0xface_b00c_dead_beef;
    let mut out = Vec::with_capacity(PAYLOAD_SIZE);
    for _ in 0..PAYLOAD_SIZE {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        out.push((state >> 56) as u8);
    }
    out
}

fn bench_sign_verify(c: &mut Criterion) {
    let payload = random_payload();
    let mut samples: Vec<Sample> = Vec::new();

    // -- Ed25519 -------------------------------------------------
    {
        use ed25519_dalek::{Signer, SigningKey, Verifier};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let sig = sk.sign(&payload);

        c.bench_function("sign_verify/ed25519/sign", |b| {
            b.iter(|| sk.sign(&payload));
        });
        c.bench_function("sign_verify/ed25519/verify", |b| {
            b.iter(|| vk.verify(&payload, &sig).unwrap());
        });

        let s = time_one(50, 500, || {
            let _ = sk.sign(&payload);
        });
        samples.push(Sample {
            category: "sign".into(),
            axis: "by algorithm".into(),
            library: "Ed25519".into(),
            value: 1.0 / s,
            unit: Unit::OpsPerSec,
        });
        let v = time_one(50, 500, || {
            let _ = vk.verify(&payload, &sig);
        });
        samples.push(Sample {
            category: "verify".into(),
            axis: "by algorithm".into(),
            library: "Ed25519".into(),
            value: 1.0 / v,
            unit: Unit::OpsPerSec,
        });
    }

    // -- secp256k1 -----------------------------------------------
    {
        use k256::ecdsa::{
            Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier,
        };
        let sk = SigningKey::from_bytes(&[8u8; 32].into()).unwrap();
        let vk: VerifyingKey = *sk.verifying_key();
        let sig: Signature = sk.sign(&payload);

        c.bench_function("sign_verify/secp256k1/sign", |b| {
            b.iter(|| {
                let _: Signature = sk.sign(&payload);
            });
        });
        c.bench_function("sign_verify/secp256k1/verify", |b| {
            b.iter(|| vk.verify(&payload, &sig).unwrap());
        });

        let s = time_one(50, 500, || {
            let _: Signature = sk.sign(&payload);
        });
        samples.push(Sample {
            category: "sign".into(),
            axis: "by algorithm".into(),
            library: "secp256k1".into(),
            value: 1.0 / s,
            unit: Unit::OpsPerSec,
        });
        let v = time_one(50, 500, || {
            let _ = vk.verify(&payload, &sig);
        });
        samples.push(Sample {
            category: "verify".into(),
            axis: "by algorithm".into(),
            library: "secp256k1".into(),
            value: 1.0 / v,
            unit: Unit::OpsPerSec,
        });
    }

    // -- P-256 ---------------------------------------------------
    {
        use p256::ecdsa::{
            Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier,
        };
        let sk = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let vk: VerifyingKey = *sk.verifying_key();
        let sig: Signature = sk.sign(&payload);

        c.bench_function("sign_verify/p256/sign", |b| {
            b.iter(|| {
                let _: Signature = sk.sign(&payload);
            });
        });
        c.bench_function("sign_verify/p256/verify", |b| {
            b.iter(|| vk.verify(&payload, &sig).unwrap());
        });

        let s = time_one(50, 500, || {
            let _: Signature = sk.sign(&payload);
        });
        samples.push(Sample {
            category: "sign".into(),
            axis: "by algorithm".into(),
            library: "P-256".into(),
            value: 1.0 / s,
            unit: Unit::OpsPerSec,
        });
        let v = time_one(50, 500, || {
            let _ = vk.verify(&payload, &sig);
        });
        samples.push(Sample {
            category: "verify".into(),
            axis: "by algorithm".into(),
            library: "P-256".into(),
            value: 1.0 / v,
            unit: Unit::OpsPerSec,
        });
    }

    mkit_benches::write_summary("sign_verify", &samples);
}

criterion_group!(benches, bench_sign_verify);
criterion_main!(benches);
