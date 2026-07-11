//! `mkit-release-attest` — internal release tool (not shipped, not published).
//!
//! Produces and verifies the **mkit-native release attestation**: a
//! DSSE envelope over an in-toto v1 Statement whose subjects are the
//! BLAKE3 digests of the release tarballs, signed with the mkit
//! release-attestation Ed25519 key. This is the trust root
//! `mkit self update` verifies against (public keys embedded in the
//! CLI binary and checked in at `docs/keys/release-attest.pub`), so
//! the updater needs neither `cosign` nor GitHub's attestation
//! infrastructure.
//!
//! Three modes:
//!
//! ```text
//! mkit-release-attest keygen --out-pub <path>
//!     Generate a fresh Ed25519 keypair. Writes the public-key file to
//!     <path> and prints the 64-hex SECRET seed to stdout, so it can be
//!     piped straight into `gh secret set MKIT_RELEASE_ATTEST_KEY`
//!     without ever touching disk. keyid goes to stderr.
//!
//! mkit-release-attest sign --tag <vX.Y.Z> --out <path>
//!                          (--key-env <VAR> | --key-file <path>)
//!                          <artifact>...
//!     Sign the artifacts (subject name = file basename, digest =
//!     BLAKE3) with predicate {"tag": "<vX.Y.Z>"} and write the DSSE
//!     envelope to <path>. Self-verifies with the derived public key
//!     before writing.
//!
//! mkit-release-attest verify --pubkeys <path> --dsse <path>
//!                            --tag <vX.Y.Z> <artifact>...
//!     Verify the envelope signature against the `ed25519:<hex>` keys
//!     in <path>, require the predicate tag to match, and require the
//!     subject set to EXACTLY equal the artifact set (same basenames,
//!     matching BLAKE3 digests). Used by release.yml as a post-sign
//!     sanity check that the secret key matches the checked-in pubkey.
//! ```
//!
//! The predicate type URI follows SPEC-ATTESTATIONS §6.4:
//! `https://github.com/officialunofficial/mkit/spec/predicate/release/v1`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use mkit_attest::{
    Envelope, PAYLOAD_TYPE_IN_TOTO, Registry, Sig, Signer as _, TrustRoot, envelope, jcs, pae_of,
    signer_repo_key::RepoKeySigner, statement,
};
use mkit_core::hash;
use zeroize::Zeroizing;

/// Predicate type URI for the release attestation (SPEC-ATTESTATIONS §6.4).
const PREDICATE_TYPE_RELEASE_V1: &str =
    "https://github.com/officialunofficial/mkit/spec/predicate/release/v1";

/// sysexits(3)-aligned exit codes, mirroring the mkit CLI's contract.
const EXIT_OK: u8 = 0;
const EXIT_GENERAL: u8 = 1;
const EXIT_USAGE: u8 = 64;
const EXIT_DATAERR: u8 = 65;
const EXIT_NOINPUT: u8 = 66;

const USAGE: &str = "\
usage:
  mkit-release-attest keygen --out-pub <path>
  mkit-release-attest sign   --tag <vX.Y.Z> --out <path> \\
                             (--key-env <VAR> | --key-file <path>) <artifact>...
  mkit-release-attest verify --pubkeys <path> --dsse <path> \\
                             --tag <vX.Y.Z> <artifact>...
";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let code = match argv.get(1).map(String::as_str) {
        Some("keygen") => keygen(&argv[2..]),
        Some("sign") => sign(&argv[2..]),
        Some("verify") => verify(&argv[2..]),
        Some("--help" | "-h" | "help") => {
            print!("{USAGE}");
            EXIT_OK
        }
        _ => usage_err("expected a mode: keygen | sign | verify"),
    };
    ExitCode::from(code)
}

fn usage_err(msg: &str) -> u8 {
    eprintln!("error: {msg}");
    eprint!("{USAGE}");
    EXIT_USAGE
}

fn err(msg: &str, code: u8) -> u8 {
    eprintln!("error: {msg}");
    code
}

/// Minimal flag parser: `--key value` pairs, everything else positional.
/// Duplicate flags are a usage error so a malformed CI invocation fails
/// loudly instead of silently taking the last value.
fn parse_flags(args: &[String]) -> Result<(BTreeMap<String, String>, Vec<String>), String> {
    let mut flags = BTreeMap::new();
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(name) = a.strip_prefix("--") {
            let Some(value) = args.get(i + 1) else {
                return Err(format!("flag --{name} requires a value"));
            };
            if flags.insert(name.to_owned(), value.clone()).is_some() {
                return Err(format!("flag --{name} given twice"));
            }
            i += 2;
        } else {
            positional.push(a.clone());
            i += 1;
        }
    }
    Ok((flags, positional))
}

// ---------------------------------------------------------------- keygen

fn keygen(args: &[String]) -> u8 {
    let (flags, positional) = match parse_flags(args) {
        Ok(p) => p,
        Err(e) => return usage_err(&e),
    };
    if !positional.is_empty() {
        return usage_err("keygen takes no positional arguments");
    }
    let Some(out_pub) = flags.get("out-pub") else {
        return usage_err("keygen requires --out-pub <path>");
    };
    if flags.len() != 1 {
        return usage_err("keygen accepts only --out-pub");
    }

    let kp = match mkit_core::sign::KeyPair::generate() {
        Ok(kp) => kp,
        Err(e) => return err(&format!("keygen: {e}"), EXIT_GENERAL),
    };
    let pub_hex = hash::to_hex_bytes(&kp.public.0);
    let keyid = keyid_for_pubkey(&kp.public.0);

    let pub_file = format!(
        "# mkit release-attestation public key(s) — Ed25519.\n\
         # One `ed25519:<64-hex>` per non-comment line; multiple lines form\n\
         # the rotation set (a release attestation verifies if ANY listed\n\
         # key signed it). The secret half lives ONLY in the GitHub Actions\n\
         # secret MKIT_RELEASE_ATTEST_KEY — see docs/RELEASE.md for the\n\
         # custody and rotation runbook.\n\
         # keyid: {keyid}\n\
         ed25519:{pub_hex}\n"
    );
    if let Err(e) = std::fs::write(out_pub, pub_file) {
        return err(&format!("write {out_pub}: {e}"), EXIT_GENERAL);
    }

    // Secret seed to stdout ONLY — callers pipe it into the secret
    // store. Everything human goes to stderr.
    let seed_hex = Zeroizing::new(hash::to_hex_bytes(&kp.secret.0));
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{}", seed_hex.as_str());
    eprintln!("wrote public key to {out_pub}");
    eprintln!("keyid: {keyid}");
    eprintln!(
        "stdout holds the SECRET seed hex — pipe it into `gh secret set`, do not save it to disk."
    );
    EXIT_OK
}

// ------------------------------------------------------------------ sign

fn sign(args: &[String]) -> u8 {
    let (flags, artifacts) = match parse_flags(args) {
        Ok(p) => p,
        Err(e) => return usage_err(&e),
    };
    let Some(tag) = flags.get("tag") else {
        return usage_err("sign requires --tag <vX.Y.Z>");
    };
    let Some(out) = flags.get("out") else {
        return usage_err("sign requires --out <path>");
    };
    if let Err(e) = validate_tag(tag) {
        return usage_err(&e);
    }
    let seed = match (flags.get("key-env"), flags.get("key-file")) {
        (Some(var), None) => match std::env::var(var) {
            Ok(v) => match decode_seed_hex(v.trim()) {
                Ok(s) => s,
                Err(e) => return err(&format!("--key-env {var}: {e}"), EXIT_DATAERR),
            },
            Err(_) => return err(&format!("--key-env {var}: variable is unset"), EXIT_NOINPUT),
        },
        (None, Some(path)) => match read_seed_file(path) {
            Ok(s) => s,
            Err((msg, code)) => return err(&msg, code),
        },
        _ => return usage_err("sign requires exactly one of --key-env or --key-file"),
    };
    if artifacts.is_empty() {
        return usage_err("sign requires at least one artifact path");
    }

    let subjects = match subjects_for(&artifacts) {
        Ok(s) => s,
        Err((msg, code)) => return err(&msg, code),
    };

    let stmt_bytes = match encode_release_statement(&subjects, tag) {
        Ok(b) => b,
        Err(e) => return err(&format!("statement: {e}"), EXIT_DATAERR),
    };

    let mut signer = RepoKeySigner::from_seed_zeroizing(&seed);
    let pae = pae_of(PAYLOAD_TYPE_IN_TOTO, &stmt_bytes);
    let sig_bytes = match signer.sign(&pae) {
        Ok(b) => b,
        Err(e) => return err(&format!("sign: {e}"), EXIT_GENERAL),
    };
    let keyid = signer.keyid_string();

    let env = Envelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_owned(),
        payload: stmt_bytes,
        signatures: vec![Sig {
            keyid: keyid.clone(),
            sig: sig_bytes,
        }],
    };
    let encoded = match env.encode() {
        Ok(s) => s,
        Err(e) => return err(&format!("encode envelope: {e}"), EXIT_DATAERR),
    };

    // Self-verify with the pubkey derived from the signing seed before
    // anything is written: a corrupt secret fails the release here, not
    // at first `mkit self update` in the field.
    let derived_pub = mkit_core::sign::KeyPair::from_seed_zeroizing(&seed)
        .public
        .0;
    let mut registry = Registry::new();
    registry.add(keyid.clone(), TrustRoot::Ed25519PubKey(derived_pub));
    match mkit_attest::verify_envelope(encoded.as_bytes(), &registry) {
        Ok(r) if r.any_verified => {}
        Ok(_) => return err("self-verify: signature did not verify", EXIT_GENERAL),
        Err(e) => return err(&format!("self-verify: {e}"), EXIT_GENERAL),
    }

    if let Err(e) = std::fs::write(out, encoded.as_bytes()) {
        return err(&format!("write {out}: {e}"), EXIT_GENERAL);
    }
    eprintln!(
        "signed {} artifact(s) for {tag} → {out} (keyid {keyid})",
        subjects.len()
    );
    EXIT_OK
}

// ---------------------------------------------------------------- verify

fn verify(args: &[String]) -> u8 {
    let (flags, artifacts) = match parse_flags(args) {
        Ok(p) => p,
        Err(e) => return usage_err(&e),
    };
    let (Some(pubkeys_path), Some(dsse_path), Some(tag)) =
        (flags.get("pubkeys"), flags.get("dsse"), flags.get("tag"))
    else {
        return usage_err("verify requires --pubkeys, --dsse, and --tag");
    };
    if artifacts.is_empty() {
        return usage_err("verify requires at least one artifact path");
    }

    let pubkeys = match parse_pubkeys_file(pubkeys_path) {
        Ok(p) => p,
        Err((msg, code)) => return err(&msg, code),
    };
    let dsse_bytes = match std::fs::read(dsse_path) {
        Ok(b) => b,
        Err(e) => return err(&format!("read {dsse_path}: {e}"), EXIT_NOINPUT),
    };

    let subjects = match subjects_for(&artifacts) {
        Ok(s) => s,
        Err((msg, code)) => return err(&msg, code),
    };

    match verify_release_dsse(&dsse_bytes, &pubkeys, tag, &subjects) {
        Ok(keyid) => {
            eprintln!(
                "verified {dsse_path}: {} subject(s), tag {tag}, keyid {keyid}",
                subjects.len()
            );
            EXIT_OK
        }
        Err(e) => err(&format!("verify {dsse_path}: {e}"), EXIT_DATAERR),
    }
}

// ---------------------------------------------------------------- shared

/// `(basename, blake3-hex, sha256-hex)`. Both digests are of the
/// identical artifact bytes (SPEC-ATTESTATIONS §4.2) — `sha256` is what
/// lets cosign / `gh attestation verify` / the SLSA verifier read this
/// attestation's subjects at all.
type ArtifactSubject = (String, String, String);

/// Subjects sorted by basename, duplicates rejected.
fn subjects_for(paths: &[String]) -> Result<Vec<ArtifactSubject>, (String, u8)> {
    let mut out: Vec<ArtifactSubject> = Vec::with_capacity(paths.len());
    for p in paths {
        let name = Path::new(p)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| (format!("artifact '{p}' has no usable basename"), EXIT_USAGE))?
            .to_owned();
        let bytes = std::fs::read(p).map_err(|e| (format!("read {p}: {e}"), EXIT_NOINPUT))?;
        out.push((
            name,
            hash::to_hex(&hash::hash(&bytes)),
            statement::sha256_hex(&bytes),
        ));
    }
    out.sort();
    if let Some(w) = out.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err((
            format!("duplicate artifact basename '{}'", w[0].0),
            EXIT_USAGE,
        ));
    }
    Ok(out)
}

/// Encode the in-toto Statement with predicate `{"tag": "<tag>"}`.
fn encode_release_statement(
    subjects: &[ArtifactSubject],
    tag: &str,
) -> Result<Vec<u8>, mkit_attest::Error> {
    let predicate = jcs::encode(&jcs::Value::Object(vec![jcs::Member::new(
        "tag",
        jcs::Value::String(tag.to_owned()),
    )]))?;
    let stmt = statement::Statement {
        subjects: subjects
            .iter()
            .map(|(name, blake3_digest, sha256_digest)| statement::Subject {
                name: Some(name.clone()),
                digest_blake3_hex: blake3_digest.clone(),
                digest_sha256_hex: sha256_digest.clone(),
            })
            .collect(),
        predicate_type: PREDICATE_TYPE_RELEASE_V1.to_owned(),
        predicate_jcs: predicate.as_bytes(),
    };
    statement::encode(&stmt).map(String::into_bytes)
}

/// Full release-attestation check: DSSE signature against any of
/// `pubkeys`, predicate type + tag match, and subject set EXACTLY equal
/// to `expected` (basename + blake3 + sha256). Returns the verifying keyid.
///
/// This is the same predicate `mkit self update` enforces — release.yml
/// runs it right after signing so a key mismatch or a subject drift
/// fails the release, not the updater in the field.
fn verify_release_dsse(
    dsse_bytes: &[u8],
    pubkeys: &[[u8; 32]],
    tag: &str,
    expected: &[ArtifactSubject],
) -> Result<String, String> {
    let mut registry = Registry::new();
    for pk in pubkeys {
        registry.add(keyid_for_pubkey(pk), TrustRoot::Ed25519PubKey(*pk));
    }
    let result = mkit_attest::verify_envelope(dsse_bytes, &registry)
        .map_err(|e| format!("envelope: {e}"))?;
    let Some(verified) = result.signatures.iter().find(|s| s.verified) else {
        return Err("no signature verified against the release-attestation key set".to_owned());
    };

    let env = envelope::decode(dsse_bytes).map_err(|e| format!("envelope: {e}"))?;
    let stmt: serde_json::Value =
        serde_json::from_slice(&env.payload).map_err(|e| format!("statement: {e}"))?;

    if stmt["predicateType"] != PREDICATE_TYPE_RELEASE_V1 {
        return Err(format!(
            "predicateType is {}, expected {PREDICATE_TYPE_RELEASE_V1}",
            stmt["predicateType"]
        ));
    }
    if stmt["predicate"]["tag"] != tag {
        return Err(format!(
            "predicate tag is {}, expected \"{tag}\"",
            stmt["predicate"]["tag"]
        ));
    }

    let Some(subject_arr) = stmt["subject"].as_array() else {
        return Err("statement has no subject array".to_owned());
    };
    let mut actual: Vec<ArtifactSubject> = Vec::with_capacity(subject_arr.len());
    for s in subject_arr {
        let (Some(name), Some(blake3_digest), Some(sha256_digest)) = (
            s["name"].as_str(),
            s["digest"]["blake3"].as_str(),
            s["digest"]["sha256"].as_str(),
        ) else {
            return Err("subject entry missing name, blake3 digest, or sha256 digest".to_owned());
        };
        actual.push((
            name.to_owned(),
            blake3_digest.to_owned(),
            sha256_digest.to_owned(),
        ));
    }
    actual.sort();
    if actual != expected {
        return Err(format!(
            "subject set mismatch:\n  attested: {actual:?}\n  expected: {expected:?}"
        ));
    }
    Ok(verified.keyid.clone())
}

/// keyid convention from SPEC-ATTESTATIONS §6.3: `blake3:<hex(BLAKE3(pubkey))>`.
fn keyid_for_pubkey(pubkey: &[u8; 32]) -> String {
    format!(
        "{}{}",
        mkit_attest::KEYID_PREFIX,
        hash::to_hex(&hash::hash(pubkey))
    )
}

/// Strict-semver release tag, mirroring release.yml's regex.
fn validate_tag(tag: &str) -> Result<(), String> {
    let rest = tag
        .strip_prefix('v')
        .ok_or_else(|| format!("tag '{tag}' must start with 'v'"))?;
    let (core, prerelease) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    let core_ok = parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    let pre_ok = prerelease
        .is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.'));
    if core_ok && pre_ok {
        Ok(())
    } else {
        Err(format!(
            "tag '{tag}' is not strict semver (vMAJOR.MINOR.PATCH[-suffix])"
        ))
    }
}

/// Decode a 64-hex-char Ed25519 seed into a zeroizing buffer.
fn decode_seed_hex(s: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let h = hash::from_hex(s).map_err(|_| "expected 64 hex chars".to_owned())?;
    Ok(Zeroizing::new(h))
}

/// Read a seed file: raw 32 bytes (mkit keygen format) or 64 hex chars
/// (+ optional trailing newline).
fn read_seed_file(path: &str) -> Result<Zeroizing<[u8; 32]>, (String, u8)> {
    let f = std::fs::File::open(path).map_err(|e| (format!("open {path}: {e}"), EXIT_NOINPUT))?;
    let mut buf = Zeroizing::new(Vec::with_capacity(66));
    f.take(66)
        .read_to_end(&mut buf)
        .map_err(|e| (format!("read {path}: {e}"), EXIT_NOINPUT))?;
    if buf.len() == 32 {
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&buf);
        return Ok(seed);
    }
    let text = core::str::from_utf8(&buf).map_err(|_| {
        (
            format!("{path}: neither raw 32 bytes nor hex"),
            EXIT_DATAERR,
        )
    })?;
    decode_seed_hex(text.trim()).map_err(|e| (format!("{path}: {e}"), EXIT_DATAERR))
}

/// Parse the checked-in public-key file: `ed25519:<64-hex>` lines,
/// `#` comments and blank lines ignored. At least one key required.
fn parse_pubkeys_file(path: &str) -> Result<Vec<[u8; 32]>, (String, u8)> {
    let text =
        std::fs::read_to_string(path).map_err(|e| (format!("read {path}: {e}"), EXIT_NOINPUT))?;
    let mut keys = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(hex) = line.strip_prefix("ed25519:") else {
            return Err((
                format!("{path}:{}: expected `ed25519:<64-hex>`", lineno + 1),
                EXIT_DATAERR,
            ));
        };
        let pk = hash::from_hex(hex)
            .map_err(|_| (format!("{path}:{}: bad hex", lineno + 1), EXIT_DATAERR))?;
        keys.push(pk);
    }
    if keys.is_empty() {
        return Err((format!("{path}: no keys found"), EXIT_DATAERR));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "mkit-release-attest-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn seed_and_pub() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
        let seed = Zeroizing::new([7u8; 32]);
        let pk = mkit_core::sign::KeyPair::from_seed_zeroizing(&seed)
            .public
            .0;
        (seed, pk)
    }

    fn sign_bytes(seed: &Zeroizing<[u8; 32]>, subjects: &[ArtifactSubject], tag: &str) -> Vec<u8> {
        let stmt = encode_release_statement(subjects, tag).unwrap();
        let mut signer = RepoKeySigner::from_seed_zeroizing(seed);
        let pae = pae_of(PAYLOAD_TYPE_IN_TOTO, &stmt);
        let sig = signer.sign(&pae).unwrap();
        Envelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.to_owned(),
            payload: stmt,
            signatures: vec![Sig {
                keyid: signer.keyid_string(),
                sig,
            }],
        }
        .encode()
        .unwrap()
        .into_bytes()
    }

    fn subj(name: &str, body: &[u8]) -> ArtifactSubject {
        (
            name.to_owned(),
            hash::to_hex(&hash::hash(body)),
            statement::sha256_hex(body),
        )
    }

    #[test]
    fn roundtrip_verifies() {
        let (seed, pk) = seed_and_pub();
        let subjects = vec![subj("a.tar.gz", b"aaa"), subj("b.tar.gz", b"bbb")];
        let dsse = sign_bytes(&seed, &subjects, "v1.2.3");
        let keyid = verify_release_dsse(&dsse, &[pk], "v1.2.3", &subjects).unwrap();
        assert_eq!(keyid, keyid_for_pubkey(&pk));
    }

    #[test]
    fn wrong_key_rejected() {
        let (seed, _) = seed_and_pub();
        let other_pk = mkit_core::sign::KeyPair::from_seed_zeroizing(&Zeroizing::new([9u8; 32]))
            .public
            .0;
        let subjects = vec![subj("a.tar.gz", b"aaa")];
        let dsse = sign_bytes(&seed, &subjects, "v1.2.3");
        let e = verify_release_dsse(&dsse, &[other_pk], "v1.2.3", &subjects).unwrap_err();
        assert!(e.contains("no signature verified"), "{e}");
    }

    #[test]
    fn rotation_set_second_key_verifies() {
        let (seed, pk) = seed_and_pub();
        let other_pk = mkit_core::sign::KeyPair::from_seed_zeroizing(&Zeroizing::new([9u8; 32]))
            .public
            .0;
        let subjects = vec![subj("a.tar.gz", b"aaa")];
        let dsse = sign_bytes(&seed, &subjects, "v1.2.3");
        // Signer's key is second in the registry — rotation-set semantics.
        verify_release_dsse(&dsse, &[other_pk, pk], "v1.2.3", &subjects).unwrap();
    }

    #[test]
    fn tag_mismatch_rejected() {
        let (seed, pk) = seed_and_pub();
        let subjects = vec![subj("a.tar.gz", b"aaa")];
        let dsse = sign_bytes(&seed, &subjects, "v1.2.3");
        let e = verify_release_dsse(&dsse, &[pk], "v1.2.4", &subjects).unwrap_err();
        assert!(e.contains("predicate tag"), "{e}");
    }

    #[test]
    fn tampered_subject_rejected() {
        let (seed, pk) = seed_and_pub();
        let signed = vec![subj("a.tar.gz", b"aaa")];
        let dsse = sign_bytes(&seed, &signed, "v1.2.3");
        let expected = vec![subj("a.tar.gz", b"TAMPERED")];
        let e = verify_release_dsse(&dsse, &[pk], "v1.2.3", &expected).unwrap_err();
        assert!(e.contains("subject set mismatch"), "{e}");
    }

    #[test]
    fn missing_subject_rejected() {
        // Attestation covers one artifact; verifier expects two — an
        // artifact the release added without attesting must fail.
        let (seed, pk) = seed_and_pub();
        let signed = vec![subj("a.tar.gz", b"aaa")];
        let dsse = sign_bytes(&seed, &signed, "v1.2.3");
        let expected = vec![subj("a.tar.gz", b"aaa"), subj("b.tar.gz", b"bbb")];
        let e = verify_release_dsse(&dsse, &[pk], "v1.2.3", &expected).unwrap_err();
        assert!(e.contains("subject set mismatch"), "{e}");
    }

    #[test]
    fn pubkeys_file_roundtrip() {
        let d = tmp_dir("pubkeys");
        let (_, pk) = seed_and_pub();
        let path = d.join("release-attest.pub");
        std::fs::write(
            &path,
            format!("# comment\n\ned25519:{}\n", hash::to_hex_bytes(&pk)),
        )
        .unwrap();
        let keys = parse_pubkeys_file(path.to_str().unwrap()).unwrap();
        assert_eq!(keys, vec![pk]);
    }

    #[test]
    fn pubkeys_file_rejects_unknown_scheme() {
        let d = tmp_dir("pubkeys-bad");
        let path = d.join("bad.pub");
        std::fs::write(&path, "p256:abcd\n").unwrap();
        assert!(parse_pubkeys_file(path.to_str().unwrap()).is_err());
    }

    #[test]
    fn seed_file_accepts_raw_and_hex() {
        let d = tmp_dir("seed");
        let raw = d.join("raw.key");
        std::fs::write(&raw, [7u8; 32]).unwrap();
        let hex = d.join("hex.key");
        std::fs::write(&hex, format!("{}\n", "07".repeat(32))).unwrap();
        assert_eq!(
            *read_seed_file(raw.to_str().unwrap()).unwrap(),
            *read_seed_file(hex.to_str().unwrap()).unwrap()
        );
    }

    #[test]
    fn validate_tag_matrix() {
        assert!(validate_tag("v0.4.0").is_ok());
        assert!(validate_tag("v1.2.3-rc.1").is_ok());
        assert!(validate_tag("0.4.0").is_err());
        assert!(validate_tag("v1.2").is_err());
        assert!(validate_tag("v1.2.x").is_err());
        assert!(validate_tag("v1.2.3-").is_err());
    }

    #[test]
    fn duplicate_basename_rejected() {
        let d = tmp_dir("dup");
        std::fs::create_dir_all(d.join("x")).unwrap();
        std::fs::create_dir_all(d.join("y")).unwrap();
        std::fs::write(d.join("x/same.tar.gz"), b"one").unwrap();
        std::fs::write(d.join("y/same.tar.gz"), b"two").unwrap();
        let paths = vec![
            d.join("x/same.tar.gz").to_str().unwrap().to_owned(),
            d.join("y/same.tar.gz").to_str().unwrap().to_owned(),
        ];
        assert!(subjects_for(&paths).is_err());
    }
}
