//! Required import claims: signature validity and every contextual binding.

use mkit_core::{Hash, layout::RepoLayout, store::ObjectStore};
use mkit_git_bridge::gitobj::{Sha1Id, sha1_hex};
use serde::Deserialize;

const PREDICATE: &str = "https://github.com/officialunofficial/mkit/spec/predicate/git-import/v1";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Claim {
    #[serde(rename = "_type")]
    statement_type: String,
    predicate_type: String,
    subject: Vec<Subject>,
    predicate: Predicate,
}

#[derive(Deserialize)]
struct Subject {
    name: String,
    digest: Digests,
}

#[derive(Deserialize)]
struct Digests {
    blake3: String,
    sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Predicate {
    git_commit: String,
    ref_name: String,
    remote_url: String,
    schema_version: u32,
    spec_version: u32,
}

pub(super) struct Context<'a> {
    pub layout: &'a RepoLayout,
    pub store: &'a ObjectStore,
    pub source: &'a str,
    pub remote: &'a str,
    pub signer: [u8; 32],
}

impl Context<'_> {
    pub(super) fn matches(&self, ref_name: &str, git_id: &Sha1Id, twin: &Hash) -> bool {
        let mut registry = mkit_attest::verify::Registry::new();
        let keyid = format!(
            "blake3:{}",
            mkit_core::to_hex(&mkit_core::hash::hash(&self.signer))
        );
        registry.add(
            keyid,
            mkit_attest::verify::TrustRoot::Ed25519PubKey(self.signer),
        );
        let mkit_ref = ref_name.strip_prefix("refs/heads/").map_or_else(
            || ref_name.to_owned(),
            |branch| format!("refs/remotes/{}/{branch}", self.remote),
        );
        let Ok(paths) = mkit_attest::store::list(self.layout, twin) else {
            return false;
        };
        let Ok(object) = self.store.read_object(twin) else {
            return false;
        };
        let Ok(bytes) = mkit_core::serialize(&object) else {
            return false;
        };
        let sha256 = mkit_attest::statement::sha256_hex(&bytes);
        paths.into_iter().any(|path| {
            let Ok(envelope) = mkit_attest::store::load(&path) else {
                return false;
            };
            if !mkit_attest::verify::verify(&envelope, &registry).is_ok_and(|r| r.any_verified) {
                return false;
            }
            let Ok(claim) = serde_json::from_slice::<Claim>(&envelope.payload) else {
                return false;
            };
            let [subject] = claim.subject.as_slice() else {
                return false;
            };
            claim.statement_type == mkit_attest::statement::IN_TOTO_TYPE
                && claim.predicate_type == PREDICATE
                && subject.name == mkit_ref
                && subject.digest.blake3 == mkit_core::to_hex(twin)
                && subject.digest.sha256.as_ref().is_none_or(|h| *h == sha256)
                && claim.predicate.ref_name == mkit_ref
                && claim.predicate.git_commit == sha1_hex(git_id)
                && claim.predicate.remote_url == self.source
                && claim.predicate.schema_version == 1
                && claim.predicate.spec_version == mkit_git_bridge::import::IMPORT_SPEC_VERSION
        })
    }
}
