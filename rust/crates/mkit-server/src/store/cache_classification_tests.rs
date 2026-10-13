//! The classification registry deliberately requires auditing each new constructor.
#![allow(clippy::unwrap_used)] // Invalid fixtures must fail immediately.

use std::collections::BTreeSet;

use super::*;
use crate::quota::QuotaScope;
use crate::repo::{NamespaceKey, RepoName};

#[test]
#[allow(clippy::too_many_lines)] // Each registry entry must exercise its actual constructor.
fn every_namespace_key_constructor_and_range_is_live() {
    let ns = NamespaceKey::deployment_default();
    let repo = RepoName::new("cache-test").unwrap();
    let id = [1; 32];
    let other = [2; 32];
    let name = "refs/heads/main";
    let quota = QuotaScope::for_signer(&ns, &id);
    let source = Partition::Ref {
        ns: ns.clone(),
        repo: repo.clone(),
        shard_ref: name.into(),
    };
    let mut covered = BTreeSet::new();
    macro_rules! key {
        ($constructor:ident, $value:expr) => {{
            assert!(covered.insert(stringify!($constructor)));
            assert_eq!(
                cacheability(&$value),
                Cacheability::Live,
                stringify!($constructor)
            );
        }};
    }
    macro_rules! range {
        ($constructor:ident, $value:expr) => {{
            assert!(covered.insert(stringify!($constructor)));
            let (start, end) = $value;
            assert_eq!(
                cacheability(&start),
                Cacheability::Live,
                stringify!($constructor)
            );
            assert_eq!(
                cacheability(&end),
                Cacheability::Live,
                stringify!($constructor)
            );
            assert_eq!(
                scan_cacheability(&start, &end),
                Cacheability::Live,
                stringify!($constructor)
            );
        }};
    }
    key!(cache_purge, keys::cache_purge("purge-1").unwrap());
    key!(
        cache_purge_generation,
        keys::cache_purge_generation("scope")
    );
    range!(class_range, keys::class_range(keys::TAG_OBJECT_INDEX));
    key!(layout_version, keys::layout_version());
    key!(sharding_marker, keys::sharding_marker());
    key!(addressing_marker, keys::addressing_marker());
    key!(inspection_marker, keys::inspection_marker());
    key!(inspection_flag, keys::inspection_flag(&repo, &id));
    key!(inspection_version, keys::inspection_version(&repo));
    key!(inspection_hold, keys::inspection_hold(&repo, &id, &other));
    range!(
        inspection_hold_range,
        keys::inspection_hold_range(&repo, &id)
    );
    key!(
        inspection_hold_index,
        keys::inspection_hold_index(&repo, &id)
    );
    key!(
        inspection_hold_manifest,
        keys::inspection_hold_manifest(&repo, &id)
    );
    key!(namespace_record, keys::namespace_record());
    key!(repo_record, keys::repo_record(&repo));
    key!(repo_listing_prefix, keys::repo_listing_prefix(true));
    key!(repo_listing, keys::repo_listing(&repo, true));
    key!(repo_visibility, keys::repo_visibility(&repo));
    key!(
        repo_visibility_revision,
        keys::repo_visibility_revision(&repo)
    );
    key!(repo_known, keys::repo_known(&repo));
    key!(repo_storage, keys::repo_storage(&repo));
    key!(repo_storage_pack, keys::repo_storage_pack(&repo, &id));
    key!(ref_key, keys::ref_key(&repo, name));
    range!(ref_prefix_range, keys::ref_prefix_range(&repo, "refs/"));
    key!(ref_index_key, keys::ref_index_key(&repo, name));
    range!(
        ref_index_prefix_range,
        keys::ref_index_prefix_range(&repo, "refs/")
    );
    key!(publication, keys::publication(&repo, name));
    key!(advance, keys::advance(&repo, name, 1));
    key!(published_ref, keys::published_ref(&repo, name));
    key!(published_index, keys::published_index(&repo, name));
    key!(published_member, keys::published_member(&repo, &id));
    range!(
        published_range,
        keys::published_range(&repo, "refs/", false)
    );
    key!(replay, keys::replay(&id));
    key!(replay_expiry, keys::replay_expiry(10, &id));
    range!(replay_expiry_before, keys::replay_expiry_before(10));
    key!(quota, keys::quota(&quota));
    key!(quota_window, keys::quota_window(10, &quota));
    range!(quota_window_before, keys::quota_window_before(10));
    key!(quota_shard, keys::quota_shard(10));
    key!(quota_view, keys::quota_view(10));
    key!(
        quota_contribution,
        keys::quota_contribution(10, &source).unwrap()
    );
    key!(quota_total, keys::quota_total(10));
    range!(
        quota_namespace_before,
        keys::quota_namespace_before(keys::TAG_QUOTA_TOTAL, 10)
    );
    range!(
        quota_namespace_window,
        keys::quota_namespace_window(keys::TAG_QUOTA_CONTRIBUTION, 10)
    );
    key!(ticket, keys::ticket(&id));
    key!(
        ticket_index,
        keys::ticket_index(&repo, name, &id, &other).unwrap()
    );
    key!(tickets_per_ref, keys::tickets_per_ref(&repo, name).unwrap());
    key!(
        tickets_per_signer,
        keys::tickets_per_signer(&repo, name, &id).unwrap()
    );
    key!(fork_job, keys::fork_job(&repo));
    key!(fork_set, keys::fork_set(&repo, 0));
    key!(membership, keys::membership(&repo, &id));
    range!(membership_repo_range, keys::membership_repo_range(&repo));
    key!(verification, keys::verification(&repo, &id));
    key!(verify_job, keys::verify_job(&repo, &id));
    key!(
        verify_row,
        keys::verify_row(&repo, &id, keys::VC_FRAME, Some(&other))
    );
    range!(verify_range, keys::verify_range(&repo, &id, None));
    key!(object_index, keys::object_index(&repo, &id, &other));
    range!(
        object_index_repo_range,
        keys::object_index_repo_range(&repo)
    );
    range!(object_index_range, keys::object_index_range(&repo, &id));
    key!(reservation, keys::reservation("reservation-1").unwrap());
    key!(
        outcome_pending,
        keys::outcome_pending(1, "reservation-1").unwrap()
    );
    key!(relay, keys::relay(1));
    key!(relay_high_water, keys::relay_high_water(&source).unwrap());
    key!(relay_scan, keys::relay_scan());
    key!(outbox_sequence, keys::outbox_sequence());
    key!(outcome_backlog, keys::outcome_backlog());
    key!(authority_generation, keys::authority_generation());
    key!(revoke_cursor, keys::revoke_cursor(false));
    key!(grant_epoch, keys::grant_epoch());
    key!(epoch_lease, keys::epoch_lease());
    key!(leased_shard, keys::leased_shard(&repo, name));
    key!(lease_recovery, keys::lease_recovery());
    key!(lease_reconcile, keys::lease_reconcile());
    key!(backup_state, keys::backup_state());
    key!(timer, keys::timer(10, 1, b"timer"));
    key!(timer_retry, keys::timer_retry(20, 1, b"timer", 10, 1));
    key!(holder, keys::holder(&id, &ns, &repo).unwrap());
    range!(holders_of, keys::holders_of(&id));
    key!(hold, keys::hold(&id, &other));
    range!(holds_of, keys::holds_of(&id));
    key!(pending_holder, keys::pending_holder(&id, &other));
    range!(pending_holders_of, keys::pending_holders_of(&id));
    key!(content_takedown, keys::content_takedown(&id, &other));
    range!(content_takedowns_of, keys::content_takedowns_of(&id));
    key!(block, keys::block(&id));
    key!(object_state, keys::object_state(&id));

    // Predicates/parsers do not introduce a key family. Keep the exemption
    // explicit so adding a constructor cannot silently escape this audit.
    let non_constructors = [
        "is_ref_key",
        "validate_reservation_id",
        "timer_retry_state",
        "parse",
        "quota_for_window",
    ];
    let declared: BTreeSet<_> = include_str!("keys.rs")
        .lines()
        .filter_map(|line| line.strip_prefix("pub fn "))
        .filter_map(|signature| signature.split_once('(').map(|(name, _)| name))
        .filter(|name| !non_constructors.contains(name))
        .collect();
    assert_eq!(
        covered, declared,
        "new key constructors require a classification audit"
    );

    for sub in [
        keys::VC_JOB,
        keys::VC_FRAME,
        keys::VC_CHILD,
        keys::VC_BASE,
        keys::VC_CANDIDATE,
        keys::VC_HISTORY,
        keys::VC_DEPENDENCY,
    ] {
        for row_id in [None, Some(&other)] {
            assert_eq!(
                cacheability(&keys::verify_row(&repo, &id, sub, row_id)),
                Cacheability::Live
            );
        }
    }
    for public in [false, true] {
        assert_eq!(
            cacheability(&keys::repo_listing(&repo, public)),
            Cacheability::Live
        );
        let (start, end) = keys::published_range(&repo, "refs/", public);
        assert_eq!(scan_cacheability(&start, &end), Cacheability::Live);
        assert_eq!(
            cacheability(&keys::revoke_cursor(public)),
            Cacheability::Live
        );
    }
}

#[test]
fn private_reserved_unknown_and_malformed_namespace_keys_are_live() {
    for raw in [
        b"ah\0".as_slice(),
        b"an\0nonce",
        b"ao\0operation",
        b"ae\0entry",
        b"ai\0receipt",
        b"tb\0",
        b"l\0",
        b"nl\0",
        b"future\0value",
        b"",
        b"missing-terminator",
        b"i\0short",
        b"v\0extra",
        b"r\0",
    ] {
        let key = Key::new(raw.to_vec());
        assert_eq!(cacheability(&key), Cacheability::Live);
        assert_eq!(scan_cacheability(&key, &key), Cacheability::Live);
    }
}

#[test]
fn every_partition_kind_has_a_distinct_cache_identity_and_live_rows() {
    let ns = NamespaceKey::deployment_default();
    let repo = RepoName::new("cache-test").unwrap();
    let partitions = [
        Partition::Namespace(ns.clone()),
        Partition::Coordinator(ns.clone()),
        Partition::Ref {
            ns: ns.clone(),
            repo: repo.clone(),
            shard_ref: "refs/heads/main".into(),
        },
        Partition::RepoIndex {
            ns: ns.clone(),
            repo: repo.clone(),
            prefix: 0,
        },
        Partition::RefIndex {
            ns,
            repo,
            bucket: 0,
        },
        Partition::ContentShard(0),
    ];
    let mut identities = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    for partition in partitions {
        assert!(identities.insert(partition.encode().unwrap()));
        kinds.insert(partition.kind());
        assert_eq!(cacheability(&keys::layout_version()), Cacheability::Live);
    }
    assert_eq!(
        kinds,
        BTreeSet::from([
            "namespace",
            "coordinator",
            "ref",
            "repo_index",
            "ref_index",
            "content"
        ])
    );
    let body = include_str!("partition.rs")
        .split_once("pub enum Partition {")
        .unwrap()
        .1
        .split_once("\n}\n")
        .unwrap()
        .0;
    let declared: BTreeSet<_> = body
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let name = line.split(['(', ' ', ',']).next()?;
            name.chars()
                .next()
                .filter(char::is_ascii_uppercase)
                .map(|_| name)
        })
        .collect();
    assert_eq!(
        declared,
        BTreeSet::from([
            "Namespace",
            "Coordinator",
            "Ref",
            "RepoIndex",
            "RefIndex",
            "ContentShard"
        ])
    );
}

#[test]
fn only_content_addressed_pack_blobs_are_immutable() {
    let id = [1; 32];
    for (key, expected) in [
        (BlobKey::pack(id), Cacheability::Immutable),
        (BlobKey::upload_marker(id), Cacheability::Live),
        (BlobKey::object(id), Cacheability::Live),
        (BlobKey::object_offsets(id), Cacheability::Live),
    ] {
        assert_eq!(blob_cacheability(&key), expected);
    }
}

#[test]
fn new_blob_constructors_require_a_classification_audit() {
    let declared: BTreeSet<_> = include_str!("blob.rs")
        .lines()
        .filter(|line| line.contains(" -> Self {"))
        .filter_map(|line| line.trim().strip_prefix("pub const fn "))
        .filter_map(|signature| signature.split_once('(').map(|(name, _)| name))
        .collect();
    assert_eq!(
        declared,
        BTreeSet::from(["pack", "upload_marker", "object", "object_offsets"])
    );
}
