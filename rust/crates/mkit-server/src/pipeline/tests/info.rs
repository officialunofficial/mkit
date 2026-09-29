//! Discovery reflects deployment configuration without reading stores.
use super::*;
use crate::repo::MultiAddressing;

#[test]
fn indexed_startup_requires_ticketed_multi_and_advertises_effective_limits() {
    let mut c = cfg(authv2());
    c.indexed = Some(crate::indexed::IndexedConfig::default());
    c.ticket_keys =
        Some(crate::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap());
    let Err(error) = Pipeline::new(
        MemoryBlobStore::default(),
        Spy::new(store(&clock())),
        Hooks::new(),
        c.clone(),
        clock(),
        Arc::new(SpyMetrics::default()),
    ) else {
        panic!("Single addressing unexpectedly accepted indexed mode");
    };
    assert_eq!(error.code(), Code::InvalidArgument);
    c.addressing = Addressing::Multi(MultiAddressing::new());
    c.write_policy = WritePolicy::Owner;
    let e = build(c.clone(), Spy::new(store(&clock())), Hooks::new(), clock());
    let info = e.pipe.server_info();
    assert!(info.indexed_mode);
    assert_eq!(info.max_delta_chain_depth, 50);
    assert_eq!(info.max_pack_bytes, c.upload_limits.max_total_bytes);
    assert_eq!(info.begin_upload_threshold_bytes, 0);
}

#[test]
fn server_info_clamps_pack_limit_without_multipart_storage() {
    let mut c = cfg(AuthMode::Open);
    c.upload_limits.max_total_bytes = 32 * 1024 * 1024;
    let pipe = Pipeline::new(
        super::stream::Counting::default(),
        store(&clock()),
        Hooks::new(),
        c.clone(),
        clock(),
        Arc::new(crate::NoopMetrics),
    )
    .unwrap();
    assert_eq!(pipe.server_info().max_pack_bytes, c.part_size);
}

#[test]
fn server_info_defaults_and_custom_limits_read_no_store() {
    let mut c = cfg(AuthMode::Open);
    let defaults = build(c.clone(), Spy::new(store(&clock())), Hooks::new(), clock());
    let info = defaults.pipe.server_info();
    assert_eq!(info.protocol, "mkit.transport.v1");
    assert_eq!(info.spec_version, 2);
    assert_eq!(info.max_pack_bytes, c.upload_limits.max_total_bytes);
    assert_eq!(info.part_size, mkit_core::upload_parts::MIN_PART_SIZE);
    assert_eq!(info.max_parts, 10_000);
    assert_eq!(info.max_list_refs_page_size, 1000);
    assert_eq!(info.begin_upload_threshold_bytes, u64::MAX);
    assert_eq!(info.namespace_policy, "single-repository");
    assert_eq!(info.index_fanout, 4096);
    assert_eq!(info.max_delta_chain_depth, 0);
    assert!(info.atomic_advance);
    assert!(!info.indexed_mode && !info.admission);
    assert!(info.receipt_public_key.is_empty());
    assert!(info.receipt_key_id.is_empty() && info.grant_schemes.is_empty());
    assert_eq!(defaults.pipe.meta.calls(), 0);

    c.part_size = 32 * 1024 * 1024;
    c.max_parts = 1;
    c.upload_limits.max_total_bytes = c.part_size;
    c.max_list_refs_page_size = 10_000;
    c.begin_upload_threshold_bytes = u64::MAX;
    let kv = store(&clock()).with_capabilities(StoreCapabilities::refs_only());
    let custom = build(c.clone(), Spy::new(kv), Hooks::new(), clock());
    let info = custom.pipe.server_info();
    assert_eq!(info.part_size, c.part_size);
    assert_eq!(info.max_parts, 1);
    assert_eq!(info.max_pack_bytes, c.part_size);
    assert_eq!(info.max_list_refs_page_size, 10_000);
    assert_eq!(info.begin_upload_threshold_bytes, u64::MAX);
    assert!(!info.atomic_advance);
    assert_eq!(custom.pipe.meta.calls(), 0);
}

#[test]
fn server_info_admission_and_multi_always_require_begin_upload() {
    for multi in [false, true] {
        for any in [false, true] {
            let mut c = cfg(authv2());
            c.ticket_keys = Some(
                crate::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap(),
            );
            c.begin_upload_threshold_bytes = 123;
            if multi {
                let policy = if any {
                    NamespacePolicy::Any {
                        unsafe_without_admission: false,
                    }
                } else {
                    NamespacePolicy::default()
                };
                c.addressing =
                    Addressing::Multi(MultiAddressing::new().with_namespace_policy(policy));
                c.write_policy = WritePolicy::Owner;
            }
            let e = build(
                c,
                Spy::new(store(&clock())),
                with_admission(Fixed(AdmissionDecision::Deny(
                    ServerError::permission_denied("unused"),
                ))),
                clock(),
            );
            let info = e.pipe.server_info();
            assert!(info.admission);
            assert_eq!(info.begin_upload_threshold_bytes, 0);
            assert_eq!(
                info.namespace_policy,
                if !multi {
                    "single-repository"
                } else if any {
                    "any"
                } else {
                    "allowlist"
                }
            );
            assert_eq!(e.pipe.meta.calls(), 0);
        }
    }
    let mut c = cfg(AuthMode::Open);
    c.addressing = Addressing::Multi(MultiAddressing::new());
    c.write_policy = WritePolicy::Owner;
    let e = build(c, Spy::new(store(&clock())), Hooks::new(), clock());
    assert!(!e.pipe.server_info().admission);
    assert_eq!(e.pipe.server_info().begin_upload_threshold_bytes, 0);
    assert_eq!(e.pipe.meta.calls(), 0);
}

#[test]
fn admission_requires_auth_v2_and_ticket_keys_at_startup() {
    for auth in [AuthMode::Open, authv2()] {
        let c = cfg(auth);
        let err = Pipeline::new(
            MemoryBlobStore::default(),
            store(&clock()),
            with_admission(Fixed(AdmissionDecision::Deny(
                ServerError::permission_denied("unused"),
            ))),
            c,
            clock(),
            Arc::new(crate::NoopMetrics),
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.public_message(),
            "admission requires auth v2 and upload ticket keys"
        );
    }
}

#[test]
fn transport_identity_admission_starts() {
    let c = cfg(AuthMode::TransportIdentity);
    let enc = Pipeline::new(
        MemoryBlobStore::default(),
        store(&clock()),
        with_admission(Fixed(AdmissionDecision::allow(Vec::new()))),
        c,
        clock(),
        Arc::new(crate::NoopMetrics),
    )
    .unwrap();
    assert_eq!(enc.server_info().begin_upload_threshold_bytes, 0);
}

#[test]
fn finite_ticket_threshold_requires_auth_v2_and_keys() {
    for auth in [AuthMode::Open, AuthMode::TransportIdentity, authv2()] {
        let mut c = cfg(auth);
        c.begin_upload_threshold_bytes = 8;
        let err = Pipeline::new(
            MemoryBlobStore::default(),
            store(&clock()),
            Hooks::new(),
            c,
            clock(),
            Arc::new(crate::NoopMetrics),
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.public_message(),
            "a ticket threshold requires auth v2 and upload ticket keys"
        );
    }
}

#[test]
fn multi_transport_identity_is_refused_at_startup() {
    let mut c = cfg(AuthMode::TransportIdentity);
    c.addressing = Addressing::Multi(MultiAddressing::new());
    c.write_policy = WritePolicy::Owner;
    let err = Pipeline::new(
        MemoryBlobStore::default(),
        store(&clock()),
        Hooks::new(),
        c,
        clock(),
        Arc::new(crate::NoopMetrics),
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        err.public_message(),
        "multi-repository deployments require auth v2 until transport identity carries tickets"
    );
}

#[test]
fn server_info_limits_are_validated_at_startup() {
    let reject = |c: PipelineConfig| {
        let err = Pipeline::new(
            MemoryBlobStore::default(),
            store(&clock()),
            Hooks::new(),
            c,
            clock(),
            Arc::new(crate::NoopMetrics),
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        err
    };
    for part_size in [
        0,
        1,
        4 * 1024 * 1024,
        9 * 1024 * 1024,
        64 * 1024 * 1024,
        u64::MAX,
    ] {
        let mut c = cfg(AuthMode::Open);
        c.part_size = part_size;
        reject(c);
    }
    let mut c = cfg(AuthMode::Open);
    c.max_parts = 0;
    reject(c);
    let mut c = cfg(AuthMode::Open);
    c.max_parts = 1;
    c.upload_limits.max_total_bytes = c.part_size + 1;
    assert_eq!(
        reject(c).public_message(),
        "max_pack_bytes is unreachable with part_size × max_parts"
    );
    for page_size in [0, 10_001, u32::MAX] {
        let mut c = cfg(AuthMode::Open);
        c.max_list_refs_page_size = page_size;
        reject(c);
    }
    for part_size in [8, 16, 32].map(|mib| mib * 1024 * 1024) {
        for page_size in [1, 10_000] {
            let mut c = cfg(AuthMode::Open);
            c.part_size = part_size;
            c.max_parts = u32::MAX;
            c.upload_limits.max_total_bytes = part_size * u64::from(c.max_parts);
            c.max_list_refs_page_size = page_size;
            build(c, Spy::new(store(&clock())), Hooks::new(), clock());
        }
    }
}
