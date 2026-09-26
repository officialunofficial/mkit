//! [`storage_suite!`](crate::storage_suite) and the case lists it expands.
//! Each list is written once and feeds both the macro and the
//! [`kv_cases`](super::kv_cases) / [`blob_cases`](super::blob_cases)
//! registries.

/// Expands to one `#[test]` per case in a module named `$name`: tests are
/// `$name::<case>` (`memory::kv_first_failing_precondition_index`, …), so
/// the test runner names a failing case. Usable from any crate's `tests/`
/// directory; the invoking crate needs no tokio dependency.
///
/// - `kv = <expr>`: a [`KvHarness`](crate::storage::KvHarness), evaluated
///   once per case; runs the `kv_*`, `dur_*` and `idx_*` cases.
/// - `blob = <expr>`: a [`BlobHarness`](crate::storage::BlobHarness) such
///   as `MemoryBlobStore::default`; runs the `blob_*` cases.
///
/// ```ignore
/// mkit_server_conformance::storage_suite!(sqlite, kv = SqliteHarness::new());
/// mkit_server_conformance::storage_suite!(fs, blob = || FsBlobStore::new(temp()));
/// ```
#[macro_export]
macro_rules! storage_suite {
    ($name:ident, kv = $kv:expr, blob = $blob:expr $(,)?) => {
        #[allow(unused_imports)]
        mod $name {
            use super::*;
            $crate::__with_kv_cases!(__storage_tests { $kv });
            $crate::__with_blob_cases!(__storage_tests { $blob });
        }
    };
    ($name:ident, kv = $kv:expr $(,)?) => {
        #[allow(unused_imports)]
        mod $name {
            use super::*;
            $crate::__with_kv_cases!(__storage_tests { $kv });
        }
    };
    ($name:ident, blob = $blob:expr $(,)?) => {
        #[allow(unused_imports)]
        mod $name {
            use super::*;
            $crate::__with_blob_cases!(__storage_tests { $blob });
        }
    };
}

/// Calls `$crate::$callback! { $args ; <module>::{ <case>, … } … }` with
/// every case over a `KvHarness`.
#[doc(hidden)]
#[macro_export]
macro_rules! __with_kv_cases {
    ($callback:ident { $($args:tt)* }) => {
        $crate::$callback! { $($args)* ;
            kv::{
                kv_get_missing_none,
                kv_put_then_get,
                kv_empty_value_distinct_from_absent,
                kv_delete_then_get_none,
                kv_has_matches_get,
                kv_get_many_order_and_missing,
                kv_absent_ok_and_fail,
                kv_present_ok_and_fail,
                kv_equals_ok_and_fail_reports_observed,
                kv_first_failing_precondition_index,
                kv_failed_batch_writes_nothing,
                kv_put_delete_same_key_last_write_wins,
                kv_check_only_batch_writes_nothing,
                kv_scan_byte_order,
                kv_scan_bounds_half_open,
                kv_scan_cursor_resumes_strictly_after,
                kv_scan_pagination_stable_under_concurrent_puts_after_cursor,
                kv_scan_short_page_still_returns_next,
                kv_scan_foreign_cursor_rejected,
                kv_scan_limit_respected,
                kv_oversize_key_invalid,
                kv_oversize_value_invalid,
                kv_batch_limits_invalid,
                kv_partition_encoding_golden,
                kv_partitions_isolated,
                kv_codec_golden_values_roundtrip,
                kv_concurrent_absent_single_winner,
                kv_refs_only_rejects_other_classes,
                kv_non_atomic_rejects_multi_write_batch,
                kv_layout_version_key_roundtrip,
                kv_refs_only_reports_implicit_layout_version,
                kv_probe_ok,
                kv_class_tags_are_zero_terminated,
                kv_not_after_past_deadline_fails_writing_nothing,
                kv_not_after_future_deadline_commits,
                kv_not_after_is_checked_before_later_preconditions,
                kv_not_after_evaluated_at_apply_not_at_build,
                kv_not_after_uses_store_clock_not_caller_clock,
                kv_not_after_pre_epoch_clock_fails_closed,
                kv_not_after_on_single_key_batch,
                kv_full_store_rejects_writes_but_serves_reads_and_deletes,
                kv_stats_reports_growth_and_shrink,
                kv_panic_in_check_and_write_recovers,
            }
            durability::{
                dur_cancelled_apply_is_all_or_nothing,
                dur_crash_restart_atomic_at_last_commit,
                dur_export_import_roundtrip,
            }
            content_index::{
                idx_holder_add_idempotent,
                idx_holder_remove,
                idx_holders_pagination,
                idx_hold_blocks_collection,
                idx_expired_hold_allows_collection,
                idx_grace_period,
                idx_block_unblock,
                idx_objects_in_different_shards_isolated,
                idx_gc_commit_then_add_hold_unavailable,
                idx_blocked_on_add,
                idx_hold_extension_keeps_max,
            }
        }
    };
}

/// Calls `$crate::$callback! { $args ; blob::{ <case>, … } }` with every
/// case over a `BlobHarness`.
#[doc(hidden)]
#[macro_export]
macro_rules! __with_blob_cases {
    ($callback:ident { $($args:tt)* }) => {
        $crate::$callback! { $($args)* ;
            blob::{
                blob_roundtrip,
                blob_zero_length,
                blob_hash_mismatch_rejected_nothing_visible,
                blob_len_short_rejected,
                blob_len_long_rejected,
                blob_abort_leaves_nothing,
                blob_dropped_sink_leaves_nothing,
                blob_identical_reput_already_present,
                blob_concurrent_same_key_both_succeed,
                blob_get_missing_none,
                blob_head_len,
                blob_range_first_middle_last,
                blob_multi_chunk_write_order,
                blob_probe_ok,
                blob_delete_then_get_none,
                blob_get_large_is_streamed,
            }
        }
    };
}

/// One `#[test]` per case, each running the case on `$harness`.
#[doc(hidden)]
#[macro_export]
macro_rules! __storage_tests {
    ($harness:expr ; $($module:ident::{ $($case:ident),* $(,)? })*) => {
        $($(
            #[test]
            fn $case() {
                $crate::__private::run(
                    stringify!($case),
                    $crate::storage::$module::$case($harness),
                );
            }
        )*)*
    };
}

/// The `(name, case)` list for harness type `$h`.
#[doc(hidden)]
#[macro_export]
macro_rules! __case_registry {
    ($h:ident ; $($module:ident::{ $($case:ident),* $(,)? })*) => {
        vec![$($(
            (
                stringify!($case),
                (|h: $h| -> $crate::__private::BoxFuture<'static, $crate::storage::Outcome> {
                    ::std::boxed::Box::pin($crate::storage::$module::$case(h))
                }) as $crate::storage::CaseFn<$h>,
            ),
        )*)*]
    };
}
