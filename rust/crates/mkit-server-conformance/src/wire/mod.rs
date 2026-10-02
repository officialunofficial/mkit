//! The black-box wire conformance suite (PRD §5.1 part b): it drives any
//! `mkit.transport.v1` server over real HTTP, given only a base URL and a
//! [`Profile`] of what the server offers. It never reaches into a
//! server's process, so it runs unchanged against `mkit-server serve`, the
//! vcs-worker under `wrangler dev`, staging, or a third party's server
//! (e.g. Workers with custom storage, or a Rust container). It is the M0
//! "nothing changes on the wire" oracle, and the M1–M5 cases extend it.
//!
//! ```no_run
//! # async fn demo() {
//! use mkit_server_conformance::wire::{Profile, WireAuth, WireTarget, run};
//!
//! let target = WireTarget {
//!     base_url: "http://127.0.0.1:8080".parse().unwrap(),
//!     profile: Profile::new(WireAuth::None),
//! };
//! let report = run(&target, None).await;
//! print!("{}", report.tap());
//! assert!(!report.failed());
//! # }
//! ```
//!
//! The same suite runs from the `mkit-server-conformance wire` binary.
//!
//! # Running it
//!
//! No CI runs it during the epic; the orchestrator runs it locally, at each
//! WP that changes server behavior and at every milestone boundary.
//!
//! ```text
//! # In-process baselines (the pipeline over memory stores):
//! cargo nextest run -p mkit-server-conformance --all-features -E 'binary(/^baseline_/)'
//!
//! # vcs-worker under `wrangler dev`, from the repo root: builds the Worker,
//! # serves it from a fresh state directory and runs this suite
//! # (`--test-faults` adds the clock-skew, stats, quota and growth cases):
//! scripts/vcs-worker-conformance.sh
//! scripts/vcs-worker-conformance.sh --test-faults
//!
//! # A deployed server (staging, a third party's): the same flags with its
//! # origin, or a TOML profile (see `ProfileSpec`); `--list-refs 0` skips the
//! # 10,000-ref listing.
//! cargo run -p mkit-server-conformance -- wire --base-url https://vcs.example --profile staging.toml
//! ```
//!
//! # Rules every case follows
//!
//! - It asserts Connect codes, HTTP status where the spec fixes it, and
//!   typed outcomes: never message text or chunk counts.
//! - It writes only refs under `refs/heads/conformance/<run_id>/<case>/`
//!   (and the matching `refs/mkit/packmap/...`) and uploads only fresh
//!   random packs, so it can run again and again against a persistent
//!   server. Timer cases ask a test handler to delete only their own refs.
//! - Under auth v2 each case signs with its own key, derived from the
//!   profile seed, the run id and the case name, so per-signer quotas never
//!   couple cases or runs.
//! - A case runs only if the profile's milestone is at least the case's and
//!   the profile has every feature the case requires (and none it
//!   excludes); otherwise the report lists it as skipped, with the reason.
//!
//! # Cases
//!
//! Names are stable: a baseline or a divergence list may refer to them.
//! Discovery, multi-repository, namespace-policy, epoch-lease, lag-window, ticket, listing-paging and
//! multipart cases are milestone M1; grant-scoped lease cases are M2.
//! Admission, payment CORS and outcome cases are M3. Each registry entry
//! fixes its case's milestone and required capabilities.
//!
//! | Case | Requires | Asserts |
//! |---|---|---|
//! | `admission.concurrent_duplicate_during_admit` | `admission`, `hook-stub`, `auth-v2` | Concurrent pre-reservation admission cannot double-charge or share another caller's result |
//! | `admission.challenge_402_typed_detail` | `admission`, `hook-stub`, `auth-v2` | Golden challenge detail, no-store, ordered RFC 9110 challenges (native separate lines; Worker may combine) and PAYMENT-REQUIRED |
//! | `admission.deny_403_no_detail` | `admission`, `hook-stub`, `auth-v2` | Deny without detail or payment header |
//! | `admission.no_state_on_challenge` | `admission`, `hook-stub`, `auth-v2` | Challenge leaves refs and outcome ledger empty and permits the same nonce retry |
//! | `admission.replay_skips_admission` | `admission`, `hook-stub`, `auth-v2` | Stored result, unchanged Admit count and no replay receipt |
//! | `admission.challenge_exhausted` | `admission`, `hook-stub`, `auth-v2` | Second challenge is terminal and changes no state |
//! | `admission.hook_down_unavailable` | `admission`, `hook-stub`, `auth-v2` | Unavailable changes no state or outcome |
//! | `admission.ticketless_upload_refused` | `admission`, `auth-v2` | Missing ticket is `failed_precondition` at stream end, with no challenge |
//! | `cors.preflight_payment_headers` | `hook-stub` | Payment headers allowed; preflight never reaches Admit |
//! | `cors.expose_admission_headers` | — | Every response exposes admission headers |
//! | `outcomes.aborted_on_cas_loss` | `admission`, `hook-stub`, `auth-v2`, `timers` | One CAS winner settles; `REF_CONFLICT` loser releases |
//! | `outcomes.expired_ticket` | `admission`, `hook-stub`, `auth-v2`, `short-tickets`, `timers` | Unused ticket expires and releases without settlement |
//! | `outcomes.backpressure_hook_down` | `admission`, `hook-stub`, `auth-v2`, `backlog-cap`, `timers` | Backlog blocks new admission, preserves reads and ticketed writes, then drains |
//! | `outcomes.eventual_completeness` | `admission`, `hook-stub`, `auth-v2`, `timers` | Nine retained outcomes eventually complete under the Free sink budget |
//! | `admission.helper_flow_commit` | `admission`, `hook-stub`, `auth-v2`, `tickets`, `timers` | MPP helper flow commits and settles one outcome per reservation |
//! | `grants.valid_ed25519` | `grants`, `multi-repo`, `auth-v2` | an ed25519 owner grants a write |
//! | `grants.valid_secp256k1_eip191` | `grants`, `multi-repo`, `auth-v2` | a 0x secp256k1 owner grants a write |
//! | `grants.valid_webauthn_p256` | `grants`, `multi-repo`, `auth-v2` | a 0x `WebAuthn` owner grants a write |
//! | `grants.push_flow` | `grants`, `multi-repo`, `auth-v2` | `BeginUpload`, ticketed `UploadPack` and `AdvanceRefs` commit |
//! | `grants.part_path_ignores_header` | `grants`, `multi-repo`, `auth-v2` | `UploadPart` ignores a malformed grant header |
//! | `grants.zero_x_without_grant_denied` | `grants`, `multi-repo`, `auth-v2` | a 0x namespace requires a grant |
//! | `grants.wrong_audience` | `grants`, `multi-repo`, `auth-v2` | audience mismatch denies |
//! | `grants.repository_out_of_scope` | `grants`, `multi-repo`, `auth-v2` | repository scope denies another repo |
//! | `grants.namespace_scope_covers_new_repo` | `grants`, `multi-repo`, `auth-v2` | namespace scope permits a new repo |
//! | `grants.grantee_mismatch` | `grants`, `multi-repo`, `auth-v2` | grantee binding denies |
//! | `grants.read_only_grant_for_write` | `grants`, `multi-repo`, `auth-v2` | read capability cannot write |
//! | `grants.expired` | `grants`, `multi-repo`, `auth-v2`, `test-faults` | expiry denies |
//! | `grants.not_yet_valid` | `grants`, `multi-repo`, `auth-v2`, `test-faults` | creation lead is bounded |
//! | `grants.ed25519_scheme_on_0x_denied` | `grants`, `multi-repo`, `auth-v2` | owner scheme must match namespace |
//! | `grants.webauthn_unconfigured_rp_denied` | `grants`, `multi-repo`, `auth-v2` | unknown relying party denies |
//! | `grants.epoch_above_stored` | `grants`, `multi-repo`, `auth-v2` | a future epoch denies |
//! | `grants.epoch_below_stored` | `grants`, `multi-repo`, `auth-v2`, `test-faults` | a revoked epoch denies |
//! | `grants.new_epoch_grant_works` | `grants`, `multi-repo`, `auth-v2`, `test-faults` | a new epoch grant works |
//! | `grants.owner_with_bad_grant_denied` | `grants`, `multi-repo`, `auth-v2` | owner cannot bypass a bad grant |
//! | `grants.header_without_auth_unauthenticated` | `grants`, `multi-repo`, `auth-v2` | missing auth v2 denies |
//! | `grants.duplicate_header_denied` | `grants`, `multi-repo`, `auth-v2` | duplicate header is malformed |
//! | `grants.oversize_header_denied` | `grants`, `multi-repo`, `auth-v2` | 8,193-byte header denies |
//! | `grants.non_ascii_header_denied` | `grants`, `multi-repo`, `auth-v2` | non-ASCII header denies |
//! | `grants.retry_with_changed_grant_returns_saved_result` | `grants`, `multi-repo`, `auth-v2` | replay precedes grant verification |
//! | `ref_scopes.create_only_rejects_update` | `grants`, `multi-repo`, `auth-v2` | create only rejects update |
//! | `ref_scopes.cu_grant_creates_but_match_update_denied_opaque` | `grants`, `multi-repo`, `auth-v2` | cu grant creates but match update denied opaque |
//! | `ref_scopes.force_allows_non_ff` | `grants`, `multi-repo`, `auth-v2` | force allows non ff |
//! | `ref_scopes.delete_needs_d` | `grants`, `multi-repo`, `auth-v2` | delete needs d |
//! | `ref_scopes.any_on_absent_needs_c` | `grants`, `multi-repo`, `auth-v2` | any on absent needs c |
//! | `ref_scopes.any_on_present_needs_f` | `grants`, `multi-repo`, `auth-v2` | any on present needs f |
//! | `ref_scopes.direct_packmap_update_denied` | `grants`, `multi-repo`, `auth-v2` | direct packmap update denied |
//! | `ref_scopes.head_only_update_ok` | `grants`, `multi-repo`, `auth-v2` | head only update ok |
//! | `ref_scopes.advance_wrong_packmap_denied` | `grants`, `multi-repo`, `auth-v2` | advance wrong packmap denied |
//! | `ref_scopes.rebaseline_push_under_head_scope` | `grants`, `multi-repo`, `auth-v2` | rebaseline push under head scope |
//! | `ref_scopes.begin_upload_any_flag` | `grants`, `multi-repo`, `auth-v2` | begin upload any flag |
//! | `ref_scopes.begin_upload_unmatched_denied` | `grants`, `multi-repo`, `auth-v2` | begin upload unmatched denied |
//! | `epochs.get_unsigned_zero` | `grants`, `multi-repo` | get unsigned zero |
//! | `epochs.get_ignores_auth_headers` | `grants`, `multi-repo` | get ignores auth headers |
//! | `epochs.get_bad_namespace_invalid_argument` | `grants`, `multi-repo` | get bad namespace invalid argument |
//! | `epochs.set_advances_and_get_reflects` | `grants`, `multi-repo` | set advances and get reflects |
//! | `epochs.set_retry_same_epoch` | `grants`, `multi-repo` | set retry same epoch |
//! | `epochs.set_over_step_denied` | `grants`, `multi-repo` | set over step |
//! | `epochs.set_decrease_denied` | `grants`, `multi-repo` | set decrease |
//! | `epochs.wrong_audience` | `grants`, `multi-repo` | wrong audience |
//! | `epochs.expired` | `grants`, `multi-repo` | expired |
//! | `epochs.not_yet_valid` | `grants`, `multi-repo` | not yet valid |
//! | `epochs.scheme_not_advertised` | `grants`, `multi-repo` | scheme not advertised |
//! | `epochs.namespace_not_served` | `grants`, `multi-repo` | namespace not served |
//! | `epochs.oversize_statement` | `grants`, `multi-repo` | oversize statement |
//! | `epochs.zero_x_secp256k1_statement` | `grants`, `multi-repo` | zero x secp256k1 statement |
//! | `epochs.zero_x_webauthn_statement` | `grants`, `multi-repo` | zero x webauthn statement |
//! | `epochs.old_grant_denied_new_grant_works_after_set` | `grants`, `multi-repo` | old grant denied new grant works after set |
//! | `reads.signed_verified_in_full` | `signed-reads`, `multi-repo`, `auth-v2` | a bad signature is `unauthenticated` before repository lookup |
//! | `reads.public_unsigned_ok` | `signed-reads`, `multi-repo`, `auth-v2` | a public repository reads unsigned |
//! | `reads.private_anonymous_not_found` | `signed-reads`, `multi-repo`, `auth-v2` | an anonymous private read is `not_found` |
//! | `reads.private_owner_ok` | `signed-reads`, `multi-repo`, `auth-v2` | the owner reads its private repository |
//! | `reads.private_read_grant_ok` | `signed-reads`, `grants`, `multi-repo`, `auth-v2` | a `read` grant reads |
//! | `reads.private_write_only_not_found` | `signed-reads`, `grants`, `multi-repo`, `auth-v2` | a write grant does not read |
//! | `reads.private_expired_signature_unauthenticated` | `signed-reads`, `multi-repo`, `auth-v2` | an expired envelope is `unauthenticated` |
//! | `reads.private_grant_old_epoch_not_found` | `signed-reads`, `grants`, `multi-repo`, `auth-v2`, `test-faults` | an epoch bump revokes the grant |
//! | `reads.private_not_found_byte_identical` | `signed-reads`, `multi-repo`, `auth-v2` | private and missing replies are byte-identical |
//! | `reads.url_token_mint_ok` | `signed-reads`, `multi-repo`, `auth-v2` | a minted token passes all three phases |
//! | `reads.url_token_private_without_read_not_found` | `signed-reads`, `multi-repo`, `auth-v2` | no read access mints `not_found` |
//! | `reads.url_token_anonymous_unauthenticated` | `signed-reads`, `multi-repo`, `auth-v2` | an unsigned mint is `unauthenticated` |
//! | `reads.url_token_bounds_invalid_argument` | `signed-reads`, `multi-repo`, `auth-v2` | bad targets are `invalid_argument` |
//! | `reads.url_token_ttl_clamped` | `signed-reads`, `multi-repo`, `auth-v2` | `ttl_seconds` clamps to the configured ttl |
//! | `visibility.envelope_owner` | `signed-reads`, `multi-repo`, `auth-v2` | the owner flips visibility |
//! | `visibility.statement_ed25519` | `signed-reads`, `multi-repo`, `auth-v2` | an ed25519 owner statement applies |
//! | `visibility.statement_eip191` | `signed-reads`, `grants`, `multi-repo`, `auth-v2` | a 0x owner statement applies |
//! | `visibility.grant_never_authorizes` | `signed-reads`, `grants`, `multi-repo`, `auth-v2` | a grant cannot change visibility |
//! | `visibility.older_created_denied` | `signed-reads`, `multi-repo`, `auth-v2` | an older statement denies |
//! | `visibility.bad_mode_invalid_argument` | `signed-reads`, `multi-repo`, `auth-v2` | unset or `UNSPECIFIED` mode is `invalid_argument` |
//! | `visibility.oversize_statement_permission_denied` | `signed-reads`, `multi-repo`, `auth-v2` | a statement over 8,192 bytes denies |
//! | `info.shape_and_policy` | | unauthenticated discovery reports consistent limits, policy and bounded private caching |
//! | `info.ignores_repository_header` | | absent, nonexistent and malformed repository identities yield identical response bytes |
//! | `policy.owner_write_allowed` | `namespace-policy`, `multi-repo`, `auth-v2` | an allowlisted namespace owner writes and reads its ref |
//! | `policy.non_owner_write_denied` | `namespace-policy`, `multi-repo`, `auth-v2` | a non-owner gets `permission_denied`; reads show existing and absent refs unchanged |
//! | `policy.non_allowlisted_namespace_denied` | `namespace-policy`, `multi-repo`, `auth-v2` | an owner outside the allowlist gets `permission_denied`; the repository is not created |
//! | `leases.idle_shard_renews_at_new_epoch` | `epoch-leases`, `grants`, `multi-repo`, `auth-v2`, `test-faults` | after a `SetGrantEpoch`, an epoch-0 grant is refused on a shard that never held a lease, and an epoch-1 grant writes there |
//! | `leases.lease_expires_before_revocation_completes` | `epoch-leases`, `grants`, `multi-repo`, `auth-v2`, `test-faults` | the warm lease expires before revocation is requested and completes, with no ack in flight; the old grant is refused, its ref unchanged, and the new grant writes on a skewed request |
//! | `lag.list_refs_window` | `auth-v2`, `test-faults`; excludes `multi-repo`; D34 | a write held in the relay reads strongly at once, is absent from `ListRefs`, then is listed within the lag bound |
//! | `lag.membership_window` | `multi-repo`, `auth-v2`, `tickets`, `test-faults`; D34 | a ticketed push held in the relay is not a member without its hint, then is within the lag bound |
//! | `leases.bump_completes_and_writes_continue` | `epoch-leases`, `test-faults`; excludes `multi-repo` | on a fresh target, a bump completes; repeating the epoch is rejected, then a second write succeeds |
//! | `timers.directive_fires_due` | `test-faults` | a future timer remains; a skewed tick deletes only the due ref |
//! | `timers.fire_on_schedule` | `test-faults`, `timers` | the driver deletes the ref within 20 s without a manual tick |
//! | `timers.redelivery_is_idempotent` | `test-faults` | repeated ticks succeed with no further effects |
//! | `refs.read_missing` | | an absent ref reads `exists = false`, empty id |
//! | `refs.update_any_then_read` | | `ANY` creates, then clobbers |
//! | `refs.update_missing_conflict_failed_precondition` | | `MISSING` on an existing ref; ref unchanged |
//! | `refs.update_match_conflict_failed_precondition` | | `MATCH` on absent and stale refs; a matching `MATCH` commits |
//! | `refs.update_unspecified_invalid_argument` | | unset or `UNSPECIFIED` expectation (§3) |
//! | `refs.update_any_with_expected_id_invalid_argument` | | `ANY`/`MISSING` with an `expected_id` |
//! | `refs.invalid_ref_name_invalid_argument` | | SPEC-REFS §3 names on `ReadRef`, `UpdateRef`, `AdvanceRefs` |
//! | `refs.name_over_512_bytes_invalid_argument` | | a 512-byte name works, 513 bytes is `invalid_argument` (SPEC-REFS v2 §3) |
//! | `refs.non_refs_prefix_rejected` | | a grammar-valid name outside `refs/` is `invalid_argument` on `ReadRef`, `UpdateRef`, `AdvanceRefs`, and a listing of its parent prefix (plus `ListRefs("")` on a `fresh_target`) shows nothing (SPEC-REFS v3 §2) |
//! | `refs.new_id_wrong_length_invalid_argument` | | ids that are not 32 bytes |
//! | `refs.list_prefix_stripped` | | `ListRefs` strips the prefix and sorts (SPEC-REFS §4, §4.1) |
//! | `refs.list_prefix_component_boundary` | | a prefix matches at `/` boundaries only, with or without the trailing `/` (SPEC-REFS §4) |
//! | `refs.list_invalid_prefix_invalid_argument` | | SPEC-REFS §4.2 |
//! | `refs.concurrent_missing_one_winner` | | 3 rounds of 24 racing `MISSING` creates: one wins, the rest `failed_precondition`, the ref holds the winner (SPEC-REFS §7) |
//! | `refs.concurrent_match_one_winner` | | the same for `MATCH` |
//! | `refs.many_refs_one_repository` | excludes `multi-repo` | 64 refs of one repository are written at once, read back, listed in order and advanced under `MATCH` |
//! | `advance.committed` | | both refs move |
//! | `advance.head_conflict_typed` | | `HEAD_CONFLICT` is a response, not an error; head unchanged |
//! | `advance.packmap_conflict_typed` | | `PACKMAP_CONFLICT`; neither ref moved |
//! | `advance.atomic_both_untouched` | `atomic-advance` | a head conflict leaves the packmap unchanged too |
//! | `advance.nonatomic_packmap_first` | not `atomic-advance` | a head conflict leaves the packmap advanced (§4 fallback order) |
//! | `advance.unspecified_invalid_argument` | | unset expectations, short ids |
//! | `advance.concurrent_one_committed` | | 3 rounds of 24 racing advances: one `COMMITTED`, the rest typed conflicts, both refs at the winner |
//! | `packs.exists_false_then_true` | | `PackExists` before and after an upload |
//! | `packs.pack_id_wrong_length_invalid_argument` | | on `PackExists` and `DownloadPack` |
//! | `upload.roundtrip_multi_chunk` | | 3 chunks up; the download matches bytes and BLAKE3 |
//! | `upload.empty_pack` | | header + one empty `last` chunk |
//! | `upload.first_not_header_invalid_argument` | | a chunk first; an empty stream |
//! | `upload.second_header_invalid_argument` | | a header after a header or a chunk |
//! | `upload.empty_message_invalid_argument` | | a message with neither `header` nor `chunk` |
//! | `upload.chunk_pack_id_mismatch_invalid_argument` | | §6.1 |
//! | `upload.offset_gap_invalid_argument` | | a gap and an overlap |
//! | `upload.overrun_invalid_argument` | | more bytes than declared |
//! | `upload.no_last_invalid_argument` | | the stream ends before `last` |
//! | `upload.declared_mismatch_invalid_argument` | | `last` before the declared count |
//! | `upload.hash_mismatch_not_stored` | | BLAKE3 mismatch; `PackExists` false, `DownloadPack` `not_found` |
//! | `upload.oversize_resource_exhausted` | | a header declaring `max_pack_bytes + 1` |
//! | `upload.rejected_never_overwrites_existing` | | a bad upload under a stored pack's id changes nothing |
//! | `download.not_found_before_any_message` | | §6.2 |
//! | `download.chunks_contiguous_ending_last` | | one header, contiguous chunks, `last` only at the end |
//! | `health.serving` | `health` | `Check("")` and the transport service are `SERVING`, unauthenticated (no mkit spec requires health, so it is declared) |
//! | `health.unknown_service_not_found` | `health` | |
//! | `auth.bearer_missing_unauthenticated` | `bearer` | unary reads and writes |
//! | `auth.bearer_wrong_unauthenticated` | `bearer` | wrong token, wrong scheme |
//! | `auth.bearer_applies_to_streaming` | `bearer` | `UploadPack`, `DownloadPack` |
//! | `auth.v2_missing_headers_unauthenticated` | `auth-v2` | unsigned writes; each required header dropped |
//! | `auth.v2_wrong_audience` | `auth-v2` | signed for, or sent with, another audience |
//! | `auth.v2_wrong_repository` | `auth-v2`; excludes `multi-repo` | another well-formed identity gives `not_found` in Single mode |
//! | `auth.v2_wrong_procedure` | `auth-v2` | signed for another RPC |
//! | `auth.v2_bad_signature` | `auth-v2` | a flipped bit; another signer's key |
//! | `auth.v2_body_digest_mismatch` | `auth-v2` | another body; an `X-Digest` off the commitment |
//! | `auth.v2_expired` | `auth-v2` | expired, over-long, inverted and zero-length windows |
//! | `auth.v2_version_not_2` | `auth-v2` | versions 1, 3, empty, absent |
//! | `auth.v2_nonce_not_canonical` | `auth-v2` | uppercase, 63, 65 characters, non-hex |
//! | `auth.v2_signature_not_strict` | `auth-v2` | `S + ℓ` rejected (strict Ed25519), the canonical signature accepted |
//! | `auth.v2_clock_lead_bound` | `auth-v2` | created 20 s ahead accepted, 40 s ahead rejected (30 s lead; assumes clocks within ~5 s) |
//! | `auth.v2_pack_commitment_mismatch` | `auth-v2` | length, id or kind differs from the upload header: any error (no code in the spec yet), nothing stored |
//! | `auth.v2_gzip_signed_fails_closed` | `auth-v2`, `strict-gzip-auth` | opt-in until the M2 spec decides §9.2: a signature over gzip bytes is rejected and writes nothing |
//! | `auth.v2_reads_unsigned_ok` | `auth-v2` | M0 reads need no signature |
//! | `replay.same_op_returns_saved_result_after_ref_moved` | `auth-v2`, `replay` | the `auth_v2.mjs` a, b, a sequence |
//! | `replay.concurrent_duplicates_all_succeed` | `auth-v2`, `replay` | 16 parallel duplicates, one effect |
//! | `replay.nonce_reuse_different_op_invalid_argument` | `auth-v2`, `replay` | |
//! | `replay.conflict_result_replayed` | `auth-v2`, `replay` | a stored CAS conflict answers its retry |
//! | `replay.advance_replay_equals_first_result` | `auth-v2`, `replay` | for a commit and for a conflict |
//! | `replay.upload_replay_succeeds` | `auth-v2`, `replay` | |
//! | `replay.expired_retry_rejected` | `auth-v2`, `replay`, `test-faults` | a cached result is not served past expiry |
//! | `quota.ops_exhaustion_resource_exhausted` | `auth-v2`, `quota`; not `multi-repo` | per signer (per branch under D34) |
//! | `quota.bytes_exhaustion_resource_exhausted` | `auth-v2`, `quota`; not `multi-repo` | refused at the header |
//! | `quota.exhaustion_allocates_no_replay` | `auth-v2`, `replay`, `quota`; not `multi-repo` | the nonce stays unspent |
//! | `quota.replay_not_charged` | `auth-v2`, `replay`, `quota`; not `multi-repo` | |
//! | `quota.namespace_cap_after_rollup` | `auth-v2`, `quota`, `multi-repo`, `test-faults` | D34 namespace cap across branches after a forced rollup |
//! | `tickets.begin_upload_new` | `tickets`, `auth-v2` | a new ticket has an id, part geometry, expiry and token |
//! | `tickets.begin_upload_idempotent` | `tickets`, `auth-v2` | a fresh nonce returns the live ticket, replay returns identical bytes, and another signer gets its own ticket |
//! | `tickets.begin_upload_caps` | `tickets`, `auth-v2` | the open-ticket cap has its exact public error and leaves no replay row |
//! | `tickets.expiry_timer_frees_cap_slot` | `tickets`, `auth-v2`, `test-faults`; excludes `multi-repo` | a full per-signer cap refuses; after a skewed `run-timers` tick past every expiry the expiry timer has freed the slots |
//! | `tickets.begin_upload_per_ref_cap` | `tickets`, `auth-v2`; excludes `multi-repo` | `Profile::ticket_per_ref` tickets from enough signers fill one ref; the next signer gets the exact cap error, and another ref is unaffected |
//! | `tickets.begin_upload_packmap_refused` | `tickets`, `auth-v2` | a packmap ref is an invalid target |
//! | `tickets.upload_pack_ticketed` | `tickets`, `auth-v2` | a ticketed upload succeeds and can be repeated |
//! | `tickets.upload_pack_bad_token` | `tickets`, `auth-v2` | an invalid token fails before a pack is stored |
//! | `tickets.upload_pack_binding_denied` | `tickets`, `auth-v2` | a valid token for another pack is denied |
//! | `tickets.upload_pack_expired_token` | `tickets`, `auth-v2`, `test-faults` | an expired token fails with `failed_precondition` |
//! | `tickets.advance_ticket_id_errors` | `tickets`, `auth-v2` | malformed, duplicate and excessive ticket ids have exact errors |
//! | `tickets.advance_marker_then_upload` | `tickets`, `auth-v2` | a missing marker leaves the ticket open for upload and retry |
//! | `tickets.advance_conflicts_keep_ticket` | `tickets`, `auth-v2` | typed ref conflicts preserve tickets for a corrected advance |
//! | `refs.delete_pair` | — | conditional deletion removes head and packmap together and rejects invalid inputs |
//! | `tickets.advance_ticket_bindings` | `tickets`, `auth-v2` | unknown and mismatched-ref tickets fail with exact errors under Single and Multi; a stranger is refused by ticket binding or namespace policy |
//! | `tickets.advance_other_repository` | `tickets`, `auth-v2`, `multi-repo` | a ticket cannot cross a repository boundary |
//! | `tickets.advance_expired_ticket` | `tickets`, `auth-v2`, `test-faults` | an expired ticket fails with its exact error |
//! | `indexed.pending_verification_unavailable` | `indexed-mode`, `multi-repo`, `tickets`, `auth-v2`, `test-faults` | HTTP 503, `Retry-After: 5`, one golden `PendingVerification` detail, and a successful same-nonce retry without replay |
//! | `indexed.async_verification_commits` | `indexed-async`, `multi-repo`, `tickets`, `auth-v2`, `test-faults` | a push of three 16 MiB windows answers `PendingVerification` until its scheduled slices finish (the Worker fails one mid-pack slice on purpose), then the same signed advance commits |
//! | `launch.indexed_verification_commits` | `indexed-async`, `multi-repo`, `tickets`, `auth-v2`; excludes `test-faults` | production-only >33 MiB ticketed push answers pending, then commits and publishes both refs with exact public pack bytes; the HTTP opt-in checks a 128 KiB extracted Blob, filename media policy and unsupported Worker proofs |
//! | `launch.takedown_nine_mib_publish` | `indexed-async`, `multi-repo`, `tickets`, `auth-v2`; excludes `test-faults` | ticketed canonical MKPL and more than 9 MiB of reachable Blob payload publish both paired refs with takedown on; report pending polls and whole-push wall time |
//! | `launch.takedown_chunked_publish` | `indexed-async`, `multi-repo`, `tickets`, `auth-v2`; excludes `test-faults` | valid 32-chunk file and canonical MKPL publish both paired refs with takedown on; report pending polls and whole-push wall time |
//! | `launch.admin_fixture` | `indexed-async`, `multi-repo`, `tickets`, `auth-v2`; excludes `test-faults` | bounded 131072-byte Blob and canonical `PackList` undergo ticketed verification, publish paired public refs and return exact pack bytes; the HTTP opt-in checks the extracted Blob |
//! | `uno.public_fixture` | `indexed-async`, `multi-repo`, `tickets`, `auth-v2`; excludes `test-faults` | default-public no-Set, streamed UploadPart/CompleteUpload, 402/AlreadyPresent, exact 1 MiB Blob and canonical `PackList` undergo ticketed verification, publish paired public refs and return exact pack bytes; the HTTP opt-in checks the extracted Blob |
//! | `uno.multipart_file_readback` | `indexed-async`, `multi-repo`, `tickets`, `auth-v2`, `multipart`, `http-objects`; excludes `test-faults` | 9 MB file in 36 chunks undergoes a real multipart push, pending verification and exact HTTP object/ref readback using the 304-byte chunk-offset sidecar |
//! | `launch.inspection_rejects_advance` | `indexed-async`, `multi-repo`, `tickets`, `auth-v2`, `sync-inspection`; excludes `test-faults` | configured sync inspector rejects or fails closed after real ticketed Blob verification; no success and both public/signed writer refs remain absent |
//! | `launch.read_fixture_public` | `indexed-async`, `multi-repo`, `tickets`, `auth-v2`, `http-objects`, `launch-read-fixture`; excludes `test-faults` | seeds a raw-only indexed pack, verifies publication/extraction and mints a token to an owned scratch fixture outside TAP |
//! | `launch.read_fixture_private` | `indexed-async`, `multi-repo`, `tickets`, `auth-v2`, `http-objects`, `launch-read-fixture`; excludes `test-faults` | revisits the public fixture with the same signer, changes real visibility and mints a private token without reseeding |
//! | `multipart.three_parts` | `multipart`, `auth-v2`; excludes `multi-repo` | a roughly 17 MiB three-part pack at the minimum part size completes and becomes visible |
//! | `multipart.resume_receipts` | `multipart`, `auth-v2`; excludes `multi-repo` | a client reconnects after partial upload, re-sends a part, and completes using old and new receipts |
//! | `multipart.root_mismatch_invisible` | `multipart`, `auth-v2`; excludes `multi-repo` | a wrong completion root never makes the pack visible |
//! | `multipart.cross_repository_no_oracle` | `multipart`, `auth-v2`, `multi-repo` | a foreign ticket fails, and foreign receipts use the same error code as garbage receipts; run on the memory multi-repo profile |
//! | `growth.replay_and_quota_pruned` | `auth-v2`, `replay`, `quota`, `test-faults` | records answer before expiry; after validity + grace + window the partition shrinks back to an absolute bound (R-31); needs a quota window ≤ 60 s allowing 265 writes, and a disposable server |
//! | `growth.tickets_and_outbox_pruned` | `auth-v2`, `tickets`, `quota`, `test-faults`, `timers` | open tickets grow the partition; they expire on the server's clock (skips when a ticket lives over 120 s), and once their outcome and relay rows drain and the replay records expire, it shrinks back to an absolute bound; needs a disposable server and the stats hook |
//! | `list.merge_paging_over_32_mib` | | with `Profile::merge_paging_refs` near-512-byte names (about 75,000) the listing exceeds 32 MiB and every page stays within 2 MiB; skipped at zero |
//! | `list.large_response_within_limit` | | follows tokens over `list_refs` long names; each response is at most 2 MiB |
//! | `list.paging_wire` | | token round trip, invalid tokens, and page-size defaults and cap |
//! | `repo.single_header_mismatch_not_found` | excludes `multi-repo` | Single reads with another identity give `not_found` |
//! | `repo.single_malformed_invalid_argument` | excludes `multi-repo` | Single reads reject malformed identities |
//! | `repo.single_signed_missing_header_unauthenticated` | `auth-v2`; excludes `multi-repo` | Single signed writes require X-Repository |
//! | `repo.isolation_refs` | `multi-repo`, `auth-v2` | refs and writes stay isolated, including equal names in different namespaces |
//! | `repo.signature_repository_mismatch_unauthenticated` | `multi-repo`, `auth-v2` | a signature for A sent to B is rejected |
//! | `repo.missing_repository_invalid_argument` | `multi-repo`, `auth-v2` | absent, empty, bare and malformed identities are rejected |
//! | `repo.read_missing_repo_not_found` | `multi-repo`, `auth-v2` | `ListRefs` and `ReadRef` of a nonexistent repo give `not_found` |
//! | `repo.packs_need_membership` | `multi-repo`, `auth-v2` | absent membership gives false / `not_found`; uploads still require tickets |
//! | `repository.upload_needs_ticket` | `multi-repo`, `auth-v2` | an un-ticketed upload fails with `failed_precondition` |
//! | `repository.ticketed_upload_multi` | `multi-repo`, `auth-v2`, `tickets` | a ticketed upload succeeds in Multi mode |
//! | `repo.isolation_packs` | `multi-repo`, `auth-v2` | a planted member is invisible in other repositories, with and without a ref hint |
//! | `repo.membership_read_your_writes` | `multi-repo`, `auth-v2`; D34 | unrelayed membership is visible only with its ref hint |
//! | `repo.isolation_replay` | `multi-repo`, `auth-v2`, `replay` | one nonce and body, validly signed for other repositories, commits there: a replay record in one repository never answers another |
//! | `repo.d36_hint_reads_during_lag` | `multi-repo`, `auth-v2`, `tickets`, `test-faults`; D34 | while the relay is held, `PackExists` and `DownloadPack` with `X-Mkit-Ref` see a real ticketed push, and the same hint in repositories with the same ref name do not |
//! | `repo.malformed_membership_hint_no_op` | `multi-repo`, `auth-v2` | malformed, unserved and oversized hints are ignored |
//!
//! The three membership cases run against a target whose harness seeds
//! membership fixtures (`Profile::planted_membership`); on a served
//! deployment each seeds its own fixture through a real ticketed push —
//! `BeginUpload` for `refs/heads/main`, the ticketed upload, and a
//! ticketed `AdvanceRefs` pair consuming the ticket — by that case's `repository-a`
//! signer into `<ns>/packs`, and member-true reads poll while the relay
//! catches up. The in-process Multi baseline seeds blob bytes
//! `conformance/<run_id>/<case>` and their BLAKE3 membership in
//! repository `packs`, owned by that case's `repository-a` signer.
//! Isolation and malformed-hint fixtures populate the membership index
//! and `refs/heads/main`; read-your-writes populates only that ref shard
//! and requires D34 (its D34 skip comes first, and on served deployments
//! it still skips — the index cannot be held undelivered against a live
//! relay). No relay runs while the read-your-writes case checks the
//! lagging index.
//!
//! # The `test-faults` contract
//!
//! A server that declares `test-faults` honors [`CLOCK_SKEW_HEADER`]
//! (shift its business clock for that request) and serves
//! `GET` [`STATS_PATH`] as `{"bytes": <u64>, "keys": <u64 or null>}` for
//! the partition that holds the repository's replay records and quota
//! windows: the one deployment-wide partition, or, when it shards by ref
//! (D34), the shard of the ref named by the `?ref=<full ref name>` query.
//! It also honors [`RELAY_DELAY_MS_HEADER`] (hold the write's relay
//! delivery) and the run-timers directive. Release builds do none of these. Report `keys` when you can: the
//! growth case then bounds the exact key count instead of bytes.
//!
//! `growth.replay_and_quota_pruned` needs a **disposable server**: a fresh
//! one, or one no other client writes to, with nothing else expiring on
//! that partition. It measures growth and pruning by the partition's total,
//! so other traffic, or other records being pruned during its calibration,
//! skews the measurement.
//!
//! # Reserved cases (M2–M5)
//!
//! The "Planned:" comments in this module's source name them, with
//! their milestone and feature, so later milestones add them without
//! renaming. None exists yet, so none can pass vacuously.
//!
// Planned (grants): native transport grant registration and the later read grants.
// Planned (indexed mode): `indexed.published_view_hides_quarantine`.
// Planned (HTTP objects): `http_objects.*`.
// Planned (leases): `leases.gc_*`.
// Planned (takedown): `takedown.*`.
// Planned (receipts): `receipts.*`.
// Planned (admin): `admin.*`.

mod cases;
pub(crate) mod challenges;
pub mod client;
pub mod profile;
pub mod report;
pub mod sign;

use std::collections::BTreeSet;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use futures::FutureExt as _;
use url::Url;

pub use cases::grants::owner_namespaces as grant_owner_namespaces;
pub use cases::grants::{RP_ID as GRANT_RP_ID, RP_ORIGIN as GRANT_RP_ORIGIN};
pub use cases::{CASES, Case};
pub use profile::{Feature, Milestone, Profile, ProfileSpec, QuotaLimits, WireAuth};
pub use report::{CaseReport, Report, Verdict};

use cases::{Ctx, Failure};

/// The `test-faults` directive that shifts the server's business clock for
/// one request, in milliseconds.
pub const CLOCK_SKEW_HEADER: &str = "x-mkit-test-clock-skew-ms";

/// The `test-faults` directive that holds the relay delivery of the write it
/// rides on (D34), in milliseconds.
pub const RELAY_DELAY_MS_HEADER: &str = "x-mkit-test-relay-delay-ms";

/// The `test-faults` stats endpoint.
pub const STATS_PATH: &str = "/__mkit_test/stats";

/// Bound on one case, so a hung server fails a case, not the run.
pub const CASE_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(10);

/// The Ed25519 seed (hex) an in-process server puts in `url_tokens` for a
/// `signed-reads` profile, so the suite can verify the tokens it mints.
pub const URL_TOKEN_SEED: &str = "9d4f2c8b1e6a35f07c2d9841ba6e5f3c09a17d4e8b2c6f103d5e9a7b4c8f1e2d";

/// `url_token_ttl` for the same configuration: 15 minutes.
pub const URL_TOKEN_TTL_MS: u64 = 15 * 60 * 1000;

/// A server to test.
#[derive(Debug, Clone)]
pub struct WireTarget {
    /// Its base URL; RPCs go to `{base_url}/<service>/<method>`.
    pub base_url: Url,
    /// What it offers.
    pub profile: Profile,
}

/// The namespace allowlist a Multi deployment needs for `profile`'s run:
/// every Multi case's `repository-a` and `repository-b` owner namespace,
/// derived exactly as the cases derive their signers, while
/// `policy.non_allowlisted_namespace_denied`'s `non-allowlisted` key
/// stays outside the set.
///
/// # Panics
/// `profile`'s auth is not [`WireAuth::AuthV2`].
#[must_use]
pub fn multi_allowlist(profile: &Profile) -> BTreeSet<mkit_core::repo_identity::Namespace> {
    let WireAuth::AuthV2 {
        audience,
        repository,
        seed,
    } = &profile.auth
    else {
        panic!("a Multi allowlist needs an auth v2 profile");
    };
    CASES
        .iter()
        .filter(|case| {
            case.requires.contains(&Feature::MultiRepo)
                // This stable case runs on both Single and Multi profiles.
                || case.name == "tickets.advance_ticket_bindings"
        })
        .flat_map(|case| {
            ["repository-a", "repository-b"].map(|label| {
                let label = format!("{}/{label}", case.name);
                let signer =
                    sign::Signer::derive(seed, &profile.run_id, &label, audience, repository);
                mkit_core::repo_identity::Namespace::parse(&format!(
                    "ed25519-{}",
                    signer.public_key_hex()
                ))
                .expect("a signer public key is a canonical namespace")
            })
        })
        .collect()
}

/// [`multi_allowlist`] as allowlist text — one canonical namespace per
/// line — which `mkit_server::policy::parse_namespace_allowlist` reads
/// back: the native `--namespace-allowlist` file's and the Worker
/// `NAMESPACE_ALLOWLIST` var's format.
#[must_use]
pub fn multi_allowlist_text(profile: &Profile) -> String {
    let mut text = multi_allowlist(profile)
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    text.push('\n');
    text
}

/// The fixed grant-owner namespaces ([`grant_owner_namespaces`]) as
/// allowlist text, one per line, to append to [`multi_allowlist_text`] for a
/// local deployment running the grant cases. Their keys are public test
/// seeds: never allowlist them on a shared or staging deployment.
#[must_use]
pub fn grant_owner_allowlist_text() -> String {
    let mut text = String::new();
    for namespace in grant_owner_namespaces() {
        text.push_str(&namespace.to_string());
        text.push('\n');
    }
    text
}

/// Run every case whose name contains `filter` (all when `None`) against
/// `target`, in [`CASES`] order.
pub async fn run(target: &WireTarget, filter: Option<&str>) -> Report {
    let profile = Arc::new(target.profile.clone());
    let mut report = Report {
        preamble: preamble(target),
        cases: Vec::new(),
    };
    let client = match client::Client::new(&target.base_url) {
        Ok(client) => client,
        Err(e) => {
            report.preamble.push(format!("cannot build a client: {e}"));
            report.cases = CASES
                .iter()
                .map(|c| CaseReport {
                    name: c.name,
                    verdict: Verdict::Fail(e.clone()),
                })
                .collect();
            return report;
        }
    };
    for case in CASES
        .iter()
        .filter(|c| filter.is_none_or(|f| c.name.contains(f)))
    {
        let verdict = match case.skip_reason(&profile) {
            Some(reason) => Verdict::Skip(reason),
            None => run_case(case, Ctx::new(client.clone(), profile.clone(), case.name)).await,
        };
        report.cases.push(CaseReport {
            name: case.name,
            verdict,
        });
    }
    report
}

async fn run_case(case: &Case, ctx: Ctx) -> Verdict {
    // A paced worker fixture (one UpdateRef at a time, debug wasm) is
    // slow but bounded. The 10 minute hang detector is too short for
    // 10,000 sequential Durable Object writes; native runs keep 8 in
    // flight and the ordinary ceiling.
    let timeout =
        if case.name == "list.large_response_within_limit" && ctx.profile().list_parallel == 1 {
            std::time::Duration::from_mins(45)
        } else if case.name == "list.merge_paging_over_32_mib" {
            // Tens of thousands of writes, then the relay drains their backlog.
            std::time::Duration::from_mins(30)
        } else {
            CASE_TIMEOUT
        };
    let fut = AssertUnwindSafe(case.run(ctx.clone())).catch_unwind();
    match tokio::time::timeout(timeout, fut).await {
        Err(_) => Verdict::Fail(format!("timed out after {timeout:?}")),
        Ok(Err(_)) => Verdict::Fail("the case panicked (a suite bug)".to_owned()),
        Ok(Ok(Ok(()))) => Verdict::Pass(ctx.take_note()),
        Ok(Ok(Err(Failure::Fail(why)))) => Verdict::Fail(why),
        Ok(Ok(Err(Failure::Skip(why)))) => Verdict::Skip(why),
    }
}

fn preamble(target: &WireTarget) -> Vec<String> {
    let p = &target.profile;
    let features: Vec<_> = p.features.iter().map(|f| f.as_str()).collect();
    vec![
        format!("target {}", target.base_url),
        format!(
            "profile auth={:?} milestone={:?} max_pack_bytes={} quota={:?} sharding_d34={}",
            p.auth, p.milestone, p.max_pack_bytes, p.quota, p.sharding_d34
        ),
        format!("features [{}]", features.join(", ")),
        format!(
            "run_id {} (refs under refs/heads/conformance/{}/)",
            p.run_id, p.run_id
        ),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn launch_verification_runs_without_fault_routes() {
        let mut profile = Profile::new(WireAuth::AuthV2 {
            audience: "http://localhost:8817".into(),
            repository: "default".into(),
            seed: [0x5e; 32],
        });
        profile.milestone = Milestone::M4;
        profile.features.extend([
            Feature::IndexedAsync,
            Feature::MultiRepo,
            Feature::Tickets,
            Feature::SyncInspection,
        ]);
        let release = CASES
            .iter()
            .find(|case| case.name == "launch.indexed_verification_commits")
            .expect("release indexed verification case must exist");
        assert!(release.skip_reason(&profile).is_none());
        let rejection = CASES
            .iter()
            .find(|case| case.name == "launch.inspection_rejects_advance")
            .expect("release inspection refusal case must exist");
        assert!(rejection.skip_reason(&profile).is_none());
        let faults = CASES
            .iter()
            .find(|case| case.name == "indexed.async_verification_commits")
            .unwrap();
        assert!(
            faults
                .skip_reason(&profile)
                .unwrap()
                .contains("test-faults")
        );
        profile.features.insert(Feature::TestFaults);
        assert!(
            rejection
                .skip_reason(&profile)
                .unwrap()
                .contains("test-faults")
        );
        assert!(
            release
                .skip_reason(&profile)
                .unwrap()
                .contains("test-faults")
        );
    }

    #[test]
    fn at_least_45_cases_with_unique_documented_names() {
        assert!(CASES.len() >= 45, "{}", CASES.len());
        let names: BTreeSet<_> = CASES.iter().map(|c| c.name).collect();
        assert_eq!(names.len(), CASES.len(), "duplicate case names");
        let docs = include_str!("mod.rs");
        for name in names {
            assert!(
                docs.contains(&format!("//! | `{name}` |")),
                "{name} is not documented"
            );
            let (group, rest) = name.split_once('.').unwrap();
            assert!(
                !group.is_empty() && !rest.is_empty() && !rest.contains('.'),
                "{name}"
            );
        }
    }

    /// The backticked feature names in `cell`.
    fn features(cell: &str) -> BTreeSet<&str> {
        cell.split('`').skip(1).step_by(2).collect()
    }

    #[test]
    fn every_documented_case_exists() {
        let names: BTreeSet<_> = CASES.iter().map(|c| c.name).collect();
        for row in include_str!("mod.rs")
            .lines()
            .filter(|l| l.starts_with("//! | `"))
        {
            let name = row["//! | `".len()..].split('`').next().unwrap();
            assert!(
                names.contains(name),
                "documented case {name} is not in the table"
            );
        }
    }

    #[test]
    fn documented_requirements_and_exclusions_match_the_table_exactly() {
        let docs = include_str!("mod.rs");
        for case in CASES {
            let row = docs
                .lines()
                .find(|l| l.starts_with(&format!("//! | `{}` |", case.name)))
                .unwrap();
            // `| name | requires; not/excludes exclusions | asserts |`
            let cell = row.split('|').nth(2).unwrap();
            let (requires, excludes) = ["not `", "excludes `"]
                .iter()
                .filter_map(|marker| cell.find(marker))
                .min()
                .map_or((cell, ""), |at| cell.split_at(at));
            let want = |list: &[Feature]| list.iter().map(|f| f.as_str()).collect::<BTreeSet<_>>();
            assert_eq!(
                features(requires),
                want(case.requires),
                "{} requires",
                case.name
            );
            assert_eq!(
                features(excludes),
                want(case.excludes),
                "{} excludes",
                case.name
            );
        }
    }

    #[test]
    fn skips_name_the_missing_feature() {
        let mut profile = Profile::new(WireAuth::None);
        let case = CASES
            .iter()
            .find(|c| c.name == "quota.replay_not_charged")
            .unwrap();
        let why = case.skip_reason(&profile).unwrap();
        assert!(why.contains("auth-v2") && why.contains("quota"), "{why}");
        let nonatomic = CASES
            .iter()
            .find(|c| c.name == "advance.nonatomic_packmap_first")
            .unwrap();
        assert!(nonatomic.skip_reason(&profile).is_none());
        profile.features.insert(Feature::AtomicAdvance);
        assert!(
            nonatomic
                .skip_reason(&profile)
                .unwrap()
                .contains("atomic-advance")
        );
        profile.milestone = Milestone::M0;
        let multi = CASES
            .iter()
            .find(|c| c.name == "repo.isolation_refs")
            .unwrap();
        assert!(multi.skip_reason(&profile).unwrap().contains("milestone"));
        profile.milestone = Milestone::M1;
        assert!(multi.skip_reason(&profile).unwrap().contains("multi-repo"));
    }
}
