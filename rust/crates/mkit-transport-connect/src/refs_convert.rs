//! `RefExpectation` (wire) <-> [`RefWriteCondition`] (trait) conversion,
//! per SPEC-TRANSPORT-CONNECT §3.

use buffa::EnumValue;
use connectrpc::ConnectError;
use mkit_core::refs::RefWriteCondition;

use crate::hashutil::hash_from_slice;
use crate::proto::mkit::transport::v1::RefExpectation;

/// Convert a wire `(expectation, expected_id)` pair into a
/// [`RefWriteCondition`].
///
/// A conforming server MUST reject `REF_EXPECTATION_UNSPECIFIED` (the
/// proto zero value — this covers both an explicitly-sent `UNSPECIFIED`
/// and a field the client never set, since the wire never distinguishes
/// the two once decoded) with `invalid_argument`, per
/// SPEC-TRANSPORT-CONNECT §3.
///
/// # Errors
///
/// `invalid_argument` if `expectation` is unset/unspecified/unknown, if
/// `ANY`/`MISSING` carries a non-empty `expected_id`, or if `MATCH`'s
/// `expected_id` is not exactly 32 bytes.
pub(crate) fn condition_from_wire(
    expectation: Option<EnumValue<RefExpectation>>,
    expected_id: Option<&[u8]>,
) -> Result<RefWriteCondition, ConnectError> {
    let expected_id = expected_id.unwrap_or(&[]);
    match expectation.and_then(|e| e.as_known()) {
        Some(RefExpectation::REF_EXPECTATION_ANY) => {
            if !expected_id.is_empty() {
                return Err(ConnectError::invalid_argument(
                    "REF_EXPECTATION_ANY MUST carry an empty expected_id",
                ));
            }
            Ok(RefWriteCondition::Any)
        }
        Some(RefExpectation::REF_EXPECTATION_MISSING) => {
            if !expected_id.is_empty() {
                return Err(ConnectError::invalid_argument(
                    "REF_EXPECTATION_MISSING MUST carry an empty expected_id",
                ));
            }
            Ok(RefWriteCondition::Missing)
        }
        Some(RefExpectation::REF_EXPECTATION_MATCH) => {
            Ok(RefWriteCondition::Match(hash_from_slice(expected_id)?))
        }
        // REF_EXPECTATION_UNSPECIFIED (explicit or defaulted), or an
        // unrecognized wire value (`EnumValue::Unknown`) — both are
        // protocol errors per SPEC-TRANSPORT-CONNECT §3.
        Some(RefExpectation::REF_EXPECTATION_UNSPECIFIED) | None => Err(
            ConnectError::invalid_argument("expectation MUST NOT be REF_EXPECTATION_UNSPECIFIED"),
        ),
    }
}
