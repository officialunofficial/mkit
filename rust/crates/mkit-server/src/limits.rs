//! Default deployment call limits. Adapters may partition these allowances
//! into smaller shared budgets; the values preserve the current defaults.

/// Storage calls available to a request.
pub const REQUEST_CALLS: u32 = 9_000;
/// Calls available to an object-reader or scanner retrieval invocation.
pub const OBJECT_READER_CALLS: u32 = 8_500;
/// Combined calls available to one scheduled alarm.
pub const ALARM_CALLS: u32 = 1_000;
/// Pair verification slice within the enclosing publication allowance.
pub const VERIFY_SLICE_CALLS: u32 = 256;
/// Maximum calls for inspected publication advancement in one alarm.
pub const INSPECTION_ADVANCE_CALLS: u32 = 960;
