//! Cloudflare plan budgets for source relay alarms.

/// Worker Paid relay targets attempted per fire.
pub const WORKER_PAID_RELAY_TARGETS: u32 = 32;
/// Worker Free relay targets attempted per fire.
pub const WORKER_FREE_RELAY_TARGETS: u32 = 8;
/// Worker Paid relay fires per alarm.
pub const WORKER_PAID_RELAY_FIRES: u32 = 8;
/// Worker Free relay fires per alarm.
pub const WORKER_FREE_RELAY_FIRES: u32 = 2;
/// Worker target calls allowed per target per fire.
pub const WORKER_RELAY_CALLS_PER_TARGET: u32 = 2;
