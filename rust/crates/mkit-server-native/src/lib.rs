#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]

mod blocking;
#[cfg(feature = "http")]
pub mod config;
#[cfg(feature = "enc")]
pub mod enc;
#[cfg(feature = "http")]
pub mod exit;
#[cfg(feature = "http")]
mod guard;
#[cfg(feature = "http")]
pub mod layers;
#[cfg(feature = "http")]
mod listen;
#[cfg(feature = "http")]
mod router;
#[cfg(feature = "s3")]
pub mod s3;
#[cfg(feature = "http")]
pub mod server;
#[cfg(feature = "http")]
mod shutdown;
#[cfg(feature = "http")]
mod spawn;
#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "http")]
pub mod telemetry;

pub use blocking::{Blocking, BlockingSink, PROBE_CACHE_TTL};
#[cfg(feature = "http")]
pub use listen::{ServeOptions, serve};
#[cfg(feature = "http")]
pub use router::{CorsPolicy, RouterOptions, build_router};
#[cfg(feature = "s3")]
pub use s3::{S3BlobStore, S3Config, S3PackSink};
#[cfg(feature = "http")]
pub use shutdown::{Shutdown, shutdown_signal};
#[cfg(feature = "http")]
pub use spawn::TokioSpawner;
#[cfg(feature = "sqlite")]
pub use sqlite::{RusqliteConn, SqliteKvStore};
