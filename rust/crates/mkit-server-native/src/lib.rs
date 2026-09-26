#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]

mod blocking;
#[cfg(feature = "sqlite")]
mod sqlite;

pub use blocking::Blocking;
#[cfg(feature = "sqlite")]
pub use sqlite::{RusqliteConn, SqliteKvStore};
