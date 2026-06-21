//! Terminal helpers — ANSI color gating and POSIX getenv wrappers.
//!
//! Color policy: `NO_COLOR` (any value, including empty) disables
//! color; `CLICOLOR_FORCE=1` forces it even when stdout is piped.
//! `NO_COLOR` wins — see <https://no-color.org>.

use std::env;
use std::io::IsTerminal;

/// Returns `true` when ANSI color should be rendered on stdout.
#[must_use]
pub fn use_color_stdout() -> bool {
    use_color(std::io::stdout().is_terminal())
}

/// Returns `true` when ANSI color should be rendered on stderr.
#[must_use]
pub fn use_color_stderr() -> bool {
    use_color(std::io::stderr().is_terminal())
}

fn use_color(is_tty: bool) -> bool {
    if env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if matches!(env::var("CLICOLOR_FORCE").ok().as_deref(), Some("1")) {
        return true;
    }
    is_tty
}

/// A `--color=<when>` choice, mirroring git's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorChoice {
    /// Always colorize, even when piped.
    Always,
    /// Colorize only on a tty (respecting `NO_COLOR`/`CLICOLOR_FORCE`).
    Auto,
    /// Never colorize.
    Never,
}

impl ColorChoice {
    /// Parse a `--color=<when>` value; `None`/`""`/`auto` → `Auto`.
    #[must_use]
    pub fn parse(s: Option<&str>) -> Option<Self> {
        match s {
            None | Some("" | "auto") => Some(Self::Auto),
            Some("always") => Some(Self::Always),
            Some("never") => Some(Self::Never),
            Some(_) => None,
        }
    }

    /// Resolve to an on/off decision for the given tty-ness.
    #[must_use]
    pub fn resolve(self, is_tty: bool) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => use_color(is_tty),
        }
    }
}

/// Convenience getenv — returns `None` for both unset and empty.
#[must_use]
pub fn getenv_nonempty(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn use_color_pure_helper_honours_current_env() {
        // We don't mutate env in tests (requires `unsafe` on 2024
        // edition / Rust 1.95); instead we observe what the helper
        // does with the CURRENT process env. A CI worker is not a
        // TTY, so `use_color(false)` must be false (barring a
        // CLICOLOR_FORCE=1 override the test will detect).
        let no_color = env::var_os("NO_COLOR").is_some();
        let force = env::var("CLICOLOR_FORCE").ok().as_deref() == Some("1");
        if no_color {
            assert!(!use_color(true));
            assert!(!use_color(false));
        } else if force {
            assert!(use_color(true));
            assert!(use_color(false));
        } else {
            assert!(use_color(true));
            assert!(!use_color(false));
        }
    }
}
