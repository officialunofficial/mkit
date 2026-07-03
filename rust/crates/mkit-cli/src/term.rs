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
    use_color_with(
        env::var_os("NO_COLOR").is_some(),
        matches!(env::var("CLICOLOR_FORCE").ok().as_deref(), Some("1")),
        is_tty,
    )
}

/// Pure decision function, taking `NO_COLOR`/`CLICOLOR_FORCE` as
/// explicit booleans instead of reading the ambient process env. Split
/// out so tests can drive every combination deterministically (#505 PR
/// 5/5) instead of branching on whatever `NO_COLOR`/`CLICOLOR_FORCE`
/// happen to be set to in the current process.
fn use_color_with(no_color: bool, force: bool, is_tty: bool) -> bool {
    if no_color {
        return false;
    }
    if force {
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
    fn use_color_with_matrix_honours_precedence_and_tty() {
        // #505 PR 5/5: inject NO_COLOR/CLICOLOR_FORCE/tty explicitly
        // instead of branching on the ambient process env — deterministic
        // regardless of what NO_COLOR/CLICOLOR_FORCE happen to be set to
        // wherever the test runs.
        //
        // NO_COLOR wins outright, tty or not.
        assert!(!use_color_with(true, true, true));
        assert!(!use_color_with(true, true, false));
        assert!(!use_color_with(true, false, true));
        assert!(!use_color_with(true, false, false));
        // CLICOLOR_FORCE overrides a non-tty when NO_COLOR is absent.
        assert!(use_color_with(false, true, true));
        assert!(use_color_with(false, true, false));
        // Neither set: falls through to tty-ness.
        assert!(use_color_with(false, false, true));
        assert!(!use_color_with(false, false, false));
    }
}
