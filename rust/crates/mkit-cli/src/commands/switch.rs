//! `mkit switch` — git's modern branch-switch UX, a thin front-end over
//! `mkit checkout`. `switch <branch>` switches to an existing branch;
//! `switch -c <new> [<start>]` creates a branch and switches to it;
//! `switch -C <new> [<start>]` creates-or-resets it. All the safety
//! guards and output strings come from `checkout` unchanged.

use clap::Parser;

use crate::clap_shim;

#[derive(Debug, Parser)]
#[command(name = "mkit switch", about = "Switch branches (git switch).")]
struct SwitchOpts {
    /// Create a new branch and switch to it (`git switch -c`).
    #[arg(short = 'c', value_name = "NEW", conflicts_with = "create_force")]
    create: Option<String>,
    /// Create-or-reset a branch and switch to it (`git switch -C`).
    #[arg(short = 'C', value_name = "NEW")]
    create_force: Option<String>,
    /// Branch to switch to, or the start-point when used with `-c`/`-C`.
    target: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<SwitchOpts>("mkit switch", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let has_create = opts.create.is_some() || opts.create_force.is_some();
    // Translate to checkout's argument surface and delegate (checkout owns
    // the clobber guard + the `Switched to …` reporting).
    let mut fwd: Vec<String> = Vec::new();
    if let Some(new) = opts.create.as_deref() {
        fwd.push("-b".to_owned());
        fwd.push(new.to_owned());
    } else if let Some(new) = opts.create_force.as_deref() {
        fwd.push("-B".to_owned());
        fwd.push(new.to_owned());
    }
    match opts.target.as_deref() {
        Some(t) => fwd.push(t.to_owned()),
        None if !has_create => {
            return super::usage_error("usage: mkit switch [-c|-C <new>] <branch>");
        }
        None => {}
    }
    super::checkout::run(&fwd)
}
