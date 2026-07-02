//! Build-time invariant: `cli::CLI_VERSION` MUST equal `CARGO_PKG_VERSION`.
//!
//! We source-grep `src/cli.rs` for the expected literal. The Rust
//! version is authored as `pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");`
//! today — which makes the invariant automatic — but if a future
//! refactor ever inlines the version string literally, this gate makes
//! sure the byte-exact Homebrew contract (`mkit <X.Y.Z>\n`) cannot
//! silently desync.

use std::fs;
use std::path::Path;

fn main() {
    // Target triple for `mkit self update`: release archives are named
    // `mkit-<version>-<triple>.tar.gz`, and TARGET is only visible to
    // build scripts, so re-export it to the crate.
    let target = std::env::var("TARGET").expect("TARGET set by cargo");
    println!("cargo:rustc-env=MKIT_TARGET_TRIPLE={target}");

    let cli_path = Path::new("src").join("cli.rs");
    println!("cargo:rerun-if-changed={}", cli_path.display());
    println!("cargo:rerun-if-changed=Cargo.toml");

    let src = fs::read_to_string(&cli_path).expect("src/cli.rs must exist");
    let version = std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION set by cargo");

    // Two accepted shapes. One keeps the invariant automatic via env!;
    // the other lets a future refactor inline a string literal without
    // breaking the Homebrew contract.
    let env_shape = r#"pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");"#;
    let literal_shape = format!(r#"pub const CLI_VERSION: &str = "{version}";"#);

    if src.contains(env_shape) || src.contains(&literal_shape) {
        return;
    }
    panic!(
        "CLI_VERSION in src/cli.rs does not match Cargo.toml package.version ({version}).\n\
         Update src/cli.rs to either:\n\
         - `pub const CLI_VERSION: &str = env!(\"CARGO_PKG_VERSION\");`  (preferred)\n\
         - `pub const CLI_VERSION: &str = \"{version}\";`               (literal)"
    );
}
