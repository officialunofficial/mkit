//! Declarative CLI transcript tests (`trycmd`) for simple, deterministic
//! error paths — pins the exact user-facing text, not just an exit code.
//!
//! Complements, rather than replaces, the existing test tiers: full
//! `--help`/`version` output is already pinned via `insta` snapshots in
//! `help_snapshot.rs`; anything involving a real repo (non-deterministic
//! hashes/timestamps) belongs with the `Repo` builder in
//! `tests/common/mod.rs`. `trycmd` is reserved for short, fully
//! deterministic transcripts where the `.trycmd` file doubles as
//! human-readable documentation of the exact behavior.
//!
//! Fixtures live in `tests/cmd/*.trycmd`. See
//! <https://docs.rs/trycmd/latest/trycmd/#syntax> for the file format.

#[test]
fn cli_transcripts() {
    trycmd::TestCases::new()
        .register_bin(
            "mkit",
            trycmd::schema::Bin::Path(std::path::PathBuf::from(env!("CARGO_BIN_EXE_mkit"))),
        )
        .case("tests/cmd/*.trycmd");
}
