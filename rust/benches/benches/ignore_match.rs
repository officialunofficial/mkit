//! `IgnoreList::is_ignored` throughput — the per-directory-entry gitignore
//! check `worktree::build_tree_inner` runs on *every* file/dir a walk
//! reaches (`add`, `status`, `commit`, `diff`, `restore`, `ls-files`,
//! `clean`). No prior coverage: `add_staging.rs`'s fixtures carry no
//! `.gitignore`, so an empty `IgnoreList` (its patterns loop is a no-op)
//! never exercised this path at all.
//!
//! Two pattern sets:
//! - `realistic_50`: a ~50-pattern `.gitignore` shaped like a real
//!   Node+Rust+editor-cruft template (the common case: non-anchored,
//!   single-segment literals and simple globs — `node_modules`, `*.log`,
//!   `target/`, …).
//! - `anchored_heavy`: patterns that all fall back to the general
//!   `match_segments` engine (anchored, multi-segment, or containing an
//!   internal `**`), so this axis stays flat across any future change to
//!   the non-anchored fast path — it is the "nothing to skip" control.
//!
//! Paths are a realistic depth-2..5 mix where most entries do NOT match
//! (the common case reaching this code — an already-matched ignored
//! subtree is skipped by the walk before it ever calls `is_ignored`
//! again, so the dominant cost in practice is the full-scan "not
//! ignored" case, not a quick early match).

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::ignore::{self, IgnoreList};

const REALISTIC_50: &str = "\
node_modules\ntarget\ndist\nbuild\ncoverage\n.DS_Store\n*.log\n*.tmp\n*.swp\n*.swo\n\
*.pyc\n*.class\n*.o\n*.obj\n*.pdb\n*.orig\n*.rej\n*.bak\n*.cache\n*.lock\n\
.env\n.env.local\n.venv\n__pycache__\n.pytest_cache\n.mypy_cache\n.ruff_cache\n\
*.egg-info\n.idea\n.vscode\nThumbs.db\ndesktop.ini\n*.iml\n*.suo\n*.user\n\
vendor\n.terraform\n.next\n.nuxt\n.parcel-cache\n.turbo\n.cache\nout\n\
*.min.js\n*.min.css\n*.map\n.eslintcache\n.stylelintcache\nlogs\n*.pid\n*.seed\n\
";

const ANCHORED_HEAVY: &str = "\
/target\n/dist\n/build\nsrc/generated\napps/*/dist\ndocs/**/build\n\
packages/*/node_modules\n/coverage\n/.cache\ntools/vendor\ninfra/**/*.tfstate\n\
services/*/target\n/out\n/.next\nweb/**/dist\ncli/**/*.o\nlibs/*/build\n\
/.turbo\napps/web/.next\napps/api/dist\ncrates/*/target\n\
";

/// Deterministic path fixture: `n` paths across a realistic depth-2..5
/// directory shape, a mix of names that hit common ignore patterns
/// (`node_modules`, `*.log`, …) and ordinary source-looking names that
/// match nothing — repo walks are mostly the latter.
fn synthetic_paths(n: usize) -> Vec<(String, bool)> {
    let leaf_names = [
        "main.rs",
        "lib.rs",
        "mod.rs",
        "index.ts",
        "app.tsx",
        "utils.py",
        "README.md",
        "Cargo.toml",
        "package.json",
        "config.yaml",
        "test.rs",
        "handler.go",
    ];
    let mid_dirs = [
        "src", "crates", "apps", "lib", "internal", "cmd", "pkg", "web",
    ];
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let depth = 2 + (i % 4);
        let mut segs: Vec<String> = Vec::with_capacity(depth);
        segs.push(mid_dirs[i % mid_dirs.len()].to_string());
        for d in 1..depth - 1 {
            segs.push(format!("mod{}", (i + d) % 37));
        }
        // Every 9th path targets a name that a real .gitignore is likely
        // to actually match, so the fixture isn't 100% "no match".
        let leaf = if i % 9 == 0 {
            "debug.log".to_string()
        } else {
            leaf_names[i % leaf_names.len()].to_string()
        };
        segs.push(leaf);
        out.push((segs.join("/"), false));
    }
    out
}

fn bench_is_ignored(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();
    let paths = synthetic_paths(20_000);

    for (axis, patterns_src) in [
        ("realistic_50 (non-anchored)", REALISTIC_50),
        ("anchored_heavy (general engine)", ANCHORED_HEAVY),
    ] {
        let list: IgnoreList = ignore::parse(patterns_src);
        let pattern_count = list.patterns().len();
        assert!(
            pattern_count >= 15,
            "fixture should have a real pattern count"
        );

        let mut group = c.benchmark_group(format!("ignore_match/{axis}"));
        group.bench_function("is_ignored", |b| {
            b.iter(|| {
                let mut hits = 0usize;
                for (p, is_dir) in &paths {
                    if list.is_ignored(p, *is_dir) {
                        hits += 1;
                    }
                }
                std::hint::black_box(hits)
            });
        });
        group.finish();

        let secs = time_one(3, 30, || {
            for (p, is_dir) in &paths {
                std::hint::black_box(list.is_ignored(p, *is_dir));
            }
        });
        let ops_per_sec = paths.len() as f64 / secs;
        eprintln!(
            "ignore_match/{axis}: {:.1} ns/path ({ops_per_sec:.0} paths/s, {pattern_count} patterns)",
            secs * 1e9 / paths.len() as f64
        );
        samples.push(Sample {
            category: "ignore_match".into(),
            axis: axis.into(),
            library: "is_ignored".into(),
            value: ops_per_sec,
            unit: Unit::OpsPerSec,
        });
    }

    mkit_benches::write_summary("ignore_match", &samples);
}

criterion_group!(benches, bench_is_ignored);
criterion_main!(benches);
